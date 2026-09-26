package archive

import (
	"bytes"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"

	"github.com/philmalin/eictar/src/internal/format"
	"github.com/philmalin/eictar/src/internal/meta"
	"github.com/philmalin/eictar/src/internal/pipeline"
)

// MetadataOptions selects which metadata a create records.
type MetadataOptions struct {
	NoOwner  bool // --no-owner: record no uid, gid or names
	NoXattrs bool // --no-xattrs: record no extended attributes other than ACLs
	NoACLs   bool // --no-acls: record no POSIX ACLs
}

// capturer turns walked entries into members, with their metadata.
//
// It runs on the walking goroutine only, so its maps need no lock.
type capturer struct {
	w     *Writer
	b     *pipeline.Builder
	opt   MetadataOptions
	names *meta.Names

	// firstLink maps an inode to the member that holds its content. A later
	// name for the same inode becomes a hardlink member that points at it.
	firstLink map[inodeKey]uint64

	// seen holds the paths recorded in this run. A path named twice - "a"
	// and "./a", or a directory and a file inside it - is recorded once, so
	// that one run never breaks the one-member-per-path rule (§9.2).
	seen map[string]bool

	// The rest is set for append and update only.
	live       map[string]*format.Member // the archive's live members, by path
	byID       map[uint64]*format.Member // all of the archive's members, for hardlink targets
	onConflict string                    // replace, skip or error (-r)
	updateMode string                    // newer, different or digest (-u)
	tombstones map[uint64]bool           // members this generation replaces

	progress Progress // --progress, or nil
	// warn reports a notice that does not fail the member.
	warn func(format string, args ...any)
}

// Conflict policies for -r (doc/design.md 9.2).
const (
	ConflictReplace = "replace"
	ConflictSkip    = "skip"
	ConflictError   = "error"
)

// ErrConflict means a path is already in the archive and --on-conflict=error
// was given.
var ErrConflict = errors.New("already in the archive")

// errUnchanged reports a path that -u found up to date. It is neither a
// notice nor a failure: most paths of a typical update are unchanged.
var errUnchanged = errors.New("unchanged")

type inodeKey struct{ dev, ino uint64 }

// errSkipped reports an entry that is deliberately not archived. It is a
// notice, not a failure.
type errSkipped struct{ reason string }

func (e *errSkipped) Error() string { return e.reason }

func newCapturer(w *Writer, b *pipeline.Builder, opt MetadataOptions) *capturer {
	return &capturer{
		w: w, b: b, opt: opt, names: meta.NewNames(),
		firstLink: map[inodeKey]uint64{}, seen: map[string]bool{},
		tombstones: map[uint64]bool{},
	}
}

// submit records one walked entry.
func (c *capturer) submit(e entry) error {
	if c.seen[e.Stored] {
		return &errSkipped{reason: fmt.Sprintf("%s: named more than once, archived once", e.Stored)}
	}

	// A path already live in the archive: -u replaces it only when it is out
	// of date, and -r follows --on-conflict.
	old, replacing := c.live[e.Stored]
	if replacing {
		if c.updateMode != "" {
			stale, err := outOfDate(c.contentOf(old), e, c.updateMode, c.w.newDigest)
			if err != nil {
				return err
			}
			if !stale {
				c.seen[e.Stored] = true
				return errUnchanged
			}
		} else {
			switch c.onConflict {
			case ConflictSkip:
				c.seen[e.Stored] = true
				return &errSkipped{reason: fmt.Sprintf("%s: already in the archive, skipped", e.Stored)}
			case ConflictError:
				return fmt.Errorf("%s: %w", e.Stored, ErrConflict)
			}
		}
	}
	c.seen[e.Stored] = true

	// The old member dies only when the new one is recorded. Under
	// --keep-going a path that fails to read would otherwise lose both
	// copies, and a socket where a file was would delete the file.
	err := c.record(e)
	if err == nil && replacing {
		c.tombstones[old.ID] = true
	}
	return err
}

// record builds the member for one entry and hands it to the pipeline.
func (c *capturer) record(e entry) error {
	m := format.Member{
		ID:         c.w.NextID(),
		Generation: c.w.Generation(),
		Path:       e.Stored,
		Mode:       meta.UnixMode(e.Info.Mode()),
		MTimeNanos: e.Info.ModTime().UnixNano(),
		Codec:      format.NoCodec,
	}
	if e.Sys.OK {
		m.ATimeNanos = e.Sys.ATimeNanos
		c.recordOwner(&m, e.Sys)
	}

	switch e.Kind {
	case kindDir:
		m.Type = format.TypeDir
		if err := c.recordXattrs(&m, e); err != nil {
			return err
		}
		return c.b.AddMeta(m)

	case kindSymlink:
		m.Type = format.TypeSymlink
		m.Mode = 0o777 // a symlink's own mode is meaningless on Linux
		m.LinkTarget = e.LinkTarget
		if m.LinkTarget == "" {
			return fmt.Errorf("symlink %q has an empty target", e.Stored)
		}
		// Linux refuses user.* attributes on a symlink, and the rest are
		// privileged, so a link's attributes are not recorded.
		return c.b.AddMeta(m)

	case kindFIFO:
		m.Type = format.TypeFIFO
		return c.b.AddMeta(m)

	case kindCharDev, kindBlockDev:
		m.Type = format.TypeBlockDev
		if e.Kind == kindCharDev {
			m.Type = format.TypeCharDev
		}
		m.RDev = []uint32{e.Sys.Major, e.Sys.Minor}
		return c.b.AddMeta(m)

	case kindSocket:
		// A socket has no content and cannot be recreated in any useful
		// way: its meaning is the process listening on it. tar skips them
		// with a notice, and so does this.
		c.w.releaseID(m.ID)
		return &errSkipped{reason: fmt.Sprintf("%s: socket ignored", e.Src)}

	case kindFile:
		return c.submitFile(m, e)

	default:
		return fmt.Errorf("%s: %s cannot be stored", e.Src, describeMode(e.Info.Mode()))
	}
}

// submitFile records a regular file, as content or as a hardlink to content
// already recorded.
func (c *capturer) submitFile(m format.Member, e entry) error {
	// A second name for an inode already archived stores no content: it
	// points at the first. Nlink > 1 is checked first because nearly every
	// file has one name, and the map should stay small.
	var key inodeKey
	linked := e.Sys.OK && e.Sys.Nlink > 1
	if linked {
		key = inodeKey{e.Sys.Dev, e.Sys.Ino}
		if first, ok := c.firstLink[key]; ok {
			m.Type = format.TypeHardlink
			m.HardlinkTo = first
			m.ATimeNanos = 0 // the inode's times belong to the first member
			return c.b.AddMeta(m)
		}
	}

	if err := c.recordXattrs(&m, e); err != nil {
		return err
	}

	f, err := openWalked(e)
	if err != nil {
		return err
	}
	defer f.Close()

	m.Type = format.TypeReg
	m.Codec = c.w.CodecRef()

	// A file with holes stores only its data regions (doc/design.md 5.1).
	segs, sparse, err := meta.DataSegments(f, e.Info.Size(), e.Sys.Blocks)
	if err != nil {
		return fmt.Errorf("%s: %w", e.Src, err)
	}
	payload := uint64(e.Info.Size())
	if sparse {
		m.Size = uint64(e.Info.Size())
		payload = 0
		for _, s := range segs {
			m.Sparse = append(m.Sparse, format.SparseSegment{Offset: uint64(s.Offset), Length: uint64(s.Length)})
			payload += uint64(s.Length)
		}
	}
	reader := func() io.Reader {
		if !sparse {
			return io.NewSectionReader(f, 0, e.Info.Size())
		}
		readers := make([]io.Reader, 0, len(segs))
		for _, s := range segs {
			readers = append(readers, io.NewSectionReader(f, s.Offset, s.Length))
		}
		return io.MultiReader(readers...)
	}

	// A file with the size of stored content can be a copy of it: hash it
	// first, and share that content instead of compressing it again
	// (doc/design.md 4.3).
	if c.w.dedup.hasSize(payload) {
		shared, err := c.shareIfCopy(m, e, reader(), payload)
		if err != nil || shared {
			if err == nil && linked {
				c.firstLink[key] = m.ID
			}
			return err
		}
	}

	if err := c.b.AddFile(m, countReader(reader(), c.progress), c.w.newDigest()); err != nil {
		return fmt.Errorf("%s: %w", e.Src, err)
	}
	// Only a member that was recorded can be a hardlink target. Set before a
	// failure, a later name would point at a member the index never gets.
	if linked {
		c.firstLink[key] = m.ID
	}
	return nil
}

// shareIfCopy hashes a file's payload, and when the archive holds that
// content, records the member as sharing it. An old owner whose blob fails its
// check is reported, and the file is then stored in full.
func (c *capturer) shareIfCopy(m format.Member, e entry, src io.Reader, payload uint64) (bool, error) {
	h := c.w.newDigest()
	n, err := io.Copy(h, src)
	if err != nil {
		return false, fmt.Errorf("reading %s: %w", e.Src, err)
	}
	if uint64(n) != payload {
		return false, nil // it changed while it was read; the full read decides
	}
	m.Digest = h.Sum(nil)
	if len(m.Sparse) == 0 {
		m.Size = payload
	}
	owner, err := c.w.dedup.usable(&m)
	if err != nil {
		if c.warn != nil {
			c.warn("%s: the archive's copy of this content is damaged (%v); storing the file in full", e.Src, err)
		}
		return false, nil
	}
	if owner == 0 {
		return false, nil
	}
	share(&m, owner)
	if err := c.b.AddMeta(m); err != nil {
		return false, err
	}
	if c.progress != nil {
		c.progress.Advance(n)
	}
	return true, nil
}

// errChangedDuringWalk means a path no longer names the file that the walk
// found there.
var errChangedDuringWalk = errors.New("changed after the walk found it; not archived")

// openWalked opens the regular file that the walk found at e.Src, and makes
// sure that it is still that file. Between the walk's lstat and this open,
// someone who can write the directory can put a symbolic link there, to
// /etc/shadow for example. A privileged backup of such a tree then stored the
// target under the file's name (doc/Security_Audit.md, finding 3). The open
// does not follow a link, except under -h, and the file must have the device
// and inode that the walk saw.
func openWalked(e entry) (*os.File, error) {
	open := meta.OpenNoFollow
	if e.Followed {
		open = os.Open
	}
	f, err := open(e.Src)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", e.Src, err)
	}
	fi, err := f.Stat()
	if err == nil && (!fi.Mode().IsRegular() || !os.SameFile(fi, e.Info)) {
		err = errChangedDuringWalk
	}
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("%s: %w", e.Src, err)
	}
	return f, nil
}

// recordOwner stores the owner by number and by name, unless --no-owner.
func (c *capturer) recordOwner(m *format.Member, sys meta.Info) {
	if c.opt.NoOwner {
		return
	}
	m.UID = format.OwnerID(sys.UID)
	m.GID = format.OwnerID(sys.GID)
	m.Uname = c.names.UserName(sys.UID)
	m.Gname = c.names.GroupName(sys.GID)
}

// recordXattrs stores the extended attributes that the options allow. ACLs
// are extended attributes on Linux, so --no-acls and --no-xattrs are two
// filters over one list.
func (c *capturer) recordXattrs(m *format.Member, e entry) error {
	if c.opt.NoXattrs && c.opt.NoACLs {
		return nil
	}
	all, err := meta.ReadXattrs(e.Src, e.Followed)
	if err != nil {
		return err
	}
	for name, value := range all {
		isACL := meta.ClassifyXattr(name) == meta.XattrACL
		if (isACL && c.opt.NoACLs) || (!isACL && c.opt.NoXattrs) {
			continue
		}
		if len(name) > format.MaxXattrName || len(value) > format.MaxXattrValue {
			// Linux never makes one this large, but macOS can: a resource
			// fork is an xattr with no size limit. The file is still
			// archived; the attribute is not (doc/design.md 15.1).
			if c.warn != nil {
				c.warn("%s: extended attribute %q is larger than the format allows (%d bytes); not archived",
					e.Src, name, len(value))
			}
			continue
		}
		if m.Xattrs == nil {
			m.Xattrs = map[string][]byte{}
		}
		m.Xattrs[name] = value
	}
	return nil
}

// contentOf returns the member that holds a path's content and times: the
// member itself, or the target of a hardlink. Without this, -u would find
// every second name of a hardlink pair out of date, and store its content
// again in full on every run.
func (c *capturer) contentOf(m *format.Member) *format.Member {
	if m.Type == format.TypeHardlink {
		if t, ok := c.byID[m.HardlinkTo]; ok {
			return t
		}
	}
	return m
}

// outOfDate applies the -u test of doc/design.md 10.5 to one path. For a
// hardlink, old is the member that holds its content (see contentOf).
func outOfDate(old *format.Member, e entry, mode string, newHash func() hash.Hash) (bool, error) {
	// A change of type is always a change.
	if memberTypeFor(e.Kind) != old.Type {
		return true, nil
	}
	if old.Type == format.TypeSymlink && old.LinkTarget != e.LinkTarget {
		return true, nil
	}

	mtime := e.Info.ModTime().UnixNano()
	switch mode {
	case "newer":
		return mtime > old.MTimeNanos, nil
	case "digest":
		if old.Type == format.TypeReg {
			same, err := sameContent(old, e, newHash)
			if err != nil {
				return false, err
			}
			return !same, nil
		}
		fallthrough // other types have no content to hash
	default: // "different"
		return mtime != old.MTimeNanos ||
			(old.Type == format.TypeReg && uint64(e.Info.Size()) != old.Size), nil
	}
}

// memberTypeFor maps a walked kind to the member type it becomes.
func memberTypeFor(k entryKind) format.MemberType {
	switch k {
	case kindDir:
		return format.TypeDir
	case kindFile:
		return format.TypeReg
	case kindSymlink:
		return format.TypeSymlink
	case kindFIFO:
		return format.TypeFIFO
	case kindCharDev:
		return format.TypeCharDev
	case kindBlockDev:
		return format.TypeBlockDev
	case kindSocket:
		return format.TypeSocket
	}
	return ""
}

// sameContent reports whether the file at e holds exactly the content of the
// member old, for -u --update-mode=digest.
//
// The digest of a member covers its payload: the whole file when it was
// stored dense, only the data regions when it had holes. How a filesystem
// reports those regions can change while the content does not - after a
// delayed allocation settles, or on another filesystem - so hashing the
// file's current regions compared two layouts, not two contents, and
// archived an unchanged sparse file again. The stress tester found it
// (doc/design.md 13.4).
//
// Thus the file is read as the member was stored. For a member with holes:
// the bytes at the member's data regions must give its digest, and the rest
// of the file must be zero. Only the file's current data outside those
// regions is read for that; its current holes are zero already.
func sameContent(old *format.Member, e entry, newHash func() hash.Hash) (bool, error) {
	size := e.Info.Size()
	if uint64(size) != old.Size {
		return false, nil
	}
	f, err := openWalked(e)
	if err != nil {
		return false, err
	}
	defer f.Close()

	h := newHash()
	if len(old.Sparse) == 0 {
		// Stored dense: the digest is of the file as a reader sees it,
		// holes as zeros, which is what a plain read gives.
		if _, err := io.Copy(h, f); err != nil {
			return false, fmt.Errorf("reading %s: %w", e.Src, err)
		}
		return bytes.Equal(h.Sum(nil), old.Digest), nil
	}

	for _, s := range old.Sparse {
		if _, err := io.Copy(h, io.NewSectionReader(f, int64(s.Offset), int64(s.Length))); err != nil {
			return false, fmt.Errorf("reading %s: %w", e.Src, err)
		}
	}
	if !bytes.Equal(h.Sum(nil), old.Digest) {
		return false, nil
	}
	cur, sparse, err := meta.DataSegments(f, size, e.Sys.Blocks)
	if err != nil {
		return false, fmt.Errorf("%s: %w", e.Src, err)
	}
	if !sparse {
		cur = []meta.Segment{{Offset: 0, Length: size}}
	}
	for _, c := range cur {
		for _, gap := range outside(c, old.Sparse) {
			zero, err := allZero(io.NewSectionReader(f, gap.Offset, gap.Length))
			if err != nil {
				return false, fmt.Errorf("reading %s: %w", e.Src, err)
			}
			if !zero {
				return false, nil
			}
		}
	}
	return true, nil
}

// outside returns the parts of c that no segment of segs covers. segs is in
// order and does not overlap, as the index guarantees.
func outside(c meta.Segment, segs []format.SparseSegment) []meta.Segment {
	var out []meta.Segment
	pos, end := c.Offset, c.Offset+c.Length
	for _, s := range segs {
		so, se := int64(s.Offset), int64(s.Offset+s.Length)
		if se <= pos || so >= end {
			continue
		}
		if so > pos {
			out = append(out, meta.Segment{Offset: pos, Length: so - pos})
		}
		pos = max(pos, se)
	}
	if pos < end {
		out = append(out, meta.Segment{Offset: pos, Length: end - pos})
	}
	return out
}

// allZero reports whether r holds only zero bytes.
func allZero(r io.Reader) (bool, error) {
	buf := make([]byte, 64<<10)
	for {
		n, err := r.Read(buf)
		for _, b := range buf[:n] {
			if b != 0 {
				return false, nil
			}
		}
		if err == io.EOF {
			return true, nil
		}
		if err != nil {
			return false, err
		}
	}
}
