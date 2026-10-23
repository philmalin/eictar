package archive

import (
	"bytes"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/philmalin/eictar/src/internal/format"
	"github.com/philmalin/eictar/src/internal/meta"
)

// --diff-extract (doc/design.md 9.10) extracts each member, with the code of
// extraction, into a scratch directory under a name of its own. It compares
// the copy with the file on disk, byte by byte and by its metadata, and then
// removes it. The comparison uses no digest, so a fault of the digest code
// that create, --verify and --diff all share does not hide a difference.

// ErrScratchInTree means that the scratch directory would be in the tree
// that --diff-extract compares. It is a usage error: the directory would
// change the time of its parent, and the walk would find the copies.
var ErrScratchInTree = errors.New("the scratch directory would be in the compared tree")

// compareBlock is the size of the blocks of the byte comparison.
const compareBlock = 1 << 20

// scratch is the scratch directory of one --diff-extract.
type scratch struct {
	dir string      // its path
	x   *extraction // the extraction into it
	// precision is that of the times of its file system: two times that
	// differ by less are the same (doc/design.md 9.10).
	precision time.Duration
	// linkTimes is false when the platform cannot set the times of a
	// symbolic link: the time of a copy of a link is then not compared.
	linkTimes bool
	root      bool // the process is root
	seq       atomic.Uint64

	mu sync.Mutex
	// skipped counts, by member type, the nodes that could not be made:
	// device nodes without root, and pipes where the platform has no safe
	// call. They get one notice at the end of the run.
	skipped map[format.MemberType]int
}

// newScratch makes the scratch directory in cfg.ScratchDir, or in
// os.TempDir(), and probes its file system. base is the base directory of
// the walk, and roots are where the walks start in it.
func newScratch(cfg DiffConfig, r *Reader, base string, roots []string) (*scratch, error) {
	parent := cfg.ScratchDir
	if parent == "" {
		parent = os.TempDir()
	}
	if err := scratchOutside(parent, base, roots); err != nil {
		return nil, err
	}
	// MkdirTemp makes the directory with mode 0700: a copy can have the
	// setuid bit, and other users must not reach it.
	dir, err := os.MkdirTemp(parent, "eictar-diff-")
	if err != nil {
		return nil, fmt.Errorf("creating the scratch directory in %s: %w", parent, err)
	}
	root, err := openDest(dir)
	if err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("opening the scratch directory %s: %w", dir, err)
	}
	isRoot := meta.IsRoot()
	s := &scratch{
		dir:  dir,
		root: isRoot,
		x: &extraction{
			r: r, root: root, names: meta.NewNames(),
			extracted: map[uint64]string{}, refused: map[string]int{},
			// A copy gets what -p restores, so that the full mode and the
			// ACLs can be compared. As root, it also gets the owner and the
			// device nodes. No reporter: the progress is that of the
			// comparison, and the notices are those of notices.
			cfg: ExtractConfig{Restore: RestoreOptions{
				Permissions: true,
				Owner:       isRoot && !cfg.Metadata.NoOwner,
				Devices:     isRoot,
				NoXattrs:    cfg.Metadata.NoXattrs,
				NoACLs:      cfg.Metadata.NoACLs,
			}},
		},
		skipped: map[format.MemberType]int{},
	}
	if err := s.probe(); err != nil {
		s.close()
		return nil, err
	}
	return s, nil
}

// scratchOutside refuses a parent of the scratch directory that is a walk
// root, or inside one. The paths are compared with their links resolved.
func scratchOutside(parent, base string, roots []string) error {
	resolve := func(p string) string {
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		if real, err := filepath.EvalSymlinks(p); err == nil {
			p = real
		}
		return p
	}
	p := resolve(parent)
	for _, root := range roots {
		tree := resolve(filepath.Join(base, filepath.FromSlash(root)))
		if p == tree || strings.HasPrefix(p, tree+string(filepath.Separator)) {
			return fmt.Errorf("%w: %s is in %s; choose another with --scratch-dir",
				ErrScratchInTree, parent, filepath.Join(base, root))
		}
	}
	return nil
}

// probe finds the precision of the times of the scratch file system, and
// whether the platform sets the times of a link. A file system that does
// not keep a time to within 2 s (that of FAT) cannot be used.
func (s *scratch) probe() error {
	const name = "probe"
	in := func(what string, err error) error {
		return fmt.Errorf("%s in the scratch directory %s: %w", what, s.dir, err)
	}
	f, err := s.x.root.OpenFile(name, os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return in("making a file", err)
	}
	if err := f.Close(); err != nil {
		return in("making a file", err)
	}
	want := time.Unix(1_700_000_001, 123_456_789)
	if err := s.x.root.Chtimes(name, want, want); err != nil {
		return in("setting a time", err)
	}
	fi, err := s.x.root.Lstat(name)
	if err != nil {
		return in("reading a time", err)
	}
	var ok bool
	if s.precision, ok = timePrecision(want, fi.ModTime()); !ok {
		return fmt.Errorf("the file system of the scratch directory %s does not keep the times of files; choose another with --scratch-dir", s.dir)
	}
	if err := s.x.root.Remove(name); err != nil {
		return in("removing a file", err)
	}
	if !copiesNodes {
		return nil
	}

	// A link to nothing: only its own time matters.
	const link = "probe-link"
	if err := s.x.root.Symlink(name, link); err != nil {
		return in("making a link", err)
	}
	d, err := s.x.root.Open(".")
	if err != nil {
		return in("opening the directory", err)
	}
	err = setLinkTimes(d.file(), link, want.UnixNano(), want.UnixNano())
	d.Close() // it was only read
	switch {
	case err == nil:
		s.linkTimes = true
	case !errors.Is(err, meta.ErrUnsupported):
		return in("setting the time of a link", err)
	}
	if err := s.x.root.Remove(link); err != nil {
		return in("removing a link", err)
	}
	return nil
}

// copiesNodes is false on Windows: there --diff-extract extracts only files
// and directories, as extraction there makes no links, pipes or devices
// that it can compare (doc/design.md 15.1).
const copiesNodes = runtime.GOOS != "windows"

// timePrecision gives the precision of a file system that stored want and
// gave back got: the smallest of the usual steps that is more than the
// difference. ok is false when the difference is 2 s or more.
func timePrecision(want, got time.Time) (p time.Duration, ok bool) {
	delta := want.Sub(got).Abs()
	for _, p := range []time.Duration{time.Nanosecond, time.Microsecond / 10, time.Microsecond,
		time.Millisecond, 10 * time.Millisecond, time.Second, 2 * time.Second} {
		if delta < p {
			return p, true
		}
	}
	return 0, false
}

// sameTime reports whether two times are the same to the precision of the
// scratch file system.
func (s *scratch) sameTime(a, b time.Time) bool { return a.Sub(b).Abs() < s.precision }

// name gives a new name in the scratch directory.
func (s *scratch) name() string { return "c" + strconv.FormatUint(s.seq.Add(1), 10) }

// skip counts a node that could not be made.
func (s *scratch) skip(t format.MemberType) {
	s.mu.Lock()
	s.skipped[t]++
	s.mu.Unlock()
}

// restorable reports whether the copy can have the extended attribute name:
// extraction restores it, and the scratch file system took it.
func (s *scratch) restorable(name string) bool {
	if xattrPolicy(meta.ClassifyXattr(name), s.x.cfg.Restore, s.root) != xattrRestore {
		return false
	}
	s.x.mu.Lock()
	defer s.x.mu.Unlock()
	return s.x.refused[name] == 0
}

// notices gives the notices of the run: what the copies could not have.
// Those items were compared with the archive only, as --diff compares them.
func (s *scratch) notices(rep Reporter) {
	if rep == nil {
		return
	}
	types := make([]string, 0, len(s.skipped))
	for t := range s.skipped {
		types = append(types, string(t))
	}
	sort.Strings(types)
	for _, t := range types {
		n, what := s.skipped[format.MemberType(t)], typeName(format.MemberType(t))
		reason := "this platform cannot make one safely"
		if t == string(format.TypeCharDev) || t == string(format.TypeBlockDev) {
			reason = "only root can make one"
		}
		rep.Warn("%d %s members were not extracted (%s); they were compared with the archive only", n, what, reason)
	}
	if len(s.x.refused) > 0 {
		names := make([]string, 0, len(s.x.refused))
		for name := range s.x.refused {
			names = append(names, name)
		}
		sort.Strings(names)
		rep.Warn("the scratch directory did not take the extended attributes %s; they were compared with the archive only",
			strings.Join(names, ", "))
	}
}

// close removes the scratch directory. It can be called more than once: a
// second call finds nothing to remove.
func (s *scratch) close() error {
	s.x.root.Close() // only a directory; nothing was written through it
	if err := removeScratch(s.dir); err != nil {
		return fmt.Errorf("removing the scratch directory: %w", err)
	}
	return nil
}

// removeScratch removes the scratch directory. A test makes it fail.
var removeScratch = os.RemoveAll

// extracts reports whether --diff-extract extracts the content of m. A
// hardlink whose target is compared too is not: its content is compared
// through the target, and --diff makes sure that the two paths are one file.
func (d *differ) extracts(m *format.Member) bool {
	if d.scratch == nil {
		return false
	}
	if m.Type != format.TypeHardlink {
		return true
	}
	// A target that is compared is selected under its own path. A tombstone
	// never is: the path is another member's, or no member's. The check of
	// the index makes sure that the target exists.
	t := d.byID[m.HardlinkTo]
	w := d.want[t.Path]
	return w == nil || w.ID != t.ID
}

// failCopy records an error of the copy of path. A full scratch directory
// gets the name of the option that chooses another.
func (d *differ) failCopy(path string, err error) {
	if errors.Is(err, syscall.ENOSPC) {
		err = fmt.Errorf("%w (the scratch directory %s is full; --scratch-dir chooses another)", err, d.scratch.dir)
	}
	d.fail(fmt.Errorf("%s: the copy: %w", path, err))
}

// extractFile is the step of a worker for one regular file: it extracts the
// content into the scratch directory, compares the copy with the file that
// the walk opened, and removes the copy. The digest of the file is compared
// with the member's as well, as --diff compares it.
func (d *differ) extractFile(w *fileWorker, job contentJob) {
	s := d.scratch
	path := job.e.Stored
	name := s.name()
	if err := w.writeFile(s.x.root, job.content, name, path); err != nil {
		d.failCopy(path, err)
		return
	}
	defer func() {
		if err := s.x.root.Remove(name); err != nil {
			d.failCopy(path, err)
		}
	}()
	cp, err := s.x.root.Open(name)
	if err != nil {
		d.failCopy(path, err)
		return
	}
	defer cp.Close()
	cpInfo, err := s.x.root.Lstat(name)
	if err != nil {
		d.failCopy(path, err)
		return
	}

	var diffs []Difference
	size := job.e.Info.Size()
	if cpInfo.Size() != size {
		diffs = append(diffs, Difference{Path: path, Kind: DiffSize, Extracted: true,
			Disk: strconv.FormatInt(size, 10), Archive: strconv.FormatInt(cpInfo.Size(), 10)})
	} else {
		// One read of a dense file gives the digest and the comparison. The
		// digest of a sparse member covers its data only, so sameContentOf
		// reads that, and the comparison reads the file again.
		var sameDigest bool
		var at int64
		if len(job.content.Sparse) == 0 {
			h := newDigest(d.r.keys)
			at, err = compareContent(io.TeeReader(job.f, h), cp.file(), job.e.Src)
			sameDigest = bytes.Equal(h.Sum(nil), job.content.Digest)
		} else {
			newHash := func() hash.Hash { return newDigest(d.r.keys) }
			sameDigest, err = sameContentOf(job.content, job.f, job.e, newHash)
			if err == nil {
				at, err = compareContent(io.NewSectionReader(job.f, 0, size), cp.file(), job.e.Src)
			}
		}
		if err != nil {
			d.fail(err)
			return
		}
		switch {
		case !sameDigest:
			// The content differs from the archive, as --diff says. The
			// copy then differs too, for the same reason.
			diffs = append(diffs, Difference{Path: path, Kind: DiffContent})
		case at >= 0:
			// The digests agree, but the bytes do not.
			diffs = append(diffs, Difference{Path: path, Kind: DiffContent, Extracted: true, Offset: at})
		}
	}

	more, err := d.compareCopy(job.m, job.e, job.f, cpInfo, func() (map[string][]byte, error) {
		return readXattrsFile(cp.file(), job.e.Src)
	}, job.found)
	if err != nil {
		d.fail(err)
		return
	}
	d.add(append(diffs, more...)...)
}

// compareContent reads src and cp to their ends, and returns the offset of
// the first byte that differs, or -1. A shorter one differs at its end.
// name is the path of src, for an error.
func compareContent(src, cp io.Reader, name string) (int64, error) {
	a := make([]byte, compareBlock)
	b := make([]byte, compareBlock)
	var off int64
	for {
		na, errA := io.ReadFull(src, a)
		nb, errB := io.ReadFull(cp, b)
		if errA != nil && errA != io.EOF && errA != io.ErrUnexpectedEOF {
			return 0, fmt.Errorf("reading %s: %w", name, errA)
		}
		if errB != nil && errB != io.EOF && errB != io.ErrUnexpectedEOF {
			return 0, fmt.Errorf("reading the copy of %s: %w", name, errB)
		}
		n := min(na, nb)
		if !bytes.Equal(a[:n], b[:n]) {
			return off + int64(firstDifference(a[:n], b[:n])), nil
		}
		if na != nb {
			return off + int64(n), nil
		}
		if na < compareBlock {
			return -1, nil
		}
		off += int64(na)
	}
}

// firstDifference returns the index of the first byte where a and b differ.
// They have one length, and they differ.
func firstDifference(a, b []byte) int {
	i := 0
	for a[i] == b[i] {
		i++
	}
	return i
}

// extractNode is the step of the walk for a member without content: a
// directory, a symbolic link, a pipe or a device node. It makes the node in
// the scratch directory, with the code of extraction, compares it with the
// node on disk, and removes it.
func (d *differ) extractNode(m *format.Member, e entry, found map[string]bool) {
	s := d.scratch
	if !copiesNodes && m.Type != format.TypeDir {
		return
	}
	name := s.name()
	placed := *m
	placed.Path = name
	_, err := s.x.extractNode(&placed)
	if err == nil && m.Type == format.TypeDir {
		err = s.x.finishDir(&placed)
	}
	var skipped *errSkipped
	if errors.As(err, &skipped) {
		s.skip(m.Type)
		return
	}
	if err != nil {
		d.failCopy(m.Path, err)
		s.x.root.Remove(name)
		return
	}
	defer func() {
		if err := s.x.root.Remove(name); err != nil {
			d.failCopy(m.Path, err)
		}
	}()

	cpInfo, err := s.x.root.Lstat(name)
	if err != nil {
		d.failCopy(m.Path, err)
		return
	}
	var diffs []Difference
	var cpXattrs func() (map[string][]byte, error)
	switch m.Type {
	case format.TypeSymlink:
		target, err := s.x.root.Readlink(name)
		if err != nil {
			d.failCopy(m.Path, err)
			return
		}
		if target = filepath.ToSlash(target); !found[DiffLink] && target != e.LinkTarget {
			diffs = append(diffs, Difference{Path: m.Path, Kind: DiffLink, Extracted: true,
				Disk: e.LinkTarget, Archive: target})
		}
	case format.TypeCharDev, format.TypeBlockDev:
		cs := meta.Stat(cpInfo)
		if !found[DiffDevice] && cs.OK && e.Sys.OK && (cs.Major != e.Sys.Major || cs.Minor != e.Sys.Minor) {
			diffs = append(diffs, Difference{Path: m.Path, Kind: DiffDevice, Extracted: true,
				Disk: fmt.Sprintf("%d,%d", e.Sys.Major, e.Sys.Minor), Archive: fmt.Sprintf("%d,%d", cs.Major, cs.Minor)})
		}
	case format.TypeDir:
		// By the path, which is safe in the private scratch directory: the
		// mode of the copy can forbid an open.
		cpXattrs = func() (map[string][]byte, error) {
			return readXattrsPath(filepath.Join(s.dir, name), false)
		}
	}
	more, err := d.compareCopy(m, e, e.self, cpInfo, cpXattrs, found)
	if err != nil {
		d.fail(err)
		return
	}
	d.add(append(diffs, more...)...)
}

// compareCopy compares the metadata of a copy with that of the path e on
// disk: what extraction restored on the copy. src is e open, for its
// extended attributes, and cpXattrs reads those of the copy: it is nil for
// a member that has none, as create records them on files and directories
// only. A kind in found differs between the archive and the disk already,
// so the copy is not compared for it.
func (d *differ) compareCopy(m *format.Member, e entry, src srcFile, cpInfo fs.FileInfo,
	cpXattrs func() (map[string][]byte, error), found map[string]bool) ([]Difference, error) {
	s := d.scratch
	opt := d.cfg.Metadata
	var diffs []Difference
	add := func(kind, disk, copied string) {
		diffs = append(diffs, Difference{Path: m.Path, Kind: kind, Extracted: true, Disk: disk, Archive: copied})
	}
	// Windows has no mode to restore (doc/design.md 15.1), and the mode of
	// a link means nothing (doc/design.md 7.6).
	if copiesNodes && m.Type != format.TypeSymlink && !found[DiffMode] {
		if a, b := meta.UnixMode(e.Info.Mode()), meta.UnixMode(cpInfo.Mode()); a != b {
			add(DiffMode, fmt.Sprintf("%04o", a), fmt.Sprintf("%04o", b))
		}
	}
	if s.x.cfg.Restore.Owner && m.UID != nil && m.GID != nil && !found[DiffOwner] {
		cs := meta.Stat(cpInfo)
		if cs.OK && e.Sys.OK && (cs.UID != e.Sys.UID || cs.GID != e.Sys.GID) {
			add(DiffOwner, fmt.Sprintf("%d:%d", e.Sys.UID, e.Sys.GID), fmt.Sprintf("%d:%d", cs.UID, cs.GID))
		}
	}
	if (m.Type != format.TypeSymlink || s.linkTimes) && !found[DiffMTime] &&
		!s.sameTime(e.Info.ModTime(), cpInfo.ModTime()) {
		add(DiffMTime, formatNanos(e.Info.ModTime().UnixNano()), formatNanos(cpInfo.ModTime().UnixNano()))
	}

	if cpXattrs == nil || !copiesNodes || opt.NoXattrs && opt.NoACLs {
		return diffs, nil
	}
	disk, err := readXattrs(e, src, opt, nil)
	if err != nil {
		return nil, err
	}
	all, err := cpXattrs()
	if err != nil {
		return nil, fmt.Errorf("%s: the copy: %w", m.Path, err)
	}
	var xattrs, acls []string
	for _, name := range xattrNames(disk, all) {
		if !opt.records(name) || !s.restorable(name) {
			continue
		}
		a, onDisk := disk[name]
		b, onCopy := all[name]
		if onDisk && onCopy && bytes.Equal(a, b) {
			continue
		}
		if meta.ClassifyXattr(name) == meta.XattrACL {
			acls = append(acls, name)
		} else {
			xattrs = append(xattrs, name)
		}
	}
	if len(xattrs) > 0 && !found[DiffXattrs] {
		diffs = append(diffs, Difference{Path: m.Path, Kind: DiffXattrs, Extracted: true, Names: xattrs})
	}
	if len(acls) > 0 && !found[DiffACLs] {
		diffs = append(diffs, Difference{Path: m.Path, Kind: DiffACLs, Extracted: true, Names: acls})
	}
	return diffs, nil
}
