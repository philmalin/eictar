package archive

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"eictar/src/internal/format"
	"eictar/src/internal/fsutil"
	"eictar/src/internal/meta"
)

// ExtractConfig drives extraction.
type ExtractConfig struct {
	Archive     string
	Destination string // created if absent
	Patterns    []string
	Exclude     []string // --exclude and -X
	Overwrite   OverwritePolicy
	ToStdout    io.Writer // when non-nil, content goes here instead of to files
	KeepGoing   bool
	Reporter    Reporter

	// Passphrase supplies the key for an encrypted archive.
	Passphrase PassphraseFunc
	// RequireEncryption refuses an archive that is not encrypted; see
	// ErrNotEncrypted.
	RequireEncryption bool
	// Workers is the number of extracting goroutines; 0 means GOMAXPROCS.
	// Extraction to stdout ignores it: the output is one ordered stream.
	Workers int
	// MemoryLimit bounds what extraction may allocate; 0 takes a quarter of
	// RAM. It caps the worker count against the archive's chunk size.
	MemoryLimit int64

	// Restore selects which recorded metadata is applied.
	Restore RestoreOptions
}

// RestoreOptions selects the metadata extraction applies. The defaults are the
// safe ones: permission bits and times, user attributes and ACLs, nothing
// that needs privilege and nothing that grants it (doc/design.md 7 and 14).
type RestoreOptions struct {
	Permissions bool // -p: also restore setuid, setgid and sticky
	Owner       bool // --preserve-owner: chown to the recorded owner; needs root
	Devices     bool // --preserve-devices: create device nodes; needs root
	NoXattrs    bool // --no-xattrs: apply no extended attributes but ACLs
	NoACLs      bool // --no-acls: apply no POSIX ACLs
}

// OverwritePolicy decides what happens when an extracted path already exists.
type OverwritePolicy int

const (
	OverwriteAlways OverwritePolicy = iota
	OverwriteNever
	OverwriteNewer
)

// extraction carries the state one Extract call shares across its phases.
type extraction struct {
	r     *Reader
	root  *os.Root
	cfg   ExtractConfig
	names *meta.Names

	mu    sync.Mutex // guards stats, the reporter, extracted and refused
	stats Stats
	// extracted records the regular files written in this run, by member
	// id, so that a hardlink can link to its target rather than copy it.
	extracted map[uint64]string
	// refused counts, by name, the extended attributes that the destination
	// did not take. They are listed in one notice at the end of the run.
	refused map[string]int
}

// Extract writes the matching members under cfg.Destination.
//
// All filesystem work goes through os.Root, which holds a descriptor on the
// destination and refuses any path that leaves it - including a path reached
// *through* a symbolic link. That is what stops the classic attack of an
// archive containing "evil -> /etc" followed by "evil/passwd"; a lexical check
// alone cannot (doc/design.md 7).
func Extract(cfg ExtractConfig) (Stats, error) {
	r, err := OpenWith(cfg.Archive, OpenOptions{
		Passphrase: cfg.Passphrase, RequireEncryption: cfg.RequireEncryption,
	})
	if err != nil {
		return Stats{}, err
	}
	defer r.Close()

	members, err := selectMembers(r.Members(), cfg.Patterns)
	if err != nil {
		return Stats{}, err
	}
	members = excludeMembers(members, cfg.Exclude)
	sort.SliceStable(members, func(i, j int) bool { return members[i].Path < members[j].Path })

	// Tombstones are included: a live hardlink can point to one (§9.2).
	everything := r.AllMembers()
	byID := make(map[uint64]*format.Member, len(everything))
	for i := range everything {
		byID[everything[i].ID] = &everything[i]
	}

	if p := progressOf(cfg.Reporter); p != nil {
		p.Total(payloadTotal(members))
	}
	if cfg.ToStdout != nil {
		return extractToStdout(r, members, byID, cfg)
	}

	dest := cfg.Destination
	if dest == "" {
		dest = "."
	}
	if err := os.MkdirAll(dest, 0o777); err != nil {
		return Stats{}, fmt.Errorf("creating %s: %w", dest, err)
	}
	root, err := os.OpenRoot(dest)
	if err != nil {
		return Stats{}, fmt.Errorf("opening %s: %w", dest, err)
	}
	defer root.Close()

	x := &extraction{
		r: r, root: root, cfg: cfg, names: meta.NewNames(),
		extracted: map[uint64]string{}, refused: map[string]int{},
	}
	stats, err := x.run(members, byID)
	x.reportRefused()
	return stats, err
}

// reportRefused gives the one notice for the extended attributes that the
// destination did not take (doc/design.md 7.7): a macOS name on Linux, a
// Linux security.* name on FreeBSD, or any name on a filesystem without them.
func (x *extraction) reportRefused() {
	if len(x.refused) == 0 || x.cfg.Reporter == nil {
		return
	}
	names := make([]string, 0, len(x.refused))
	total := 0
	for name, n := range x.refused {
		names = append(names, name)
		total += n
	}
	sort.Strings(names)
	const shown = 8
	list := strings.Join(names[:min(shown, len(names))], ", ")
	if len(names) > shown {
		list += fmt.Sprintf(", and %d more", len(names)-shown)
	}
	x.cfg.Reporter.Warn("the destination did not take %d extended attributes (%d names): %s", total, len(names), list)
}

// run extracts in four phases.
//
//  1. Directories, links, pipes and devices, in path order, on this
//     goroutine. They carry no payload, the files need them to exist first,
//     and creating them in parallel would let the result depend on a race.
//  2. Regular files, across the workers.
//  3. Hardlinks, once their targets exist.
//  4. Directory metadata, deepest first, once every child exists: writing a
//     child changes its parent's mtime, and a default ACL set early would be
//     inherited by the files written into the directory.
func (x *extraction) run(members []format.Member, byID map[uint64]*format.Member) (Stats, error) {
	var dirs, files, links []format.Member

	for i := range members {
		m := &members[i]
		switch m.Type {
		case format.TypeReg:
			files = append(files, *m)
			continue
		case format.TypeHardlink:
			links = append(links, *m)
			continue
		}

		skipped, err := x.extractNode(m)
		if !x.record(m, skipped, err) {
			return x.stats, err
		}
		if m.Type == format.TypeDir && err == nil {
			dirs = append(dirs, *m)
		}
	}

	if err := x.extractFiles(files); err != nil {
		return x.stats, err
	}

	for i := range links {
		m := &links[i]
		skipped, err := x.extractHardlink(m, byID)
		if !x.record(m, skipped, err) {
			return x.stats, err
		}
	}

	if err := x.finishDirs(dirs); err != nil {
		return x.stats, err
	}
	return x.stats, nil
}

// record counts one member's outcome. It reports false when the run must stop.
func (x *extraction) record(m *format.Member, skipped bool, err error) bool {
	x.mu.Lock()
	defer x.mu.Unlock()

	var notice *errSkipped
	switch {
	case errors.As(err, &notice):
		x.stats.Skipped++
		x.warnLocked("%v", notice)
	case err != nil:
		x.stats.Failed++
		if !x.cfg.KeepGoing {
			return false
		}
		x.warnLocked("%v", err)
	case skipped:
		x.stats.Skipped++
	default:
		x.stats.Members++
		x.stats.Bytes += m.Size
		if x.cfg.Reporter != nil {
			x.cfg.Reporter.Member(m)
		}
	}
	return true
}

func (x *extraction) warnLocked(format string, args ...any) {
	if x.cfg.Reporter != nil {
		x.cfg.Reporter.Warn(format, args...)
	}
}

// extractNode handles everything without a payload: directories, symlinks,
// pipes, devices and sockets.
func (x *extraction) extractNode(m *format.Member) (bool, error) {
	if err := checkPath(m); err != nil {
		return false, err
	}

	switch m.Type {
	case format.TypeDir:
		// Created private; its real mode comes in the final pass, so that a
		// directory that ends up 0700 is never open while it is filled.
		if err := x.root.MkdirAll(m.Path, 0o700); err != nil {
			return false, unsafeOrRaw(x.root, m, err)
		}
		return false, nil

	case format.TypeSymlink:
		return x.writeSymlink(m)

	case format.TypeFIFO:
		return x.writeSpecial(m, func(dir *os.File, base string) error {
			return meta.Mkfifo(dir, base, 0o600)
		})

	case format.TypeCharDev, format.TypeBlockDev:
		if !x.cfg.Restore.Devices {
			return false, &errSkipped{reason: fmt.Sprintf("%s: device node skipped (use --preserve-devices, as root)", m.Path)}
		}
		char := m.Type == format.TypeCharDev
		return x.writeSpecial(m, func(dir *os.File, base string) error {
			return meta.Mknod(dir, base, char, 0o600, m.RDev[0], m.RDev[1])
		})

	case format.TypeSocket:
		return false, &errSkipped{reason: fmt.Sprintf("%s: socket ignored", m.Path)}

	default:
		return false, fmt.Errorf("member %q is a %s, which cannot be extracted", m.Path, m.Type)
	}
}

// checkPath is the lexical check that runs before os.Root does its own, so
// that a hostile path is reported as what it is.
func checkPath(m *format.Member) error {
	if !fsutil.IsStoredPath(m.Path) {
		return fmt.Errorf("%w: member %q is not in canonical stored form", fsutil.ErrUnsafePath, m.Path)
	}
	return nil
}

// parent opens the directory that will hold m, creating it private if it does
// not exist. The descriptor comes from os.Root, so the *at calls made against
// it with a single name component stay inside the destination.
func (x *extraction) parent(m *format.Member) (*os.File, string, error) {
	dir, base := path.Split(m.Path)
	dir = path.Clean(dir)
	if dir != "." {
		if err := x.root.MkdirAll(dir, 0o700); err != nil {
			return nil, "", unsafeOrRaw(x.root, m, err)
		}
	}
	f, err := x.root.Open(dir)
	if err != nil {
		return nil, "", unsafeOrRaw(x.root, m, err)
	}
	return f, base, nil
}

// clearForReplace applies the overwrite policy to a node that cannot be
// written over in place (a link, a pipe, a device): it reports a skip, or
// removes what is there.
func (x *extraction) clearForReplace(m *format.Member) (bool, error) {
	skip, err := shouldSkip(x.root, m, x.cfg.Overwrite)
	if err != nil || skip {
		return skip, err
	}
	if _, err := x.root.Lstat(m.Path); err == nil {
		if err := x.root.Remove(m.Path); err != nil {
			return false, fmt.Errorf("replacing %s: %w", m.Path, err)
		}
	}
	return false, nil
}

// writeSpecial creates a pipe or a device node and applies its metadata.
func (x *extraction) writeSpecial(m *format.Member, create func(dir *os.File, base string) error) (bool, error) {
	if skip, err := x.clearForReplace(m); err != nil || skip {
		return skip, err
	}
	dir, base, err := x.parent(m)
	if err != nil {
		return false, err
	}
	defer dir.Close()

	if err := create(dir, base); err != nil {
		if errors.Is(err, meta.ErrUnsupported) {
			// Only a call on a directory descriptor is safe from a planted
			// link, and this platform has none for this node type
			// (doc/design.md 15.1).
			return false, &errSkipped{reason: fmt.Sprintf("%s: a %s cannot be created safely on this platform; skipped", m.Path, m.Type)}
		}
		return false, fmt.Errorf("creating %s: %w", m.Path, err)
	}
	if err := x.applyOwner(m, func(uid, gid int) error { return x.root.Lchown(m.Path, uid, gid) }); err != nil {
		return false, err
	}
	if err := x.root.Chmod(m.Path, meta.FileMode(m.Mode, x.cfg.Restore.Permissions)); err != nil {
		return false, fmt.Errorf("setting mode of %s: %w", m.Path, err)
	}
	return false, x.applyTimes(m)
}

// writeSymlink recreates a link, target verbatim, and restores the link's own
// owner and times without touching what it points at.
func (x *extraction) writeSymlink(m *format.Member) (bool, error) {
	if skip, err := x.clearForReplace(m); err != nil || skip {
		return skip, err
	}
	if dir := path.Dir(m.Path); dir != "." {
		if err := x.root.MkdirAll(dir, 0o700); err != nil {
			return false, unsafeOrRaw(x.root, m, err)
		}
	}
	if err := x.root.Symlink(m.LinkTarget, m.Path); err != nil {
		return false, unsafeOrRaw(x.root, m, err)
	}

	if err := x.applyOwner(m, func(uid, gid int) error { return x.root.Lchown(m.Path, uid, gid) }); err != nil {
		return false, err
	}

	// os.Root.Chtimes follows the link and would retime its target. The
	// no-follow call works on the parent directory's descriptor instead.
	dir, base, err := x.parent(m)
	if err != nil {
		return false, err
	}
	defer dir.Close()
	if err := meta.SetLinkTimes(dir, base, x.atime(m), m.MTimeNanos); err != nil {
		if errors.Is(err, meta.ErrUnsupported) {
			return false, nil
		}
		return false, fmt.Errorf("setting times of %s: %w", m.Path, err)
	}
	return false, nil
}

// extractFiles writes regular files in parallel.
//
// Every worker reads its own byte ranges with ReadAt and writes through the
// shared os.Root, both of which are safe for concurrent use, so there is no
// shared file offset and no lock on the hot path.
func (x *extraction) extractFiles(files []format.Member) error {
	workers := x.cfg.Workers
	if workers < 1 {
		workers = runtime.GOMAXPROCS(0)
	}
	workers = min(workers, len(files))
	workers = boundByMemory(workers, files, x.cfg.MemoryLimit)
	if workers < 1 {
		return nil
	}

	var (
		wg       sync.WaitGroup
		firstErr error
		errMu    sync.Mutex
	)
	jobs := make(chan *format.Member)

	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for m := range jobs {
				skipped, err := x.extractFile(m, m.Path)
				if !x.record(m, skipped, err) {
					errMu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					errMu.Unlock()
				}
			}
		}()
	}

	for i := range files {
		errMu.Lock()
		stop := firstErr != nil
		errMu.Unlock()
		if stop {
			break
		}
		jobs <- &files[i]
	}
	close(jobs)
	wg.Wait()
	return firstErr
}

// extractFile writes one regular member's content under target, which is its
// own path, or a hardlink's path when the target member was not extracted.
func (x *extraction) extractFile(m *format.Member, target string) (bool, error) {
	placed := *m
	placed.Path = target
	if err := checkPath(&placed); err != nil {
		return false, err
	}

	skip, err := shouldSkip(x.root, &placed, x.cfg.Overwrite)
	if err != nil || skip {
		return skip, err
	}
	if dir := path.Dir(target); dir != "." {
		if err := x.root.MkdirAll(dir, 0o700); err != nil {
			return false, unsafeOrRaw(x.root, &placed, err)
		}
	}
	if err := x.writeFile(m, target); err != nil {
		return false, err
	}

	// The first path to receive this content is what later hardlinks link
	// to. That is the member's own path, or - when the member itself was not
	// selected - the first of its hardlinks, so that the other names become
	// links to that copy rather than copies of their own.
	x.mu.Lock()
	if _, done := x.extracted[m.ID]; !done {
		x.extracted[m.ID] = target
	}
	x.mu.Unlock()
	return false, nil
}

// writeFile writes content through a temporary file, renamed into place only
// once its digest has verified.
//
// Writing to the destination directly would mean a member that fails part way
// through has already destroyed whatever was there. Owner, extended
// attributes, mode and times all go on the temporary file before the rename,
// so the file never exists under its real name with the wrong ones - in
// particular never briefly readable by someone its final mode excludes. The
// owner goes first: chown clears setuid, so the mode has to follow it.
func (x *extraction) writeFile(m *format.Member, target string) error {
	tmp, err := tempName(target)
	if err != nil {
		return err
	}
	placed := *m
	placed.Path = target

	f, err := x.root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return unsafeOrRaw(x.root, &placed, err)
	}
	cleanup := func() { x.root.Remove(tmp) }

	var dst io.Writer = f
	if len(m.Sparse) > 0 {
		dst = &sparseWriter{f: f, segs: m.Sparse}
	}
	if err := x.r.WriteMember(m, countWriter(dst, progressOf(x.cfg.Reporter))); err != nil {
		f.Close()
		cleanup()
		return err
	}
	if len(m.Sparse) > 0 {
		// The holes are whatever the data does not cover, up to the logical
		// size, which truncation extends to without writing.
		if err := f.Truncate(int64(m.Size)); err != nil {
			f.Close()
			cleanup()
			return fmt.Errorf("sizing %s: %w", target, err)
		}
	}

	steps := []func() error{
		func() error { return x.applyXattrs(m, f, target) },
		func() error { return x.applyOwner(m, func(uid, gid int) error { return f.Chown(uid, gid) }) },
		func() error { return f.Chmod(meta.FileMode(m.Mode, x.cfg.Restore.Permissions)) },
	}
	for _, step := range steps {
		if err := step(); err != nil {
			f.Close()
			cleanup()
			return fmt.Errorf("%s: %w", target, err)
		}
	}
	if err := f.Close(); err != nil {
		cleanup()
		return fmt.Errorf("closing %s: %w", tmp, err)
	}

	mtime := time.Unix(0, m.MTimeNanos)
	if err := x.root.Chtimes(tmp, time.Unix(0, x.atime(m)), mtime); err != nil {
		cleanup()
		return fmt.Errorf("setting times of %s: %w", target, err)
	}
	if err := x.root.Rename(tmp, target); err != nil {
		cleanup()
		return fmt.Errorf("renaming %s into place: %w", tmp, err)
	}
	return nil
}

// extractHardlink links a member to its target. When the target was not
// extracted in this run - excluded by a pattern, say - the first such link
// gets the target's content instead, so that asking for one name of a file
// always produces the file. Later links to the same target link to it.
func (x *extraction) extractHardlink(m *format.Member, byID map[uint64]*format.Member) (bool, error) {
	if err := checkPath(m); err != nil {
		return false, err
	}
	target, ok := byID[m.HardlinkTo]
	if !ok {
		return false, fmt.Errorf("%w: hardlink %q names member %d, which is not in the archive",
			format.ErrCorruptIndex, m.Path, m.HardlinkTo)
	}

	x.mu.Lock()
	written, linked := x.extracted[target.ID]
	x.mu.Unlock()

	if !linked {
		return x.extractFile(target, m.Path)
	}

	if skip, err := x.clearForReplace(m); err != nil || skip {
		return skip, err
	}
	if dir := path.Dir(m.Path); dir != "." {
		if err := x.root.MkdirAll(dir, 0o700); err != nil {
			return false, unsafeOrRaw(x.root, m, err)
		}
	}
	if err := x.root.Link(written, m.Path); err != nil {
		return false, unsafeOrRaw(x.root, m, err)
	}
	return false, nil
}

// finishDirs applies directory metadata, deepest first.
func (x *extraction) finishDirs(dirs []format.Member) error {
	sort.Slice(dirs, func(i, j int) bool { return dirs[i].Path > dirs[j].Path })

	for i := range dirs {
		m := &dirs[i]
		d, err := x.root.Open(m.Path)
		if err != nil {
			return fmt.Errorf("opening %s: %w", m.Path, err)
		}
		err = x.applyXattrs(m, d, m.Path)
		if err == nil {
			err = x.applyOwner(m, func(uid, gid int) error { return d.Chown(uid, gid) })
		}
		if err == nil {
			err = d.Chmod(meta.FileMode(m.Mode, x.cfg.Restore.Permissions))
		}
		d.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", m.Path, err)
		}
		if err := x.root.Chtimes(m.Path, time.Unix(0, x.atime(m)), time.Unix(0, m.MTimeNanos)); err != nil {
			return fmt.Errorf("setting times of %s: %w", m.Path, err)
		}
	}
	return nil
}

// applyOwner restores ownership when --preserve-owner asked for it and the
// archive recorded it. The name wins over the number when the name exists
// here, as in tar: uid 1000 on one machine is rarely the same person on
// another, and "alice" usually is.
func (x *extraction) applyOwner(m *format.Member, chown func(uid, gid int) error) error {
	if !x.cfg.Restore.Owner || m.UID == nil || m.GID == nil {
		return nil
	}
	uid := x.names.ResolveUser(m.Uname, *m.UID)
	gid := x.names.ResolveGroup(m.Gname, *m.GID)
	if err := chown(int(uid), int(gid)); err != nil {
		return fmt.Errorf("setting the owner: %w", err)
	}
	return nil
}

// applyXattrs sets the recorded extended attributes the policy allows.
//
// User attributes, names with no namespace (every name from macOS) and ACLs
// are restored by default. security.*, trusted.* and the rest of system.* need
// privilege and are often specific to one machine or filesystem, so they are
// restored only as root. A name that the destination does not take - a macOS
// name on Linux, or any name on a filesystem without extended attributes -
// is counted for the one notice at the end of the run, not failed member by
// member (doc/design.md 7.7).
func (x *extraction) applyXattrs(m *format.Member, f *os.File, where string) error {
	if len(m.Xattrs) == 0 {
		return nil
	}
	names := make([]string, 0, len(m.Xattrs))
	for name := range m.Xattrs {
		names = append(names, name)
	}
	sort.Strings(names) // a stable order, so failures are reproducible

	for _, name := range names {
		switch meta.ClassifyXattr(name) {
		case meta.XattrUser, meta.XattrPlain:
			if x.cfg.Restore.NoXattrs {
				continue
			}
		case meta.XattrACL:
			if x.cfg.Restore.NoACLs {
				continue
			}
		case meta.XattrPrivileged:
			if x.cfg.Restore.NoXattrs || !meta.IsRoot() {
				continue
			}
		}
		if err := meta.SetXattr(f, name, m.Xattrs[name]); err != nil {
			if errors.Is(err, meta.ErrRefused) {
				x.mu.Lock()
				x.refused[name]++
				x.mu.Unlock()
				continue
			}
			return fmt.Errorf("%s: %w", where, err)
		}
	}
	return nil
}

// atime returns the access time to restore: the recorded one, or the
// modification time when none was recorded.
func (x *extraction) atime(m *format.Member) int64 {
	if m.ATimeNanos != 0 {
		return m.ATimeNanos
	}
	return m.MTimeNanos
}

// applyTimes sets atime and mtime on a node that is not a symbolic link.
func (x *extraction) applyTimes(m *format.Member) error {
	if err := x.root.Chtimes(m.Path, time.Unix(0, x.atime(m)), time.Unix(0, m.MTimeNanos)); err != nil {
		return fmt.Errorf("setting times of %s: %w", m.Path, err)
	}
	return nil
}

// sparseWriter places a sparse member's data stream at the offsets its map
// gives. The stream is the data segments back to back, which is what the
// archive stores (doc/design.md 5.1).
type sparseWriter struct {
	f    io.WriterAt
	segs []format.SparseSegment
	i    int    // the segment being filled
	done uint64 // bytes written into it
}

func (s *sparseWriter) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		if s.i >= len(s.segs) {
			return written, fmt.Errorf("%w: more data than the sparse map describes", format.ErrCorruptIndex)
		}
		seg := s.segs[s.i]
		n := min(uint64(len(p)), seg.Length-s.done)
		if _, err := s.f.WriteAt(p[:n], int64(seg.Offset+s.done)); err != nil {
			return written, err
		}
		written += int(n)
		p = p[n:]
		s.done += n
		if s.done == seg.Length {
			s.i++
			s.done = 0
		}
	}
	return written, nil
}

// holeExpander writes a sparse member to a stream, with the holes as zeroes.
// A pipe has no holes, so -O gets the file as it reads.
type holeExpander struct {
	w    io.Writer
	segs []format.SparseSegment
	size uint64
	i    int
	done uint64 // bytes of the current segment written
	pos  uint64 // logical position reached in the output
}

func (h *holeExpander) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		if h.i >= len(h.segs) {
			return written, fmt.Errorf("%w: more data than the sparse map describes", format.ErrCorruptIndex)
		}
		seg := h.segs[h.i]
		if err := h.zeroTo(seg.Offset + h.done); err != nil {
			return written, err
		}
		n := min(uint64(len(p)), seg.Length-h.done)
		if _, err := h.w.Write(p[:n]); err != nil {
			return written, err
		}
		written += int(n)
		p = p[n:]
		h.done += n
		h.pos += n
		if h.done == seg.Length {
			h.i++
			h.done = 0
		}
	}
	return written, nil
}

// Finish writes the trailing hole.
func (h *holeExpander) Finish() error { return h.zeroTo(h.size) }

var zeroes = make([]byte, 64<<10)

func (h *holeExpander) zeroTo(end uint64) error {
	for h.pos < end {
		n := min(end-h.pos, uint64(len(zeroes)))
		if _, err := h.w.Write(zeroes[:n]); err != nil {
			return err
		}
		h.pos += n
	}
	return nil
}

// extractToStdout writes content, in member order, to one stream. A hardlink
// writes its target's content; a sparse member writes its holes as zeroes.
func extractToStdout(r *Reader, members []format.Member, byID map[uint64]*format.Member, cfg ExtractConfig) (Stats, error) {
	var stats Stats
	for i := range members {
		m := &members[i]
		content := m
		if m.Type == format.TypeHardlink {
			if content = byID[m.HardlinkTo]; content == nil {
				return stats, fmt.Errorf("%w: hardlink %q names a missing member", format.ErrCorruptIndex, m.Path)
			}
		}
		if !content.Type.HasPayload() {
			continue
		}

		var err error
		progress := progressOf(cfg.Reporter)
		if len(content.Sparse) > 0 {
			h := &holeExpander{w: cfg.ToStdout, segs: content.Sparse, size: content.Size}
			if err = r.WriteMember(content, countWriter(h, progress)); err == nil {
				err = h.Finish()
			}
		} else {
			err = r.WriteMember(content, countWriter(cfg.ToStdout, progress))
		}
		if err != nil {
			stats.Failed++
			if cfg.KeepGoing {
				if cfg.Reporter != nil {
					cfg.Reporter.Warn("%v", err)
				}
				continue
			}
			return stats, err
		}
		stats.Members++
		stats.Bytes += content.Size
		if cfg.Reporter != nil {
			cfg.Reporter.Member(m)
		}
	}
	return stats, nil
}

// boundByMemory limits the worker count by what the members will make each
// worker allocate.
//
// Every worker decodes into a buffer of its member's chunk size, and that
// number comes from the index. It is capped at format.MaxChunkSize, but a cap
// of 256 MiB times 64 workers is still 16 GiB, so the archive's own figures
// decide how many workers are affordable rather than the flag alone
// (doc/design.md 8.3).
func boundByMemory(workers int, members []format.Member, limit int64) int {
	var largest int64
	for i := range members {
		if c := int64(members[i].ChunkSize); c > largest {
			largest = c
		}
	}
	if largest <= 0 {
		return workers
	}
	if limit <= 0 {
		limit = defaultExtractBudget()
	}
	// Two buffers per worker: the chunk as read and the chunk as decoded.
	affordable := int(limit / (2 * largest))
	if affordable < 1 {
		affordable = 1
	}
	return min(workers, affordable)
}

// defaultExtractBudget is what extraction may use when no limit was given.
func defaultExtractBudget() int64 {
	if ram := totalMemory(); ram > 0 {
		return ram / 4
	}
	return 512 << 20
}

// tempName returns a sibling name for the in-progress copy of a member. It
// stays in the same directory so the rename cannot cross a filesystem, and
// carries random bytes so that two workers, or two runs, never collide.
func tempName(memberPath string) (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generating a temporary name: %w", err)
	}
	dir, base := path.Split(memberPath)
	name := fmt.Sprintf(".eictar-part-%s-%x", base, b)
	// Keep the name within what a filesystem will accept.
	if len(name) > 200 {
		name = name[:180] + fmt.Sprintf("-%x", b)
	}
	return path.Join(dir, name), nil
}

func shouldSkip(root *os.Root, m *format.Member, policy OverwritePolicy) (bool, error) {
	fi, err := root.Lstat(m.Path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, unsafeOrRaw(root, m, err)
	}
	switch policy {
	case OverwriteNever:
		return true, nil
	case OverwriteNewer:
		return !time.Unix(0, m.MTimeNanos).After(fi.ModTime()), nil
	default:
		return false, nil
	}
}

// unsafeOrRaw decides whether a failed operation was an escape attempt.
//
// os.Root reports an escape with an unexported error, so rather than matching
// its text, this walks the member's own parent components: if any of them is a
// symbolic link, the archive was trying to write through it, and that is worth
// naming precisely. The check runs only on the failure path.
func unsafeOrRaw(root *os.Root, m *format.Member, err error) error {
	dir := path.Dir(m.Path)
	for dir != "." && dir != "/" && dir != "" {
		if fi, lerr := root.Lstat(dir); lerr == nil && fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: member %q would be written through the symbolic link %q",
				fsutil.ErrUnsafePath, m.Path, dir)
		}
		dir = path.Dir(dir)
	}
	return fmt.Errorf("extracting %s: %w", m.Path, err)
}
