// Package testutil builds fixture trees and compares them. It is test-only
// support code, shared by the unit tests and the operational tests.
//
// Fixtures are built by code rather than committed to the repository, because
// a checkout cannot carry modes, hardlinks, sparse holes or exact timestamps
// faithfully (doc/design.md 13.3).
package testutil

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

// Tree is a directory of fixture files under a temporary root.
//
// Every method fails the test on error rather than returning one: a fixture
// that cannot be built is a broken test, not a condition worth handling.
type Tree struct {
	tb   testing.TB
	Root string
}

// NewTree creates an empty fixture tree that is removed when the test ends.
func NewTree(tb testing.TB) *Tree {
	tb.Helper()
	return &Tree{tb: tb, Root: tb.TempDir()}
}

// Path joins a relative path onto the tree root.
func (t *Tree) Path(rel string) string { return filepath.Join(t.Root, rel) }

// Dir creates a directory, and any parents, with the given mode.
func (t *Tree) Dir(rel string, mode os.FileMode) *Tree {
	t.tb.Helper()
	p := t.Path(rel)
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.tb.Fatalf("testutil: mkdir %s: %v", rel, err)
	}
	// MkdirAll applies the umask; set the mode explicitly so a fixture means
	// the same thing whatever umask the test runs under.
	if err := os.Chmod(p, mode); err != nil {
		t.tb.Fatalf("testutil: chmod %s: %v", rel, err)
	}
	return t
}

// File writes a regular file, creating parent directories as needed.
func (t *Tree) File(rel string, mode os.FileMode, content []byte) *Tree {
	t.tb.Helper()
	p := t.Path(rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.tb.Fatalf("testutil: mkdir for %s: %v", rel, err)
	}
	if err := os.WriteFile(p, content, mode); err != nil {
		t.tb.Fatalf("testutil: write %s: %v", rel, err)
	}
	if err := os.Chmod(p, mode); err != nil { // defeat the umask
		t.tb.Fatalf("testutil: chmod %s: %v", rel, err)
	}
	return t
}

// Text is File with a string, for readability at call sites.
func (t *Tree) Text(rel string, mode os.FileMode, content string) *Tree {
	t.tb.Helper()
	return t.File(rel, mode, []byte(content))
}

// Symlink creates a symbolic link at rel pointing at target. The target is
// stored verbatim and need not exist: a dangling link is a case worth
// archiving correctly.
func (t *Tree) Symlink(rel, target string) *Tree {
	t.tb.Helper()
	p := t.Path(rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.tb.Fatalf("testutil: mkdir for %s: %v", rel, err)
	}
	if err := os.Symlink(target, p); err != nil {
		t.tb.Fatalf("testutil: symlink %s -> %s: %v", rel, target, err)
	}
	return t
}

// Hardlink creates a second name for an existing file.
func (t *Tree) Hardlink(rel, existing string) *Tree {
	t.tb.Helper()
	p := t.Path(rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.tb.Fatalf("testutil: mkdir for %s: %v", rel, err)
	}
	if err := os.Link(t.Path(existing), p); err != nil {
		t.tb.Fatalf("testutil: link %s -> %s: %v", rel, existing, err)
	}
	return t
}

// Sparse creates a file of the given logical size whose only real data is the
// supplied segments. Whether the filesystem actually leaves holes is its
// business; what matters is that the logical layout is reproducible.
func (t *Tree) Sparse(rel string, mode os.FileMode, size int64, segments ...Segment) *Tree {
	t.tb.Helper()
	p := t.Path(rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.tb.Fatalf("testutil: mkdir for %s: %v", rel, err)
	}

	f, err := os.OpenFile(p, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		t.tb.Fatalf("testutil: create %s: %v", rel, err)
	}
	defer f.Close()

	for _, seg := range segments {
		if _, err := f.WriteAt(seg.Data, seg.Offset); err != nil {
			t.tb.Fatalf("testutil: write segment at %d of %s: %v", seg.Offset, rel, err)
		}
	}
	if err := f.Truncate(size); err != nil {
		t.tb.Fatalf("testutil: truncate %s to %d: %v", rel, size, err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.tb.Fatalf("testutil: chmod %s: %v", rel, err)
	}
	return t
}

// Segment is one run of real data in a sparse fixture file.
type Segment struct {
	Offset int64
	Data   []byte
}

// SetTimes sets the access and modification times of an existing entry.
func (t *Tree) SetTimes(rel string, atime, mtime time.Time) *Tree {
	t.tb.Helper()
	if err := os.Chtimes(t.Path(rel), atime, mtime); err != nil {
		t.tb.Fatalf("testutil: chtimes %s: %v", rel, err)
	}
	return t
}

// Chmod sets a mode, special bits included, which File's os.WriteFile cannot.
// On Windows, only the write bit of the owner has an effect: it is the
// read-only attribute.
func (t *Tree) Chmod(rel string, mode os.FileMode) *Tree {
	t.tb.Helper()
	if err := os.Chmod(t.Path(rel), mode); err != nil {
		t.tb.Fatalf("testutil: chmod %s: %v", rel, err)
	}
	return t
}

// Entry is one observed filesystem object, as Snapshot sees it.
type Entry struct {
	Path    string // relative to the tree root, slash-separated
	Mode    os.FileMode
	Size    int64
	Content []byte // regular files only
	Target  string // symlinks only
	MTime   time.Time
	// LinkGroup identifies hardlinked files: entries sharing an inode share a
	// group number. The numbers themselves carry no meaning across snapshots,
	// only the grouping does.
	LinkGroup int

	Xattrs map[string][]byte // user.* attributes only: the portable ones
	Blocks int64             // 512-byte blocks allocated, for hole checks
	UID    uint32
	GID    uint32
}

// Snapshot walks a directory and records what it finds, following no symlinks.
func Snapshot(tb testing.TB, root string) []Entry {
	tb.Helper()

	var out []Entry
	groups := map[inodeKey]int{}

	err := filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}

		e := Entry{
			Path:  filepath.ToSlash(rel),
			Mode:  fi.Mode(),
			Size:  fi.Size(),
			MTime: fi.ModTime(),
		}
		fillSys(&e, p, fi)
		switch {
		case fi.Mode()&os.ModeSymlink != 0:
			if e.Target, err = os.Readlink(p); err != nil {
				return err
			}
			e.Size = 0 // a symlink's size is its target length; compare the target instead
		case fi.Mode().IsRegular():
			if e.Content, err = os.ReadFile(p); err != nil {
				return err
			}
			if key, n, ok := inodeOf(p, fi); ok && n > 1 {
				g, seen := groups[key]
				if !seen {
					g = len(groups) + 1
					groups[key] = g
				}
				e.LinkGroup = g
			}
		}
		out = append(out, e)
		return nil
	})
	if err != nil {
		tb.Fatalf("testutil: walking %s: %v", root, err)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// CompareOptions selects which properties must match. The zero value compares
// paths, types, content and symlink targets.
type CompareOptions struct {
	Mode      bool // compare permission bits
	Special   bool // also compare setuid, setgid and sticky
	MTime     bool // compare modification times exactly, links included
	Hardlinks bool // compare which files share an inode
	Xattrs    bool // compare user.* extended attributes
	Holes     bool // a file with holes must still have them
	Owner     bool // compare uid and gid
}

// CompareTrees fails the test if the two trees differ in the selected
// properties. Differences are reported one per line, so a failure names every
// mismatch rather than only the first.
func CompareTrees(tb testing.TB, wantRoot, gotRoot string, opt CompareOptions) {
	tb.Helper()

	want := Snapshot(tb, wantRoot)
	got := Snapshot(tb, gotRoot)

	var diffs []string
	report := func(format string, args ...any) {
		diffs = append(diffs, fmt.Sprintf(format, args...))
	}

	byPath := make(map[string]Entry, len(got))
	for _, e := range got {
		byPath[e.Path] = e
	}

	for _, w := range want {
		g, ok := byPath[w.Path]
		if !ok {
			report("missing: %s", w.Path)
			continue
		}
		delete(byPath, w.Path)

		if w.Mode.Type() != g.Mode.Type() {
			report("%s: type %v, want %v", w.Path, g.Mode.Type(), w.Mode.Type())
			continue
		}
		if opt.Mode && w.Mode.Perm() != g.Mode.Perm() {
			report("%s: mode %04o, want %04o", w.Path, g.Mode.Perm(), w.Mode.Perm())
		}
		special := os.ModeSetuid | os.ModeSetgid | os.ModeSticky
		if opt.Special && w.Mode&special != g.Mode&special {
			report("%s: special bits %v, want %v", w.Path, g.Mode&special, w.Mode&special)
		}
		if opt.Xattrs && !sameXattrs(w.Xattrs, g.Xattrs) {
			report("%s: xattrs %v, want %v", w.Path, g.Xattrs, w.Xattrs)
		}
		if opt.Owner && (w.UID != g.UID || w.GID != g.GID) {
			report("%s: owner %d:%d, want %d:%d", w.Path, g.UID, g.GID, w.UID, w.GID)
		}
		if opt.Holes && w.Mode.IsRegular() && w.Blocks*512 < w.Size && g.Blocks*512 >= g.Size {
			report("%s: its holes were filled (%d blocks for %d bytes, want %d blocks)",
				w.Path, g.Blocks, g.Size, w.Blocks)
		}
		if w.Target != g.Target {
			report("%s: symlink target %q, want %q", w.Path, g.Target, w.Target)
		}
		if w.Mode.IsRegular() {
			if w.Size != g.Size {
				report("%s: size %d, want %d", w.Path, g.Size, w.Size)
			}
			if !bytes.Equal(w.Content, g.Content) {
				report("%s: content differs (%d bytes, want %d)", w.Path, len(g.Content), len(w.Content))
			}
		}
		// Links are compared too: extraction restores a link's own time with
		// utimensat and AT_SYMLINK_NOFOLLOW (M5). A fixture sets it with
		// SetLinkTimes.
		if opt.MTime && !w.MTime.Equal(g.MTime) {
			report("%s: mtime %v, want %v", w.Path, g.MTime, w.MTime)
		}
		if opt.Hardlinks && (w.LinkGroup != 0) != (g.LinkGroup != 0) {
			report("%s: hardlinked=%v, want %v", w.Path, g.LinkGroup != 0, w.LinkGroup != 0)
		}
	}

	extra := make([]string, 0, len(byPath))
	for p := range byPath {
		extra = append(extra, p)
	}
	sort.Strings(extra)
	for _, p := range extra {
		report("unexpected: %s", p)
	}

	if opt.Hardlinks {
		compareLinkGroups(want, got, report)
	}

	if len(diffs) > 0 {
		tb.Errorf("trees differ (want %s, got %s):\n  %s",
			wantRoot, gotRoot, joinLines(diffs))
	}
}

// compareLinkGroups checks that files sharing an inode in one tree also share
// one in the other. The group numbers differ between trees; only the
// partitioning is meaningful.
func compareLinkGroups(want, got []Entry, report func(string, ...any)) {
	gotGroup := make(map[string]int, len(got))
	for _, e := range got {
		gotGroup[e.Path] = e.LinkGroup
	}

	members := map[int][]string{}
	for _, e := range want {
		if e.LinkGroup != 0 {
			members[e.LinkGroup] = append(members[e.LinkGroup], e.Path)
		}
	}
	for _, paths := range members {
		if len(paths) < 2 {
			continue
		}
		sort.Strings(paths)
		first := gotGroup[paths[0]]
		for _, p := range paths[1:] {
			if first == 0 || gotGroup[p] != first {
				report("%s and %s should share an inode", paths[0], p)
			}
		}
	}
}

func sameXattrs(a, b map[string][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if !bytes.Equal(v, b[k]) {
			return false
		}
	}
	return true
}

func joinLines(lines []string) string {
	out := lines[0]
	for _, l := range lines[1:] {
		out += "\n  " + l
	}
	return out
}

// AcceptsNonUTF8 reports whether the filesystem of the tree keeps a file name
// that is not valid UTF-8. POSIX names are bytes, and Linux and the BSDs take
// any; APFS on macOS refuses them (EILSEQ). Windows names are UTF-16: Go
// writes U+FFFD for the bad byte, so the name that is read back is another
// name. A test of such names skips there.
func (t *Tree) AcceptsNonUTF8() bool {
	const name = ".probe-\xe9"
	p := filepath.Join(t.Root, name)
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		return false
	}
	defer os.Remove(p)
	entries, err := os.ReadDir(t.Root)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.Name() == name {
			return true
		}
	}
	return false
}
