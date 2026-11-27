package archive

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// openHookFS is the file system of the operating system, with a function
// that runs once before the first OpenArchive.
type openHookFS struct {
	fileSystem
	hook func(path string)
}

func (h *openHookFS) OpenArchive(path string, flag int) (archiveFile, error) {
	if hook := h.hook; hook != nil {
		h.hook = nil
		hook(path)
	}
	return h.fileSystem.OpenArchive(path, flag)
}

// withOpenHook makes hook run before the next open of an archive.
func withOpenHook(t *testing.T, hook func(path string)) {
	saved := fsys
	t.Cleanup(func() { fsys = saved })
	fsys = &openHookFS{fileSystem: saved, hook: hook}
}

// swapIn renames the file from over path, as another process can between
// the check of path and its open.
func swapIn(t *testing.T, from string) func(string) {
	return func(path string) {
		if err := os.Rename(from, path); err != nil {
			t.Errorf("swapping %s in: %v", path, err)
		}
	}
}

// TestCreateRefusesAFileSwappedBeforeItsOpen: when the file at -f is put
// in place of another between its Lstat and its open, create refuses it.
// The mode and the lock must come from the file that the rename replaces
// (doc/Security_Audit_Pass_2.eml, findings 15 and 17).
func TestCreateRefusesAFileSwappedBeforeItsOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.ect")
	other := filepath.Join(dir, "other")
	mkfile(t, dir, "a.ect")
	mkfile(t, dir, "other")
	withOpenHook(t, swapIn(t, other))

	w, err := Create(path, Options{})
	if err == nil {
		w.Abort()
	}
	if !errors.Is(err, ErrUnsafeTarget) {
		t.Errorf("Create = %v, want %v", err, ErrUnsafeTarget)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("the directory has %d entries after the refusal, want 1", len(entries))
	}
}

// TestCompactRefusesAFileSwappedBeforeItsOpen: the same for compact, which
// renames its new file over the archive that it read.
func TestCompactRefusesAFileSwappedBeforeItsOpen(t *testing.T) {
	archive := mkArchive(t, mutTree(t), false, "t")
	data, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	other := archive + ".other"
	if err := os.WriteFile(other, data, 0o644); err != nil {
		t.Fatal(err)
	}
	withOpenHook(t, swapIn(t, other))

	if _, err := CompactArchive(CompactConfig{Archive: archive}); !errors.Is(err, ErrUnsafeTarget) {
		t.Errorf("CompactArchive = %v, want %v", err, ErrUnsafeTarget)
	}
}

// TestCreateOfAFileRemovedBeforeItsOpen: a file that goes away between its
// Lstat and its open leaves a create with no file to replace. The rename
// then must not replace a file that another run made since.
func TestCreateOfAFileRemovedBeforeItsOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.ect")
	mkfile(t, dir, "a.ect")
	withOpenHook(t, func(p string) { os.Remove(p) })

	w, err := Create(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if w.guard != nil {
		t.Error("a guard for a file that is gone")
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if r, err := Open(path, nil); err != nil {
		t.Errorf("the new archive: %v", err)
	} else {
		r.Close()
	}
}

// TestOpenedAsSeen: the open must give the regular file that Lstat found.
func TestOpenedAsSeen(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	mkfile(t, dir, "a")
	mkfile(t, dir, "b")
	ai, _ := os.Lstat(a)
	bi, _ := os.Lstat(b)
	di, _ := os.Lstat(dir)
	for _, c := range []struct {
		name          string
		before, after fs.FileInfo
		ok            bool
	}{
		{"the same file", ai, ai, true},
		{"another file", ai, bi, false},
		{"nothing before", nil, ai, false},
		{"a directory before", di, di, false},
	} {
		err := openedAsSeen(a, c.before, c.after)
		if c.ok != (err == nil) || (err != nil && !errors.Is(err, ErrUnsafeTarget)) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// TestReplaceRule: the caller's file gives its mode; in a sticky directory
// that everyone can write, the file of a third user is refused, as under
// fs.protected_regular; any other file of another user only limits the
// mode (doc/Security_Audit_Pass_2.eml, finding 17).
func TestReplaceRule(t *testing.T) {
	const me, dirOwner, other = 1000, 2000, 3000
	shared := fs.ModeDir | fs.ModeSticky | 0o777
	for _, c := range []struct {
		name      string
		file, dir uint32
		mode      fs.FileMode
		dirOK     bool
		want      int
	}{
		{"own file in /tmp", me, 0, shared, true, replaceKeep},
		{"own file in a home", me, me, fs.ModeDir | 0o755, true, replaceKeep},
		{"a third user in /tmp", other, dirOwner, shared, true, replaceRefuse},
		{"the owner of /tmp", dirOwner, dirOwner, shared, true, replaceLimit},
		{"no owner of the directory", other, dirOwner, shared, false, replaceRefuse},
		{"sticky, not world-writable", other, dirOwner, fs.ModeDir | fs.ModeSticky | 0o775, true, replaceLimit},
		{"world-writable, not sticky", other, dirOwner, fs.ModeDir | 0o777, true, replaceLimit},
		{"another user's home", other, other, fs.ModeDir | 0o755, true, replaceLimit},
	} {
		if got := replaceRule(c.file, c.dir, me, c.mode, c.dirOK); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
}

// statFailFS opens archives whose Stat fails.
type statFailFS struct{ fileSystem }

type statFailFile struct{ archiveFile }

func (statFailFile) Stat() (os.FileInfo, error) { return nil, errStat }

var errStat = errors.New("stat failed")

func (s statFailFS) OpenArchive(path string, flag int) (archiveFile, error) {
	f, err := s.fileSystem.OpenArchive(path, flag)
	if err != nil {
		return nil, err
	}
	return statFailFile{f}, nil
}

// TestCreateStatOfTheOldFileFails: a create stops when the file that it
// replaces cannot give its mode and identity.
func TestCreateStatOfTheOldFileFails(t *testing.T) {
	dir := t.TempDir()
	mkfile(t, dir, "a.ect")
	saved := fsys
	t.Cleanup(func() { fsys = saved })
	fsys = statFailFS{saved}

	w, err := Create(filepath.Join(dir, "a.ect"), Options{})
	if err == nil {
		w.Abort()
	}
	if !errors.Is(err, errStat) {
		t.Errorf("Create = %v, want %v", err, errStat)
	}
}
