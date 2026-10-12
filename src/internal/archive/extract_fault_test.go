package archive

import (
	"cmp"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/philmalin/eictar/src/internal/fsutil"
	"github.com/philmalin/eictar/src/internal/meta"
	"github.com/philmalin/eictar/src/internal/testutil"
)

// faultDest is a destination of an extraction with faults (doc/design.md
// 13.5, step 3). Each operation steps fs, the counter of the archive fault
// tests (faultFS). The operation that fs makes fail does nothing and gives
// its error. A write that fails writes half of its bytes first, as a full
// disk does.
type faultDest struct {
	d    destDir
	fs   *faultFS
	open *openSet
}

// openSet holds the directories and files of a destination that are open.
type openSet struct {
	mu sync.Mutex
	m  map[any]string
}

func (s *openSet) add(k any, what string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[any]string{}
	}
	s.m[k] = what
}

func (s *openSet) remove(k any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, k)
}

func (d *faultDest) MkdirAll(name string, perm fs.FileMode) error {
	if err := d.fs.step("mkdir", name); err != nil {
		return err
	}
	return d.d.MkdirAll(name, perm)
}

func (d *faultDest) Open(name string) (destFile, error) {
	if err := d.fs.step("open", name); err != nil {
		return nil, err
	}
	f, err := d.d.Open(name)
	if err != nil {
		return nil, err
	}
	ff := &faultDestFile{f: f, fs: d.fs, open: d.open, read: true}
	d.open.add(ff, "opened "+name)
	return ff, nil
}

func (d *faultDest) OpenRoot(name string) (destDir, error) {
	if err := d.fs.step("openroot", name); err != nil {
		return nil, err
	}
	r, err := d.d.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	fd := &faultDest{d: r, fs: d.fs, open: d.open}
	d.open.add(fd, "directory "+name)
	return fd, nil
}

func (d *faultDest) OpenFile(name string, flag int, perm fs.FileMode) (destFile, error) {
	if err := d.fs.step("create", name); err != nil {
		return nil, err
	}
	f, err := d.d.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	ff := &faultDestFile{f: f, fs: d.fs, open: d.open}
	d.open.add(ff, "file "+name)
	return ff, nil
}

func (d *faultDest) Lstat(name string) (fs.FileInfo, error) {
	if err := d.fs.step("lstat", name); err != nil {
		return nil, err
	}
	return d.d.Lstat(name)
}

func (d *faultDest) Lchown(name string, uid, gid int) error {
	if err := d.fs.step("lchown", name); err != nil {
		return err
	}
	return d.d.Lchown(name, uid, gid)
}

func (d *faultDest) Chmod(name string, mode fs.FileMode) error {
	if err := d.fs.step("chmod", name); err != nil {
		return err
	}
	return d.d.Chmod(name, mode)
}

func (d *faultDest) Chtimes(name string, atime, mtime time.Time) error {
	if err := d.fs.step("chtimes", name); err != nil {
		return err
	}
	return d.d.Chtimes(name, atime, mtime)
}

func (d *faultDest) Symlink(oldname, newname string) error {
	if err := d.fs.step("symlink", newname); err != nil {
		return err
	}
	return d.d.Symlink(oldname, newname)
}

func (d *faultDest) Link(oldname, newname string) error {
	if err := d.fs.step("link", newname); err != nil {
		return err
	}
	return d.d.Link(oldname, newname)
}

func (d *faultDest) Remove(name string) error {
	if err := d.fs.step("remove", name); err != nil {
		return err
	}
	return d.d.Remove(name)
}

func (d *faultDest) Rename(oldname, newname string) error {
	if err := d.fs.step("rename", oldname); err != nil {
		return err
	}
	return d.d.Rename(oldname, newname)
}

// Close of a directory changes nothing on the disk, so a run can ignore its
// failure.
func (d *faultDest) Close() error {
	d.open.remove(d)
	if err := d.fs.step("close", "a directory"); err != nil {
		d.fs.setHarmless()
		d.d.Close()
		return err
	}
	return d.d.Close()
}

// faultDestFile is a file of a faultDest.
type faultDestFile struct {
	f    destFile
	fs   *faultFS
	open *openSet
	// read means that it came from Open: nothing is written through it, so
	// a run can ignore the failure of its close.
	read bool
}

func (f *faultDestFile) Write(p []byte) (int, error) {
	if err := f.fs.step("write", "a file"); err != nil {
		n, _ := f.f.Write(p[:len(p)/2])
		return n, err
	}
	return f.f.Write(p)
}

func (f *faultDestFile) WriteAt(p []byte, off int64) (int, error) {
	if err := f.fs.step("write", "a file"); err != nil {
		n, _ := f.f.WriteAt(p[:len(p)/2], off)
		return n, err
	}
	return f.f.WriteAt(p, off)
}

func (f *faultDestFile) Truncate(size int64) error {
	if err := f.fs.step("truncate", "a file"); err != nil {
		return err
	}
	return f.f.Truncate(size)
}

func (f *faultDestFile) Chown(uid, gid int) error {
	if err := f.fs.step("chown", "a file"); err != nil {
		return err
	}
	return f.f.Chown(uid, gid)
}

func (f *faultDestFile) Chmod(mode fs.FileMode) error {
	if err := f.fs.step("chmod", "a file"); err != nil {
		return err
	}
	return f.f.Chmod(mode)
}

func (f *faultDestFile) Close() error {
	f.open.remove(f)
	if err := f.fs.step("close", "a file"); err != nil {
		if f.read {
			f.fs.setHarmless()
		}
		f.f.Close()
		return err
	}
	return f.f.Close()
}

func (f *faultDestFile) file() *os.File { return f.f.file() }

// withDest runs fn with the destination of each extraction wrapped by ff. open
// gets the directories and files that stay open.
func withDest(ff *faultFS, open *openSet, fn func() (Stats, error)) (Stats, error) {
	saved := openDest
	openDest = func(dir string) (destDir, error) {
		d, err := saved(dir)
		if err != nil {
			return nil, err
		}
		fd := &faultDest{d: d, fs: ff, open: open}
		open.add(fd, "the destination")
		return fd, nil
	}
	defer func() { openDest = saved }()

	// The calls of meta on a descriptor are operations on the destination
	// too.
	fifo, nod, linkTimes, xattr := mkfifo, mknod, setLinkTimes, setXattr
	defer func() { mkfifo, mknod, setLinkTimes, setXattr = fifo, nod, linkTimes, xattr }()
	mkfifo = func(dir *os.File, name string, mode uint32) error {
		if err := ff.step("mkfifo", name); err != nil {
			return err
		}
		return fifo(dir, name, mode)
	}
	mknod = func(dir *os.File, name string, char bool, mode, major, minor uint32) error {
		if err := ff.step("mknod", name); err != nil {
			return err
		}
		return nod(dir, name, char, mode, major, minor)
	}
	setLinkTimes = func(dir *os.File, name string, atime, mtime int64) error {
		if err := ff.step("setlinktimes", name); err != nil {
			return err
		}
		return linkTimes(dir, name, atime, mtime)
	}
	setXattr = func(f *os.File, name string, value []byte) error {
		if err := ff.step("setxattr", name); err != nil {
			return err
		}
		return xattr(f, name, value)
	}
	return fn()
}

// partFiles gives the temporary files of an extraction that stay under dir.
func partFiles(t *testing.T, dir string) []string {
	t.Helper()
	var parts []string
	filepath.WalkDir(dir, func(p string, e fs.DirEntry, err error) error {
		if err == nil && strings.HasPrefix(e.Name(), ".eictar-part-") {
			parts = append(parts, p)
		}
		return nil
	})
	return parts
}

// TestExtractFaultsAreNeverSilent makes each operation on the destination of
// an extraction fail in turn: each directory, file, link, mode, time and
// extended attribute that it writes, and each owner when it runs as root.
// These rules apply after each fault:
//   - An extraction that reports success, with no failed member, had no
//     fault, apart from the close of a handle that wrote nothing.
//   - The error is the fault itself: an I/O error, not damage, and not an
//     unsafe path.
//   - No directory or file stays open, and no temporary file stays behind,
//     unless its removal was what failed.
func TestExtractFaultsAreNeverSilent(t *testing.T) {
	tree := mutTree(t)
	tree.Text("t/big.txt", 0o644, strings.Repeat("several chunks of text. ", 2000))
	tree.Text("t/empty", 0o644, "")
	tree.Text("t/sub2/d.txt", 0o644, "delta") // one batch, two directories: t/sub and t/sub2
	tree.Hardlink("t/link.txt", "t/a.txt")
	tree.Symlink("t/sym", "a.txt")
	tree.Sparse("t/holes", 0o644, 1<<20, testutil.Segment{Offset: 1 << 19, Data: []byte("data in the middle")})
	if runtime.GOOS != "windows" {
		tree.Fifo("t/pipe", 0o644)
	}
	archive := mkArchive(t, tree, false, "t")

	for _, tc := range []struct {
		name      string
		over      bool // the tree is at the destination already
		keepGoing bool
	}{
		{"into an empty directory", false, false},
		{"over the tree", true, false},
		{"with --keep-going", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := func(ff *faultFS) (string, Stats, error) {
				t.Helper()
				dest := t.TempDir()
				if tc.over {
					if _, err := Extract(ExtractConfig{Archive: archive, Destination: dest}); err != nil {
						t.Fatal(err)
					}
				}
				var open openSet
				stats, err := withDest(ff, &open, func() (Stats, error) {
					return Extract(ExtractConfig{Archive: archive, Destination: dest, Workers: 2,
						KeepGoing: tc.keepGoing, Restore: RestoreOptions{Permissions: true, Owner: meta.IsRoot()}})
				})
				for _, what := range open.m {
					t.Errorf("fault %s: %s stays open", cmp.Or(ff.failed, "none"), what)
				}
				return dest, stats, err
			}

			count := &faultFS{}
			dest, _, err := run(count)
			if err != nil {
				t.Fatalf("with no fault: %v", err)
			}
			testutil.CompareTrees(t, tree.Root, dest, testutil.CompareOptions{Mode: true, MTime: true, Hardlinks: true})
			t.Logf("%d operations", count.n)

			for k := 1; k <= count.n; k++ {
				ff := &faultFS{failAt: k}
				dest, stats, err := run(ff)
				what := ff.failed
				if what == "" {
					what = "none"
				}
				switch {
				case err != nil && IsDamage(err):
					t.Errorf("fault %s: reported as damage: %v", what, err)
				case errors.Is(err, fsutil.ErrUnsafePath):
					// No path of the archive goes through a link.
					t.Errorf("fault %s: reported as an unsafe path: %v", what, err)
				case err == nil && stats.Failed <= 0 && ff.failed != "" && !ff.harmless:
					t.Errorf("fault %s: the extraction reported success (%d failed)", what, stats.Failed)
				case err != nil && !errors.Is(err, syscall.EIO) && !errors.Is(err, syscall.ENOSPC):
					// The error is the fault, not what came of it later: a
					// link that was not made, and then not found.
					t.Errorf("fault %s: the error is not the fault: %v", what, err)
				}
				if !strings.HasPrefix(ff.failed, "remove ") {
					for _, p := range partFiles(t, dest) {
						t.Errorf("fault %s: %s stays behind", what, p)
					}
				}
			}
		})
	}
}
