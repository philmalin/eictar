package archive

import (
	"cmp"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/philmalin/eictar/src/internal/meta"
	"github.com/philmalin/eictar/src/internal/testutil"
)

// The fault tests of the source of a create (doc/testing.md 5, step 3):
// the walk, and the reads of each file, through srcPaths and srcDir.

// faultSrcPaths is srcPaths with faults: each operation steps fs, the counter
// of the archive fault tests (faultFS). The operation that fs makes fail
// does nothing and gives its error.
type faultSrcPaths struct {
	fs   *faultFS
	open *openSet
}

func (p *faultSrcPaths) Lstat(path string) (fs.FileInfo, error) {
	if err := p.fs.step("lstat", path); err != nil {
		return nil, err
	}
	return osSrcPaths{}.Lstat(path)
}

func (p *faultSrcPaths) Stat(path string) (fs.FileInfo, error) {
	if err := p.fs.step("stat", path); err != nil {
		return nil, err
	}
	return osSrcPaths{}.Stat(path)
}

func (p *faultSrcPaths) Readlink(path string) (string, error) {
	if err := p.fs.step("readlink", path); err != nil {
		return "", err
	}
	return osSrcPaths{}.Readlink(path)
}

func (p *faultSrcPaths) OpenRoot(path string) (srcDir, error) {
	if err := p.fs.step("openroot", path); err != nil {
		return nil, err
	}
	d, err := osSrcPaths{}.OpenRoot(path)
	return p.dir(d, path, err)
}

func (p *faultSrcPaths) Open(path string) (srcFile, error) {
	if err := p.fs.step("open", path); err != nil {
		return nil, err
	}
	f, err := osSrcPaths{}.Open(path)
	return p.file(f, path, err)
}

func (p *faultSrcPaths) OpenNoFollow(path string) (srcFile, error) {
	if err := p.fs.step("open", path); err != nil {
		return nil, err
	}
	f, err := osSrcPaths{}.OpenNoFollow(path)
	return p.file(f, path, err)
}

func (p *faultSrcPaths) dir(d srcDir, name string, err error) (srcDir, error) {
	if err != nil {
		return nil, err
	}
	fd := &faultSrcDir{d: d, p: p}
	p.open.add(fd, "directory "+name)
	return fd, nil
}

func (p *faultSrcPaths) file(f srcFile, name string, err error) (srcFile, error) {
	if err != nil {
		return nil, err
	}
	ff := &faultSrcFile{f: f, p: p}
	p.open.add(ff, "file "+name)
	return ff, nil
}

// faultSrcDir is a directory of the source with faults.
type faultSrcDir struct {
	d srcDir
	p *faultSrcPaths
}

func (d *faultSrcDir) Lstat(name string) (fs.FileInfo, error) {
	if err := d.p.fs.step("lstat", name); err != nil {
		return nil, err
	}
	return d.d.Lstat(name)
}

func (d *faultSrcDir) Stat(name string) (fs.FileInfo, error) {
	if err := d.p.fs.step("stat", name); err != nil {
		return nil, err
	}
	return d.d.Stat(name)
}

func (d *faultSrcDir) Readlink(name string) (string, error) {
	if err := d.p.fs.step("readlink", name); err != nil {
		return "", err
	}
	return d.d.Readlink(name)
}

func (d *faultSrcDir) OpenRoot(name string) (srcDir, error) {
	if err := d.p.fs.step("openroot", name); err != nil {
		return nil, err
	}
	sub, err := d.d.OpenRoot(name)
	return d.p.dir(sub, name, err)
}

func (d *faultSrcDir) Open(name string) (srcFile, error) {
	if err := d.p.fs.step("open", name); err != nil {
		return nil, err
	}
	f, err := d.d.Open(name)
	return d.p.file(f, name, err)
}

func (d *faultSrcDir) OpenFile(name string, flag int, perm fs.FileMode) (srcFile, error) {
	if err := d.p.fs.step("open", name); err != nil {
		return nil, err
	}
	f, err := d.d.OpenFile(name, flag, perm)
	return d.p.file(f, name, err)
}

// Close of a directory that is read changes nothing, so a run can ignore its
// failure.
func (d *faultSrcDir) Close() error {
	d.p.open.remove(d)
	if err := d.p.fs.step("close", "a directory"); err != nil {
		d.p.fs.setHarmless()
		d.d.Close()
		return err
	}
	return d.d.Close()
}

// faultSrcFile is a file of the source with faults.
type faultSrcFile struct {
	f srcFile
	p *faultSrcPaths
}

func (f *faultSrcFile) Read(b []byte) (int, error) {
	if err := f.p.fs.step("read", "a file"); err != nil {
		return 0, err
	}
	return f.f.Read(b)
}

func (f *faultSrcFile) ReadAt(b []byte, off int64) (int, error) {
	if err := f.p.fs.step("read", "a file"); err != nil {
		return 0, err
	}
	return f.f.ReadAt(b, off)
}

func (f *faultSrcFile) Stat() (fs.FileInfo, error) {
	if err := f.p.fs.step("stat", "a file"); err != nil {
		return nil, err
	}
	return f.f.Stat()
}

func (f *faultSrcFile) ReadDir(n int) ([]fs.DirEntry, error) {
	if err := f.p.fs.step("readdir", "a directory"); err != nil {
		return nil, err
	}
	return f.f.ReadDir(n)
}

// Close of a file that is read changes nothing, so a run can ignore its
// failure.
func (f *faultSrcFile) Close() error {
	f.p.open.remove(f)
	if err := f.p.fs.step("close", "a file"); err != nil {
		f.p.fs.setHarmless()
		f.f.Close()
		return err
	}
	return f.f.Close()
}

func (f *faultSrcFile) file() *os.File { return f.f.file() }

// withSrc runs fn with the source of each walk wrapped by ff. open gets the
// directories and files that stay open.
func withSrc(ff *faultFS, open *openSet, fn func() error) error {
	saved := srcPaths
	srcPaths = &faultSrcPaths{fs: ff, open: open}
	segs, xf, xp := dataSegments, readXattrsFile, readXattrsPath
	defer func() { srcPaths, dataSegments, readXattrsFile, readXattrsPath = saved, segs, xf, xp }()
	dataSegments = func(f *os.File, size, blocks int64) ([]meta.Segment, bool, error) {
		if err := ff.step("holes", f.Name()); err != nil {
			return nil, false, err
		}
		return segs(f, size, blocks)
	}
	readXattrsFile = func(f *os.File, path string) (map[string][]byte, error) {
		if err := ff.step("xattrs", path); err != nil {
			return nil, err
		}
		return xf(f, path)
	}
	readXattrsPath = func(path string, follow bool) (map[string][]byte, error) {
		if err := ff.step("xattrs", path); err != nil {
			return nil, err
		}
		return xp(path, follow)
	}
	return fn()
}

// TestCreateFaultsAreNeverSilent makes each operation on the source of a
// create fail in turn: each lstat, link, open, read and listing of the walk
// and of the reads of each file, its holes and its extended attributes.
// These rules apply after each fault:
//   - A create that reports success, with no failed member, had no fault,
//     apart from the close of what it read.
//   - The error is the fault itself, not damage.
//   - No directory or file of the source stays open.
func TestCreateFaultsAreNeverSilent(t *testing.T) {
	tree := mutTree(t)
	tree.Text("t/big.txt", 0o644, strings.Repeat("several chunks of text. ", 2000))
	tree.Text("t/empty", 0o644, "")
	tree.Text("t/copy.txt", 0o644, "alpha")
	tree.Hardlink("t/link.txt", "t/b.txt")
	tree.Symlink("t/sym", "a.txt")
	tree.Symlink("t/symdir", "sub")
	tree.Sparse("t/holes", 0o644, 1<<20, testutil.Segment{Offset: 1 << 19, Data: []byte("data in the middle")})

	for _, tc := range []struct {
		name          string
		keepGoing     bool
		dereference   bool
		oneFileSystem bool
		// update, when set, makes the run an append to an archive of the
		// tree: "replace" replaces each file, and a mode of -u compares each
		// with the archive.
		update string // or "diff" for a --diff of an archive of the tree
	}{
		{"create", false, false, false, ""},
		{"with --keep-going", true, false, false, ""},
		{"with -h", false, true, false, ""},
		{"with --one-file-system", false, false, true, ""},
		{"append", false, false, false, "replace"},
		{"append with --keep-going", true, false, false, "replace"},
		{"append -u=digest", false, false, false, UpdateDigest},
		{"--diff", false, false, false, "diff"},
		{"--diff with --keep-going", true, false, false, "diff"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var base string
			if tc.update != "" {
				base = mkArchive(t, tree, false, "t")
			}
			run := func(ff *faultFS) (Stats, error) {
				t.Helper()
				cfg := CreateConfig{Archive: filepath.Join(t.TempDir(), "x.ect"), Paths: []string{"t"},
					BaseDir: tree.Root, Workers: 2, KeepGoing: tc.keepGoing, Dereference: tc.dereference, OneFileSystem: tc.oneFileSystem,
					Options: Options{Codec: "zstd", ChunkSize: 4096}}
				if base != "" {
					cfg.Archive = copyArchive(t, base)
				}
				var open openSet
				var stats Stats
				err := withSrc(ff, &open, func() error {
					var err error
					switch tc.update {
					case "":
						stats, err = CreateArchive(cfg)
					case "diff":
						// A difference is no failure: a fault must not
						// show as one.
						var res DiffResult
						res, err = DiffArchive(DiffConfig{Archive: cfg.Archive, BaseDir: tree.Root, Workers: 2, KeepGoing: tc.keepGoing})
						stats.Failed = res.Failed
						if ff.failed == "" && len(res.Differences) > 0 {
							t.Errorf("with no fault, differences: %+v", res.Differences)
						}
					case "replace":
						stats, err = AppendArchive(AppendConfig{CreateConfig: cfg})
					default:
						stats, err = AppendArchive(AppendConfig{CreateConfig: cfg, UpdateMode: tc.update})
					}
					return err
				})
				for _, what := range open.m {
					t.Errorf("fault %s: %s stays open", cmp.Or(ff.failed, "none"), what)
				}
				return stats, err
			}

			count := &faultFS{}
			if _, err := run(count); err != nil {
				t.Fatalf("with no fault: %v", err)
			}
			t.Logf("%d operations", count.n)
			for k := 1; k <= count.n; k++ {
				ff := &faultFS{failAt: k}
				stats, err := run(ff)
				what := cmp.Or(ff.failed, "none")
				switch {
				case err != nil && IsDamage(err):
					t.Errorf("fault %s: reported as damage: %v", what, err)
				case err == nil && stats.Failed <= 0 && ff.failed != "" && !ff.harmless:
					t.Errorf("fault %s: the create reported success (%d failed)", what, stats.Failed)
				case err == nil && !tc.keepGoing && ff.failed != "" && !ff.harmless:
					// Without --keep-going, a fault stops the run with its error.
					t.Errorf("fault %s: no error without --keep-going (%d failed)", what, stats.Failed)
				case err != nil && !errors.Is(err, syscall.EIO):
					t.Errorf("fault %s: the error is not the fault: %v", what, err)
				}
			}
		})
	}
}

func (p *faultSrcPaths) EvalSymlinks(path string) (string, error) {
	if err := p.fs.step("evalsymlinks", path); err != nil {
		return "", err
	}
	return osSrcPaths{}.EvalSymlinks(path)
}
