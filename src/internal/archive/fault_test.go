package archive

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/philmalin/eictar/src/internal/codec"
	"github.com/philmalin/eictar/src/internal/crypt"
	"github.com/philmalin/eictar/src/internal/format"
	"github.com/philmalin/eictar/src/internal/testutil"
)

// faultFS is the file system of the archive files (fs.go) with faults
// (doc/testing.md 5, step 3). It counts each operation on an archive file
// or on its directory, and makes operation failAt fail. A write that fails
// writes half of its bytes first and gives ENOSPC, as a full disk does. Each
// other operation that fails gives EIO, and does nothing.
type faultFS struct {
	mu     sync.Mutex
	n      int
	failAt int
	// failOp, when it is set, makes the first operation of that kind fail
	// in place of operation failAt.
	failOp string
	failed string // the operation that failed, if one did
	// harmless means that a run can ignore the failed operation: a chown,
	// which a run that is not root cannot always do, or a close of a file
	// that the run did not write.
	harmless bool
	open     map[*faultFile]string // the files not closed yet
}

func (fs *faultFS) setHarmless() {
	fs.mu.Lock()
	fs.harmless = true
	fs.mu.Unlock()
}

func (fs *faultFS) step(op, name string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.n++
	switch {
	case fs.failOp != "":
		if op != fs.failOp || fs.failed != "" {
			return nil
		}
	case fs.n != fs.failAt:
		return nil
	}
	fs.failed = fmt.Sprintf("%s %s (operation %d)", op, filepath.Base(name), fs.n)
	errno := syscall.EIO
	if op == "write" {
		errno = syscall.ENOSPC
	}
	return &os.PathError{Op: op, Path: name, Err: errno}
}

func (fs *faultFS) wrap(f archiveFile, err error) (archiveFile, error) {
	if err != nil {
		return nil, err
	}
	ff := &faultFile{f: f, fs: fs}
	fs.mu.Lock()
	if fs.open == nil {
		fs.open = map[*faultFile]string{}
	}
	fs.open[ff] = f.Name()
	fs.mu.Unlock()
	return ff, nil
}

func (fs *faultFS) OpenArchive(path string, flag int) (archiveFile, error) {
	if err := fs.step("open", path); err != nil {
		return nil, err
	}
	return fs.wrap(osFS{}.OpenArchive(path, flag))
}

func (fs *faultFS) CreateNew(path string, perm os.FileMode) (archiveFile, error) {
	if err := fs.step("create", path); err != nil {
		return nil, err
	}
	return fs.wrap(osFS{}.CreateNew(path, perm))
}

func (fs *faultFS) CreateTemp(dir, pattern string) (archiveFile, error) {
	if err := fs.step("create", filepath.Join(dir, pattern)); err != nil {
		return nil, err
	}
	return fs.wrap(osFS{}.CreateTemp(dir, pattern))
}

func (fs *faultFS) Rename(oldpath, newpath string, replace bool) error {
	if err := fs.step("rename", oldpath); err != nil {
		return err
	}
	return osFS{}.Rename(oldpath, newpath, replace)
}

func (fs *faultFS) Remove(path string) error {
	if err := fs.step("remove", path); err != nil {
		return err
	}
	return osFS{}.Remove(path)
}

func (fs *faultFS) SyncDir(dir string) error {
	if err := fs.step("syncdir", dir); err != nil {
		return err
	}
	return osFS{}.SyncDir(dir)
}

// faultFile is an archive file of a faultFS.
type faultFile struct {
	f     archiveFile
	fs    *faultFS
	wrote atomic.Bool // a write or a truncate came through this file
}

func (f *faultFile) Read(p []byte) (int, error) {
	if err := f.fs.step("read", f.f.Name()); err != nil {
		return 0, err
	}
	return f.f.Read(p)
}

func (f *faultFile) Write(p []byte) (int, error) {
	f.wrote.Store(true)
	if err := f.fs.step("write", f.f.Name()); err != nil {
		n, _ := f.f.Write(p[:len(p)/2])
		return n, err
	}
	return f.f.Write(p)
}

func (f *faultFile) ReadAt(p []byte, off int64) (int, error) {
	if err := f.fs.step("read", f.f.Name()); err != nil {
		return 0, err
	}
	return f.f.ReadAt(p, off)
}

func (f *faultFile) Seek(off int64, whence int) (int64, error) {
	if err := f.fs.step("seek", f.f.Name()); err != nil {
		return 0, err
	}
	return f.f.Seek(off, whence)
}

func (f *faultFile) Sync() error {
	if err := f.fs.step("sync", f.f.Name()); err != nil {
		return err
	}
	return f.f.Sync()
}

func (f *faultFile) Truncate(size int64) error {
	f.wrote.Store(true)
	if err := f.fs.step("truncate", f.f.Name()); err != nil {
		return err
	}
	return f.f.Truncate(size)
}

func (f *faultFile) Stat() (os.FileInfo, error) {
	if err := f.fs.step("stat", f.f.Name()); err != nil {
		return nil, err
	}
	return f.f.Stat()
}

func (f *faultFile) Chmod(mode os.FileMode) error {
	if err := f.fs.step("chmod", f.f.Name()); err != nil {
		return err
	}
	return f.f.Chmod(mode)
}

func (f *faultFile) Chown(uid, gid int) error {
	if err := f.fs.step("chown", f.f.Name()); err != nil {
		f.fs.setHarmless()
		return err
	}
	return f.f.Chown(uid, gid)
}

// Close closes the file also when it fails, as close(2) does.
func (f *faultFile) Close() error {
	f.fs.mu.Lock()
	delete(f.fs.open, f)
	f.fs.mu.Unlock()
	err := f.fs.step("close", f.f.Name())
	if err != nil && !f.wrote.Load() {
		f.fs.setHarmless()
	}
	if cerr := f.f.Close(); err == nil {
		err = cerr
	}
	return err
}

func (f *faultFile) Name() string { return f.f.Name() }
func (f *faultFile) Fd() uintptr  { return f.f.Fd() }

// withFS runs fn with fs as the file system of the archive files.
func withFS(fs fileSystem, fn func() error) error {
	fsys = fs
	defer func() { fsys = osFS{} }()
	return fn()
}

// archiveState is what an archive holds, as a user sees it: each live member
// with its metadata and its content. "absent" is no file. Two archives with
// the same state give the same extraction, whatever their ids and keys.
func archiveState(path string, opens []OpenOptions) (string, error) {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return "absent", nil
	}
	var r *Reader
	var errs []error
	for _, o := range opens {
		var err error
		if r, err = OpenWith(path, o); err == nil {
			break
		}
		errs = append(errs, err)
	}
	if r == nil {
		for _, err := range errs {
			if IsDamage(err) {
				return "", err
			}
		}
		return "", errs[0]
	}
	defer r.Close()

	paths := map[uint64]string{}
	for _, m := range r.AllMembers() {
		paths[m.ID] = m.Path
	}
	ms := r.Members()
	sort.Slice(ms, func(i, j int) bool { return ms[i].Path < ms[j].Path })
	var b strings.Builder
	for i := range ms {
		m := &ms[i]
		fmt.Fprintf(&b, "%q %s %o size=%d mtime=%d link=%q", m.Path, m.Type, m.Mode, m.Size, m.MTimeNanos, m.LinkTarget)
		if m.Type == format.TypeHardlink {
			fmt.Fprintf(&b, " to=%q", paths[m.HardlinkTo])
		}
		if m.Type == format.TypeReg {
			h := sha256.New()
			if err := r.WriteMember(m, h); err != nil {
				return "", fmt.Errorf("%s: %w", m.Path, err)
			}
			fmt.Fprintf(&b, " content=%x", h.Sum(nil))
		}
		b.WriteString("\n")
	}
	return b.String(), nil
}

// copyDir copies the regular files of src into a new directory.
func copyDir(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	ents, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		fi, err := e.Info()
		if err != nil || !fi.Mode().IsRegular() {
			t.Fatalf("copyDir: %s: %v", e.Name(), err)
		}
		b := readAll(t, filepath.Join(src, e.Name()))
		if err := os.WriteFile(filepath.Join(dst, e.Name()), b, fi.Mode().Perm()); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

// faultCase is one operation that writes an archive.
type faultCase struct {
	name string
	// setup makes the state before in dir, and returns the archive's base
	// name. The archive need not exist.
	setup func(t *testing.T, dir string) string
	// run does the operation on the archive at path.
	run func(path string) error
	// opens are the ways to open the archive, before and after.
	opens []OpenOptions
}

// writeCases are the operations that write an archive, each from its state
// before. The fault tests and the power-loss tests run each one.
func writeCases(t *testing.T) []faultCase {
	t.Helper()
	tree := mutTree(t)
	tree.Text("t/big.txt", 0o644, strings.Repeat("several chunks of text. ", 2000))
	tree.Hardlink("t/link.txt", "t/a.txt")
	changed := mutTree(t)
	changed.Text("t/a.txt", 0o644, "alpha, changed")
	changed.Text("t/new.txt", 0o644, "a new file")
	dicts := dictTree(t, "src", 20)

	plain := []OpenOptions{openFor(false)}
	enc := []OpenOptions{openFor(true)}
	both := []OpenOptions{openFor(true), {Passphrase: passphrase("battery staple")}}
	// Two workers, not one for each CPU: each worker has its own encoder,
	// and under -race the set-up of 32 encoders made each run 15 times
	// slower.
	twoWorkers := func(c *AppendConfig) { c.Workers = 2 }
	create := func(tr *testutil.Tree, encrypted bool, params codec.Params, paths ...string) func(string) error {
		return func(path string) error {
			cfg := CreateConfig{
				Archive: path, Paths: paths, BaseDir: tr.Root, Workers: 2,
				Options: Options{Codec: "zstd", ChunkSize: 4096, Params: params},
			}
			if encrypted {
				cfg.Encryption = &EncryptionConfig{Passphrase: []byte("correct horse"), Params: testKDF, EncryptIndex: true}
			}
			_, err := CreateArchive(cfg)
			return err
		}
	}
	mk := func(tr *testutil.Tree, encrypted bool, paths ...string) func(*testing.T, string) string {
		return func(t *testing.T, dir string) string {
			if err := create(tr, encrypted, nil, paths...)(filepath.Join(dir, "m.ect")); err != nil {
				t.Fatal(err)
			}
			return "m.ect"
		}
	}
	appended := func(encrypted bool) func(*testing.T, string) string {
		return func(t *testing.T, dir string) string {
			name := mk(tree, encrypted, "t")(t, dir)
			if _, err := appendTo(t, filepath.Join(dir, name), changed, encrypted, twoWorkers, "t/a.txt"); err != nil {
				t.Fatal(err)
			}
			if _, err := DeleteMembers(DeleteConfig{Archive: filepath.Join(dir, name), Patterns: []string{"t/b.txt"}, Open: openFor(encrypted)}); err != nil {
				t.Fatal(err)
			}
			return name
		}
	}
	var cases []faultCase
	for _, e := range []bool{false, true} {
		suffix, opens := ", plain", plain
		if e {
			suffix, opens = ", encrypted", enc
		}
		cases = append(cases,
			faultCase{"create" + suffix, func(*testing.T, string) string { return "m.ect" }, create(tree, e, nil, "t"), opens},
			faultCase{"create over an archive" + suffix, mk(tree, e, "t"), create(changed, e, nil, "t"), opens},
			faultCase{"append" + suffix, mk(tree, e, "t"), func(path string) error {
				_, err := appendTo(t, path, changed, e, twoWorkers, "t/a.txt", "t/new.txt")
				return err
			}, opens},
			faultCase{"delete" + suffix, mk(tree, e, "t"), func(path string) error {
				_, err := DeleteMembers(DeleteConfig{Archive: path, Patterns: []string{"t/sub"}, Open: openFor(e)})
				return err
			}, opens},
			faultCase{"compact" + suffix, appended(e), func(path string) error {
				_, err := CompactArchive(CompactConfig{Archive: path, Open: openFor(e)})
				return err
			}, opens},
			faultCase{"recompress" + suffix, appended(e), func(path string) error {
				_, err := CompactArchive(CompactConfig{Archive: path, Open: openFor(e),
					Recompress: &RecompressConfig{Codec: "xz", Params: codec.Params{"preset": "1"}, ChunkSize: 64 << 10}})
				return err
			}, opens},
			faultCase{"create with a dictionary" + suffix, func(*testing.T, string) string { return "m.ect" },
				create(dicts, e, codec.Params{"train": "4K"}, "src"), opens},
			// The append loads the archive's dictionary, and uses it again.
			faultCase{"append with a dictionary" + suffix, func(t *testing.T, dir string) string {
				if err := create(dicts, e, codec.Params{"train": "4K"}, "src/f000.go", "src/f001.go", "src/f002.go",
					"src/f003.go", "src/f004.go", "src/f005.go", "src/f006.go", "src/f007.go")(filepath.Join(dir, "m.ect")); err != nil {
					t.Fatal(err)
				}
				return "m.ect"
			}, func(path string) error {
				_, err := appendTo(t, path, dicts, e, func(c *AppendConfig) {
					c.Workers = 2
					c.Options.Params = codec.Params{"train": "4K"}
				}, "src/f008.go", "src/f009.go")
				return err
			}, opens},
			// The compact copies the dictionary as it is.
			faultCase{"compact with a dictionary" + suffix, func(t *testing.T, dir string) string {
				path := filepath.Join(dir, "m.ect")
				if err := create(dicts, e, codec.Params{"train": "4K"}, "src")(path); err != nil {
					t.Fatal(err)
				}
				if _, err := DeleteMembers(DeleteConfig{Archive: path, Patterns: []string{"src/f000.go"}, Open: openFor(e)}); err != nil {
					t.Fatal(err)
				}
				return "m.ect"
			}, func(path string) error {
				_, err := CompactArchive(CompactConfig{Archive: path, Open: openFor(e)})
				return err
			}, opens},
			// The recompress learns a new dictionary from the members.
			faultCase{"recompress with a dictionary" + suffix, mk(dicts, e, "src"), func(path string) error {
				_, err := CompactArchive(CompactConfig{Archive: path, Open: openFor(e),
					Recompress: &RecompressConfig{Codec: "zstd", Params: codec.Params{"train": "4K"}, Workers: 2}})
				return err
			}, opens},
			faultCase{"repair" + suffix, func(t *testing.T, dir string) string {
				name := mk(tree, e, "t")(t, dir)
				f, err := os.OpenFile(filepath.Join(dir, name), os.O_APPEND|os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				if _, err := f.Write([]byte("the start of an append that a crash cut off")); err != nil {
					t.Fatal(err)
				}
				return name
			}, func(path string) error {
				_, err := RepairArchive(path, openFor(e))
				return err
			}, opens},
		)
	}
	cases = append(cases, faultCase{"change of passphrase", appended(true), func(path string) error {
		_, err := CompactArchive(CompactConfig{Archive: path, Open: openFor(true),
			Rewrap: &RewrapConfig{Passphrase: passphrase("battery staple"), Params: crypt.KDFParams{Time: 2}}})
		return err
	}, both})
	return cases
}

// TestFaultsLeaveTheOldOrTheNewArchive makes each operation on an archive
// file fail in turn, for each operation that writes an archive. After each
// fault, the archive must hold its old state or its new state, or --repair
// must give one of them back (doc/testing.md 5, step 3). An operation that
// reports success must have made the new state. No file stays open, and no
// temporary file stays behind unless its removal was what failed.
func TestFaultsLeaveTheOldOrTheNewArchive(t *testing.T) {
	cases := writeCases(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			template := t.TempDir()
			name := tc.setup(t, template)
			before, err := archiveState(filepath.Join(template, name), tc.opens)
			if err != nil && !IsDamage(err) {
				t.Fatalf("the state before: %v", err)
			}

			// A run with no fault counts the operations, and gives the state
			// after.
			dir := copyDir(t, template)
			count := &faultFS{}
			if err := withFS(count, func() error { return tc.run(filepath.Join(dir, name)) }); err != nil {
				t.Fatalf("with no fault: %v", err)
			}
			after, err := archiveState(filepath.Join(dir, name), tc.opens)
			if err != nil {
				t.Fatalf("the state after: %v", err)
			}
			if count.n == 0 {
				t.Fatal("the operation used no archive file: the seam is not in its path")
			}
			t.Logf("%d operations", count.n)
			if strings.Contains(tc.name, "dictionary") {
				r, err := OpenWith(filepath.Join(dir, name), tc.opens[0])
				if err != nil {
					t.Fatal(err)
				}
				n := len(r.index.Dicts)
				r.Close()
				if n == 0 {
					t.Fatal("the archive has no dictionary: the case does not test the writes of one")
				}
			}

			// Each run of a dictionary case trains a dictionary, which is
			// slow under -race. There, those cases test one fault point in
			// seven. The runs without -race test each one.
			stride := 1
			if raceDetector && strings.Contains(tc.name, "dictionary") {
				stride = 7
			}
			for k := 1; k <= count.n; k += stride {
				dir := copyDir(t, template)
				path := filepath.Join(dir, name)
				ff := &faultFS{failAt: k}
				runErr := withFS(ff, func() error { return tc.run(path) })
				checkFault(t, ff, k, path, runErr, before, after, tc.opens, before == "")
			}
		})
	}
}

// checkFault checks the archive at path after a run with fault k.
// wasTorn means that the archive needed a repair before the run.
func checkFault(t *testing.T, ff *faultFS, k int, path string, runErr error, before, after string, opens []OpenOptions, wasTorn bool) {
	t.Helper()
	what := ff.failed
	if what == "" {
		what = fmt.Sprintf("operation %d did not occur", k)
	}
	for _, name := range ff.open {
		t.Errorf("fault %s: %s stays open", what, filepath.Base(name))
	}
	// A fault of the disk is an I/O error (exit 4), not damage (exit 3).
	if runErr != nil && !wasTorn && IsDamage(runErr) {
		t.Errorf("fault %s: reported as damage: %v", what, runErr)
	}
	// The error is the fault, not what came of it later: a repair that
	// could not read a generation said that the archive had none.
	if runErr != nil && ff.failed != "" && !errors.Is(runErr, syscall.EIO) && !errors.Is(runErr, syscall.ENOSPC) {
		t.Errorf("fault %s: the error is not the fault: %v", what, runErr)
	}

	got, err := archiveState(path, opens)
	if err != nil {
		if !IsDamage(err) {
			t.Errorf("fault %s: the archive does not open, and it is not damage: %v", what, err)
			return
		}
		// A failed operation undoes what it wrote. Only a fault in the
		// truncate that undoes an append can leave a torn archive.
		if !wasTorn && !strings.HasPrefix(ff.failed, "truncate ") {
			t.Errorf("fault %s (run error: %v): the archive needs a repair: %v", what, runErr, err)
		}
		for _, o := range opens {
			if _, err = RepairArchive(path, o); err == nil {
				break
			}
		}
		if err != nil {
			t.Errorf("fault %s: repair: %v", what, err)
			return
		}
		if got, err = archiveState(path, opens); err != nil {
			t.Errorf("fault %s: after repair: %v", what, err)
			return
		}
	}
	// A failed operation must fail the run, unless the run can ignore it.
	if runErr == nil && ff.failed != "" && !ff.harmless {
		t.Errorf("fault %s: the run reported success", what)
	}
	switch {
	case runErr == nil && got != after:
		t.Errorf("fault %s: the run succeeded, but the archive is not the new one:\n%s\nwant:\n%s", what, got, after)
	case got != before && got != after:
		t.Errorf("fault %s (run error: %v): the archive is neither the old nor the new one:\n%s", what, runErr, got)
	}

	ents, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if e.Name() != filepath.Base(path) && !strings.HasPrefix(ff.failed, "remove ") {
			t.Errorf("fault %s: %s stays behind", what, e.Name())
		}
	}
}

var _ archiveFile = (*faultFile)(nil)

// TestReadFaultsAreNeverSilent makes each operation of an extraction and of a
// verify fail in turn. An extraction that reports success must have written
// each file with its content, and a verify that reports no damage must have
// read each member. The error is an I/O error, not damage: a backup script
// must not think that the archive is broken when the disk is.
func TestReadFaultsAreNeverSilent(t *testing.T) {
	tree := mutTree(t)
	tree.Text("t/big.txt", 0o644, strings.Repeat("several chunks of text. ", 2000))
	tree.Hardlink("t/link.txt", "t/a.txt")
	want := map[string]string{}
	for _, p := range []string{"t/a.txt", "t/b.txt", "t/sub/c.txt", "t/big.txt", "t/link.txt"} {
		want[p] = string(readAll(t, tree.Path(p)))
	}

	for _, enc := range []bool{false, true} {
		archive := mkArchive(t, tree, enc, "t")
		original := readAll(t, archive)
		ops := map[string]func(ff *faultFS) (string, error){
			"extract": func(ff *faultFS) (string, error) {
				dest := t.TempDir()
				err := withFS(ff, func() error {
					_, err := Extract(ExtractConfig{Archive: archive, Destination: dest, Passphrase: openFor(enc).Passphrase})
					return err
				})
				if err == nil {
					for p, content := range want {
						b, rerr := os.ReadFile(filepath.Join(dest, p))
						if rerr != nil || string(b) != content {
							t.Errorf("fault %s: the extraction succeeded, but %s is wrong: %v", ff.failed, p, rerr)
						}
					}
				}
				return checkRead(t, ff, err), err
			},
			"verify": func(ff *faultFS) (string, error) {
				var res VerifyResult
				err := withFS(ff, func() error {
					var err error
					res, err = VerifyArchive(VerifyConfig{Archive: archive, Open: openFor(enc)})
					return err
				})
				if err == nil && res.Failed == 0 && ff.failed != "" && !strings.HasPrefix(ff.failed, "close ") {
					t.Errorf("fault %s: the verify found no fault", ff.failed)
				}
				return checkRead(t, ff, err), err
			},
		}
		for name, op := range ops {
			t.Run(fmt.Sprintf("%s, encrypted=%v", name, enc), func(t *testing.T) {
				count := &faultFS{}
				_, err := op(count)
				if err != nil {
					t.Fatalf("with no fault: %v", err)
				}
				t.Logf("%d operations", count.n)
				for k := 1; k <= count.n; k++ {
					op(&faultFS{failAt: k})
				}
				if string(readAll(t, archive)) != string(original) {
					t.Fatal("a read changed the archive")
				}
			})
		}
	}
}

// checkRead checks what a run with a read fault leaves: no file open, and an
// error that is not damage.
func checkRead(t *testing.T, ff *faultFS, err error) string {
	t.Helper()
	for _, name := range ff.open {
		t.Errorf("fault %s: %s stays open", ff.failed, filepath.Base(name))
	}
	if err != nil && IsDamage(err) {
		t.Errorf("fault %s: reported as damage: %v", ff.failed, err)
	}
	return ff.failed
}

// TestOSFSGivesNoFileOnError: on an error, each method of osFS gives a nil
// archiveFile. A nil *os.File inside an archiveFile is not nil, so a caller
// that tests the file, not the error, would use it.
func TestOSFSGivesNoFileOnError(t *testing.T) {
	dir := t.TempDir()
	exists := filepath.Join(dir, "exists")
	if err := os.WriteFile(exists, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing", "x")
	for name, open := range map[string]func() (archiveFile, error){
		"OpenArchive": func() (archiveFile, error) { return osFS{}.OpenArchive(missing, os.O_RDONLY) },
		"CreateNew":   func() (archiveFile, error) { return osFS{}.CreateNew(exists, 0o644) },
		"CreateTemp":  func() (archiveFile, error) { return osFS{}.CreateTemp(missing, "x") },
	} {
		if f, err := open(); err == nil || f != nil {
			t.Errorf("%s: file %v, error %v; want no file and an error", name, f, err)
		}
	}
}
