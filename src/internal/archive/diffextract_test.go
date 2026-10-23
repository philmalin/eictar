//go:build unix

package archive

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"hash"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/philmalin/eictar/src/internal/crypt"
	"github.com/philmalin/eictar/src/internal/format"
	"github.com/philmalin/eictar/src/internal/meta"
	"github.com/philmalin/eictar/src/internal/testutil"
)

// foundX is found, with " extracted" after each difference of a copy.
func foundX(res DiffResult) []string {
	var out []string
	for _, d := range res.Differences {
		s := d.Path + " " + d.Kind
		if d.Extracted {
			s += " extracted"
		}
		out = append(out, s)
	}
	return out
}

// diffExtract runs --diff-extract of the archive against the tree, with a
// scratch directory of its own, and checks that the run removed it.
func diffExtract(t *testing.T, archivePath, base string, cfg DiffConfig) (DiffResult, error) {
	t.Helper()
	parent := t.TempDir()
	cfg.Archive, cfg.BaseDir, cfg.Extract, cfg.ScratchDir = archivePath, base, true, parent
	res, err := DiffArchive(cfg)
	if left, _ := os.ReadDir(parent); len(left) != 0 {
		t.Errorf("the scratch directory is still there: %v", left)
	}
	return res, err
}

func TestDiffExtractOfAnUnchangedTree(t *testing.T) {
	tree := diffFixture(t)
	archivePath := diffArchive(t, tree, "tree")

	res, err := diffExtract(t, archivePath, tree.Root, DiffConfig{})
	if err != nil {
		t.Fatalf("DiffArchive: %v", err)
	}
	if len(res.Differences) != 0 {
		t.Errorf("an unchanged tree has differences: %v", foundX(res))
	}
	if res.Compared != 15 {
		t.Errorf("compared %d members, want 15", res.Compared)
	}
}

// A change on disk is a difference with the archive, as --diff reports it.
// The copy differs for the same reason, and is not reported again.
func TestDiffExtractReportsEachCauseOnce(t *testing.T) {
	tree := diffFixture(t)
	archivePath := diffArchive(t, tree, "tree")
	tree.Text("tree/content.txt", 0o644, "content of content.tx!")
	tree.Chmod("tree/mode.txt", 0o600)
	os.Remove(tree.Path("tree/link"))
	tree.Symlink("tree/link", "other")
	tree.Chmod("tree/gonedir", 0o700)
	settle(tree)

	res, err := diffExtract(t, archivePath, tree.Root, DiffConfig{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"tree/content.txt content", "tree/gonedir mode", "tree/link link", "tree/mode.txt mode"}
	if got := foundX(res); !reflect.DeepEqual(got, want) {
		t.Errorf("differences:\n got %q\nwant %q", got, want)
	}
}

// firstChunkDigest is a digest with a fault: it hashes only the first 4 KiB
// of a member.
type firstChunkDigest struct {
	hash.Hash
	left int
}

func (h *firstChunkDigest) Write(p []byte) (int, error) {
	n := min(len(p), h.left)
	h.left -= n
	h.Hash.Write(p[:n])
	return len(p), nil
}

// The claim of --diff-extract: a fault of the digest code that create,
// --verify and --diff share does not hide a difference from it.
func TestDiffExtractFindsWhatTheDigestMisses(t *testing.T) {
	saved := newDigest
	t.Cleanup(func() { newDigest = saved })
	newDigest = func(keys *crypt.Keys) hash.Hash { return &firstChunkDigest{Hash: saved(keys), left: 4096} }

	tree := diffFixture(t)
	content := bytes.Repeat([]byte("0123456789abcdef"), 1024) // 16 KiB
	tree.File("tree/big", 0o644, content)
	settle(tree)
	archivePath := diffArchive(t, tree, "tree")
	content[10000] = 'X' // after the first chunk; the size does not change
	tree.File("tree/big", 0o644, content)
	settle(tree)

	if res, err := DiffArchive(DiffConfig{Archive: archivePath, BaseDir: tree.Root}); err != nil || len(res.Differences) != 0 {
		t.Fatalf("--diff: %v, %v; the fault must hide the change from it", found(res), err)
	}
	if _, err := VerifyArchive(VerifyConfig{Archive: archivePath}); err != nil {
		t.Fatalf("--verify: %v; the fault must hide nothing from it either", err)
	}
	res, err := diffExtract(t, archivePath, tree.Root, DiffConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := foundX(res), []string{"tree/big content extracted"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("--diff-extract: %q, want %q", got, want)
	}
	if res.Differences[0].Offset != 10000 {
		t.Errorf("offset %d, want 10000", res.Differences[0].Offset)
	}
}

// twistDest is the scratch directory with one fault of extraction: what it
// writes, or the mode or time that it sets, is wrong.
type twistDest struct {
	destDir
	twist string
}

func (d twistDest) OpenFile(name string, flag int, perm fs.FileMode) (destFile, error) {
	f, err := d.destDir.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return twistFile{f, d.twist}, nil
}

func (d twistDest) Chtimes(name string, atime, mtime time.Time) error {
	switch d.twist {
	case "time":
		// A fault of extraction: the probe of the precision sets its time
		// with the same call, and must see the file system as it is.
		if name != "probe" {
			mtime = mtime.Add(time.Second)
		}
	case "fat":
		// A file system that keeps times to 2 s, as FAT does.
		atime, mtime = atime.Truncate(2*time.Second), mtime.Truncate(2*time.Second)
	}
	return d.destDir.Chtimes(name, atime, mtime)
}

type twistFile struct {
	destFile
	twist string
}

func (d twistDest) Symlink(oldname, newname string) error {
	if d.twist == "link" && !strings.HasPrefix(newname, "probe") {
		oldname += "x"
	}
	return d.destDir.Symlink(oldname, newname)
}

func (f twistFile) Write(p []byte) (int, error) { return f.WriteAt(p, -1) }

// WriteAt writes p at off, or at the end of what was written with an off of
// -1, with the fault of the twist.
func (f twistFile) WriteAt(p []byte, off int64) (int, error) {
	write := func(q []byte) (int, error) {
		if off < 0 {
			return f.destFile.Write(q)
		}
		return f.destFile.WriteAt(q, off)
	}
	if len(p) == 0 {
		return write(p)
	}
	q := append([]byte(nil), p...)
	switch f.twist {
	case "byte":
		q[len(q)/2] ^= 1
	case "first":
		q[0] ^= 1
	case "short":
		// One byte less, and no error: a write that loses data.
		if _, err := write(q[:len(q)-1]); err != nil {
			return 0, err
		}
		return len(p), nil
	case "full":
		return 0, syscall.ENOSPC
	}
	return write(q)
}

func (f twistFile) Chown(uid, gid int) error {
	if f.twist == "owner" {
		uid++
	}
	return f.destFile.Chown(uid, gid)
}

func (f twistFile) Chmod(mode fs.FileMode) error {
	if f.twist == "mode" {
		mode &^= 0o040
	}
	return f.destFile.Chmod(mode)
}

func twistScratch(t *testing.T, twist string) {
	saved := openDest
	t.Cleanup(func() { openDest = saved })
	openDest = func(dir string) (destDir, error) {
		d, err := saved(dir)
		if err != nil {
			return nil, err
		}
		return twistDest{d, twist}, nil
	}
}

// A fault of extraction shows only in the copy: each one is a difference
// after extraction.
func TestDiffExtractFindsFaultsOfExtraction(t *testing.T) {
	for _, tc := range []struct{ twist, want string }{
		{"byte", "tree/same.txt content extracted"},
		{"first", "tree/same.txt content extracted"},
		{"short", "tree/same.txt size extracted"},
		{"mode", "tree/same.txt mode extracted"},
		{"time", "tree/same.txt mtime extracted"},
	} {
		t.Run(tc.twist, func(t *testing.T) {
			tree := diffFixture(t)
			archivePath := diffArchive(t, tree, "tree/same.txt")
			twistScratch(t, tc.twist)
			res, err := diffExtract(t, archivePath, tree.Root, DiffConfig{})
			if err != nil {
				t.Fatal(err)
			}
			if got := foundX(res); !reflect.DeepEqual(got, []string{tc.want}) {
				t.Errorf("got %q, want %q", got, tc.want)
			}
			if tc.twist == "first" && len(res.Differences) == 1 && res.Differences[0].Offset != 0 {
				t.Errorf("offset %d, want 0", res.Differences[0].Offset)
			}
		})
	}
}

func TestDiffExtractFindsAMissingAttribute(t *testing.T) {
	if !meta.Supports.Xattrs {
		t.Skip("no extended attributes on this platform")
	}
	tree := diffFixture(t)
	tree.Xattr("tree/same.txt", "user.kept", []byte("1"))
	settle(tree)
	archivePath := diffArchive(t, tree, "tree/same.txt")

	saved := setXattr
	t.Cleanup(func() { setXattr = saved })
	setXattr = func(f *os.File, name string, value []byte) error { return nil } // sets nothing

	res, err := diffExtract(t, archivePath, tree.Root, DiffConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := foundX(res), []string{"tree/same.txt xattrs extracted"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// An attribute that the scratch file system does not take is not a
// difference of the copy: the run says so in one notice, and --diff compares
// it with the archive.
func TestDiffExtractOfAnAttributeThatTheScratchRefuses(t *testing.T) {
	if !meta.Supports.Xattrs {
		t.Skip("no extended attributes on this platform")
	}
	tree := diffFixture(t)
	tree.Xattr("tree/same.txt", "user.kept", []byte("1"))
	settle(tree)
	archivePath := diffArchive(t, tree, "tree/same.txt")

	saved := setXattr
	t.Cleanup(func() { setXattr = saved })
	setXattr = func(f *os.File, name string, value []byte) error {
		return fmt.Errorf("setting %s: %w", name, meta.ErrRefused)
	}

	rep := &recordingReporter{}
	res, err := diffExtract(t, archivePath, tree.Root, DiffConfig{Reporter: rep})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Differences) != 0 {
		t.Errorf("differences: %q", foundX(res))
	}
	if len(rep.warnings) != 1 || !strings.Contains(rep.warnings[0], "user.kept") {
		t.Errorf("notices: %q, want one that names user.kept", rep.warnings)
	}
}

// The times are compared to the precision of the scratch file system: a
// copy on a file system of 2 s is not a difference of time.
func TestDiffExtractComparesTimesToThePrecisionOfTheScratch(t *testing.T) {
	tree := diffFixture(t)
	stamp := diffStamp.Add(1500 * time.Millisecond)
	tree.SetTimes("tree/same.txt", stamp, stamp)
	archivePath := diffArchive(t, tree, "tree/same.txt")
	twistScratch(t, "fat")

	res, err := diffExtract(t, archivePath, tree.Root, DiffConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Differences) != 0 {
		t.Errorf("differences: %q", foundX(res))
	}
}

func TestTimePrecision(t *testing.T) {
	want := time.Unix(1_700_000_001, 123_456_789)
	for _, tc := range []struct {
		got  time.Time
		p    time.Duration
		isOK bool
	}{
		{want, time.Nanosecond, true},
		{want.Truncate(100 * time.Nanosecond), 100 * time.Nanosecond, true},
		{want.Truncate(time.Microsecond), time.Microsecond, true},
		{want.Truncate(10 * time.Millisecond), 10 * time.Millisecond, true},
		{want.Truncate(time.Second), time.Second, true},
		{want.Truncate(2 * time.Second), 2 * time.Second, true},
		{want.Add(2 * time.Second), 0, false},
		{time.Now(), 0, false},
	} {
		if p, ok := timePrecision(want, tc.got); p != tc.p || ok != tc.isOK {
			t.Errorf("timePrecision(%v): %v, %v; want %v, %v", tc.got, p, ok, tc.p, tc.isOK)
		}
	}
}

func TestDiffExtractRefusesAScratchInTheTree(t *testing.T) {
	tree := diffFixture(t)
	archivePath := diffArchive(t, tree, "tree")
	for _, parent := range []string{tree.Path("tree"), tree.Path("tree/gonedir")} {
		_, err := DiffArchive(DiffConfig{Archive: archivePath, BaseDir: tree.Root, Extract: true, ScratchDir: parent})
		if !errors.Is(err, ErrScratchInTree) {
			t.Errorf("scratch in %s: %v, want ErrScratchInTree", parent, err)
		}
	}
	// A relative path, and a path through a link, are in the tree too.
	t.Chdir(tree.Root)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(tree.Path("tree"), link); err != nil {
		t.Fatal(err)
	}
	for _, parent := range []string{"tree/gonedir", link} {
		_, err := DiffArchive(DiffConfig{Archive: archivePath, BaseDir: tree.Root, Extract: true, ScratchDir: parent})
		if !errors.Is(err, ErrScratchInTree) {
			t.Errorf("scratch in %s: %v, want ErrScratchInTree", parent, err)
		}
	}
	// Beside the tree is not in it.
	if _, err := DiffArchive(DiffConfig{Archive: archivePath, BaseDir: tree.Root, Extract: true, ScratchDir: tree.Root}); err != nil {
		t.Errorf("scratch beside the tree: %v", err)
	}
	if left, _ := filepath.Glob(filepath.Join(tree.Root, "eictar-diff-*")); len(left) != 0 {
		t.Errorf("left behind: %v", left)
	}
}

func TestDiffExtractOfAFullScratch(t *testing.T) {
	tree := diffFixture(t)
	archivePath := diffArchive(t, tree, "tree")
	twistScratch(t, "full")

	_, err := diffExtract(t, archivePath, tree.Root, DiffConfig{})
	if !errors.Is(err, syscall.ENOSPC) || !strings.Contains(err.Error(), "--scratch-dir") {
		t.Errorf("err = %v, want ENOSPC that names --scratch-dir", err)
	}
	res, err := diffExtract(t, archivePath, tree.Root, DiffConfig{KeepGoing: true})
	if err != nil {
		t.Fatalf("--keep-going: %v", err)
	}
	if res.Failed == 0 || res.Damaged != 0 {
		t.Errorf("--keep-going: %d failed, %d damaged; want failures and no damage", res.Failed, res.Damaged)
	}
}

// Damage in the archive is found when the copy is decoded.
func TestDiffExtractOfADamagedArchive(t *testing.T) {
	tree := diffFixture(t)
	data := make([]byte, 64<<10)
	rand.New(rand.NewSource(1)).Read(data)
	tree.File("tree/random", 0o644, data)
	settle(tree)
	archivePath := filepath.Join(t.TempDir(), "a.ect")
	if _, err := CreateArchive(CreateConfig{Archive: archivePath, Paths: []string{"tree/random"}, BaseDir: tree.Root,
		Options: Options{Codec: "none", ChunkSize: 1 << 20}}); err != nil {
		t.Fatal(err)
	}
	flipByteAt(t, archivePath, 1000) // in the content of the one member

	if res, err := DiffArchive(DiffConfig{Archive: archivePath, BaseDir: tree.Root}); err != nil || len(res.Differences) != 0 {
		t.Fatalf("--diff reads no member data: %v, %v", found(res), err)
	}
	_, err := diffExtract(t, archivePath, tree.Root, DiffConfig{})
	if !IsDamage(err) {
		t.Errorf("err = %v, want damage", err)
	}
	res, err := diffExtract(t, archivePath, tree.Root, DiffConfig{KeepGoing: true})
	if err != nil || res.Damaged != 1 {
		t.Errorf("--keep-going: %d damaged, %v; want 1", res.Damaged, err)
	}
}

// The workers extract in any order; the result must not depend on it.
func TestDiffExtractDoesNotDependOnWorkers(t *testing.T) {
	tree := diffFixture(t)
	archivePath := diffArchive(t, tree, "tree")
	tree.Text("tree/content.txt", 0o644, "content of content.tx!")
	tree.Chmod("tree/dup1", 0o600)
	settle(tree)
	twistScratch(t, "byte")

	var first []string
	for _, workers := range []int{1, 2, 8} {
		res, err := diffExtract(t, archivePath, tree.Root, DiffConfig{Workers: workers})
		if err != nil {
			t.Fatalf("-j %d: %v", workers, err)
		}
		if workers == 1 {
			first = foundX(res)
			continue
		}
		if got := foundX(res); !reflect.DeepEqual(got, first) {
			t.Errorf("-j %d: %q, -j 1: %q", workers, got, first)
		}
	}
	if len(first) < 5 {
		t.Errorf("differences: %q, want each file", first)
	}
}

// TestDiffExtractFaultsAreNeverSilent makes each operation on the scratch
// directory fail in turn: those of the probe, and each file, directory,
// link, pipe, mode, time and attribute of a copy. After each fault, the run
// fails with that fault, no handle stays open, and the scratch directory is
// removed. Only the close of a handle that wrote nothing can fail harmlessly.
func TestDiffExtractFaultsAreNeverSilent(t *testing.T) {
	tree := diffFixture(t)
	if pipesExtracted(t) {
		tree.Fifo("tree/pipe", 0o644)
	}
	if meta.Supports.Xattrs {
		tree.Xattr("tree/same.txt", "user.kept", []byte("1"))
	}
	settle(tree)
	archivePath := diffArchive(t, tree, "tree")

	run := func(ff *faultFS) (DiffResult, error) {
		t.Helper()
		var open openSet
		var res DiffResult
		_, err := withDest(ff, &open, func() (Stats, error) {
			var err error
			res, err = diffExtract(t, archivePath, tree.Root, DiffConfig{Workers: 2})
			return Stats{}, err
		})
		for _, what := range open.m {
			t.Errorf("fault %s: %s stays open", cmp.Or(ff.failed, "none"), what)
		}
		return res, err
	}
	count := &faultFS{}
	if res, err := run(count); err != nil || len(res.Differences) != 0 {
		t.Fatalf("with no fault: %q, %v", foundX(res), err)
	}
	t.Logf("%d operations", count.n)
	check := func(ff *faultFS) {
		t.Helper()
		_, err := run(ff)
		switch {
		case ff.failed == "" || ff.harmless:
		case err == nil:
			t.Errorf("fault %s: the run reported success", ff.failed)
		case !errors.Is(err, syscall.EIO) && !errors.Is(err, syscall.ENOSPC):
			t.Errorf("fault %s: the error is not the fault: %v", ff.failed, err)
		}
	}
	for k := 1; k <= count.n; k++ {
		check(&faultFS{failAt: k})
	}
	// The workers and the walk interleave, so operation k is not the same
	// one in each run. The first operation of each kind, on the probe and
	// on a copy, is.
	for _, op := range destOps {
		for _, probe := range []bool{true, false} {
			check(&faultFS{failIf: func(o, name string) bool {
				return o == op && strings.HasPrefix(filepath.Base(name), "probe") == probe
			}})
		}
	}
}

// destOps are the kinds of operation of faultDest, and of the calls of meta
// that withDest wraps.
var destOps = []string{"mkdir", "open", "openroot", "create", "lstat", "lchown", "chmod", "chtimes",
	"symlink", "readlink", "link", "remove", "rename", "close", "write", "truncate", "chown",
	"mkfifo", "mknod", "setlinktimes", "setxattr"}

// A scratch directory that cannot be removed is an error of the run.
func TestDiffExtractOfAScratchThatStays(t *testing.T) {
	tree := diffFixture(t)
	archivePath := diffArchive(t, tree, "tree")
	saved := removeScratch
	t.Cleanup(func() { removeScratch = saved })
	removeScratch = func(dir string) error {
		saved(dir)
		return syscall.EIO
	}
	_, err := diffExtract(t, archivePath, tree.Root, DiffConfig{})
	if !errors.Is(err, syscall.EIO) || !strings.Contains(err.Error(), "removing the scratch directory") {
		t.Errorf("err = %v, want the failed removal", err)
	}
}

func TestCompareContent(t *testing.T) {
	block := bytes.Repeat([]byte{'a'}, compareBlock)
	two := append(append([]byte(nil), block...), block...)
	changed := func(b []byte, at int) []byte {
		c := append([]byte(nil), b...)
		c[at] ^= 1
		return c
	}
	for _, tc := range []struct {
		name    string
		src, cp []byte
		want    int64
	}{
		{"empty", nil, nil, -1},
		{"the same", []byte("abc"), []byte("abc"), -1},
		{"one block", block, block, -1},
		{"two blocks", two, two, -1},
		{"the first byte", []byte("abc"), []byte("xbc"), 0},
		{"the last byte", []byte("abc"), []byte("abx"), 2},
		{"in the second block", two, changed(two, compareBlock+5), compareBlock + 5},
		{"a shorter copy", []byte("abc"), []byte("ab"), 2},
		{"a longer copy", []byte("ab"), []byte("abc"), 2},
		{"a longer copy after a block", block, append(append([]byte(nil), block...), 'x'), compareBlock},
		{"a shorter copy in the second block", two, two[:compareBlock+3], compareBlock + 3},
	} {
		got, err := compareContent(bytes.NewReader(tc.src), bytes.NewReader(tc.cp), "src")
		if err != nil || got != tc.want {
			t.Errorf("%s: %d, %v; want %d", tc.name, got, err, tc.want)
		}
	}

	bad := &errorReader{err: syscall.EIO}
	if _, err := compareContent(bad, bytes.NewReader(nil), "src"); !errors.Is(err, syscall.EIO) ||
		!strings.Contains(err.Error(), "reading src") {
		t.Errorf("a source that cannot be read: %v", err)
	}
	if _, err := compareContent(bytes.NewReader(nil), bad, "src"); !errors.Is(err, syscall.EIO) ||
		!strings.Contains(err.Error(), "the copy of src") {
		t.Errorf("a copy that cannot be read: %v", err)
	}
}

type errorReader struct{ err error }

func (r *errorReader) Read([]byte) (int, error) { return 0, r.err }

func TestSameTime(t *testing.T) {
	s := &scratch{precision: 2 * time.Second}
	a := time.Unix(1_600_000_000, 0)
	for _, tc := range []struct {
		b    time.Time
		same bool
	}{
		{a, true},
		{a.Add(1999 * time.Millisecond), true},
		{a.Add(-1999 * time.Millisecond), true},
		{a.Add(2 * time.Second), false},
		{a.Add(-2 * time.Second), false},
	} {
		if got := s.sameTime(a, tc.b); got != tc.same {
			t.Errorf("sameTime(%v, %v) = %v", a, tc.b, got)
		}
	}
}

func TestScratchNotices(t *testing.T) {
	s := &scratch{
		skipped: map[format.MemberType]int{format.TypeCharDev: 2, format.TypeFIFO: 1},
		x:       &extraction{refused: map[string]int{"user.b": 1, "user.a": 3}},
	}
	s.notices(nil) // no reporter: no notices, and no panic
	rep := &recordingReporter{}
	s.notices(rep)
	want := []string{
		"2 character device members were not extracted (only root can make one); they were compared with the archive only",
		"1 FIFO members were not extracted (this platform cannot make one safely); they were compared with the archive only",
		"the scratch directory did not take the extended attributes user.a, user.b; they were compared with the archive only",
	}
	if !reflect.DeepEqual(rep.warnings, want) {
		t.Errorf("notices:\n got %q\nwant %q", rep.warnings, want)
	}
	rep = &recordingReporter{}
	(&scratch{x: &extraction{}}).notices(rep)
	if len(rep.warnings) != 0 {
		t.Errorf("notices with nothing to say: %q", rep.warnings)
	}
}

// A pipe that the platform cannot make is compared with the archive only,
// with a notice.
func TestDiffExtractOfAPipeThatCannotBeMade(t *testing.T) {
	if !pipesExtracted(t) {
		t.Skip("no pipes on this platform")
	}
	tree := diffFixture(t)
	tree.Fifo("tree/pipe", 0o644)
	settle(tree)
	archivePath := diffArchive(t, tree, "tree/pipe")
	saved := mkfifo
	t.Cleanup(func() { mkfifo = saved })
	mkfifo = func(*os.File, string, uint32) error { return meta.ErrUnsupported }

	rep := &recordingReporter{}
	res, err := diffExtract(t, archivePath, tree.Root, DiffConfig{Reporter: rep})
	if err != nil || len(res.Differences) != 0 {
		t.Fatalf("%q, %v", foundX(res), err)
	}
	if want := "1 FIFO members were not extracted (this platform cannot make one safely); they were compared with the archive only"; len(rep.warnings) != 1 || rep.warnings[0] != want {
		t.Errorf("notices: %q", rep.warnings)
	}
}

func TestDiffExtractOfALink(t *testing.T) {
	tree := diffFixture(t)
	archivePath := diffArchive(t, tree, "tree/link")
	t.Run("target", func(t *testing.T) {
		twistScratch(t, "link")
		res, err := diffExtract(t, archivePath, tree.Root, DiffConfig{})
		if got, want := foundX(res), []string{"tree/link link extracted"}; err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%q, %v; want %q", got, err, want)
		}
	})
	t.Run("time", func(t *testing.T) {
		saved := setLinkTimes
		t.Cleanup(func() { setLinkTimes = saved })
		setLinkTimes = func(dir *os.File, name string, atime, mtime int64) error {
			if name != "probe-link" {
				mtime += int64(time.Hour)
			}
			return saved(dir, name, atime, mtime)
		}
		res, err := diffExtract(t, archivePath, tree.Root, DiffConfig{})
		if got, want := foundX(res), []string{"tree/link mtime extracted"}; err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%q, %v; want %q", got, err, want)
		}
	})
}

// A hardlink whose target is compared is not extracted: the target's copy
// shows the content. Alone, it is extracted with the target's content.
func TestDiffExtractOfAHardlink(t *testing.T) {
	tree := diffFixture(t)
	archivePath := diffArchive(t, tree, "tree")
	twistScratch(t, "byte")
	// The walk found hard first, so same.txt is the hardlink member.
	res, err := diffExtract(t, archivePath, tree.Root, DiffConfig{Patterns: []string{"tree/hard", "tree/same.txt"}})
	if got, want := foundX(res), []string{"tree/hard content extracted"}; err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("with its target: %q, %v; want %q", got, err, want)
	}
	res, err = diffExtract(t, archivePath, tree.Root, DiffConfig{Patterns: []string{"tree/same.txt"}})
	if got, want := foundX(res), []string{"tree/same.txt content extracted"}; err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("alone: %q, %v; want %q", got, err, want)
	}
}

func TestDiffExtractOfASparseFile(t *testing.T) {
	tree := diffFixture(t)
	tree.Sparse("tree/holes", 0o644, 1<<20, testutil.Segment{Offset: 1 << 19, Data: []byte("data in the middle")})
	settle(tree)
	archivePath := diffArchive(t, tree, "tree/holes")
	res, err := diffExtract(t, archivePath, tree.Root, DiffConfig{})
	if err != nil || len(res.Differences) != 0 {
		t.Fatalf("unchanged: %q, %v", foundX(res), err)
	}
	twistScratch(t, "byte")
	res, err = diffExtract(t, archivePath, tree.Root, DiffConfig{})
	if got, want := foundX(res), []string{"tree/holes content extracted"}; err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("a wrong byte: %q, %v; want %q", got, err, want)
	}
}

// The attributes and the ACLs of a copy are two differences, each with its
// names. --no-acls leaves out the ACLs only.
func TestDiffExtractOfAttributesAndACLs(t *testing.T) {
	tree := mutTree(t)
	path := copyArchive(t, mkArchive(t, tree, false, "t/a.txt"))
	// A privileged attribute is compared only as root, who restores it.
	recorded := map[string][]byte{"user.a": []byte("1"), "system.posix_acl_access": []byte("1"), "trusted.x": []byte("1")}
	forgeIndex(t, path, nil, func(ix *format.Index) { ix.Members[0].Xattrs = recorded })
	ff, sx := readXattrsFile, setXattr
	t.Cleanup(func() { readXattrsFile, setXattr = ff, sx })
	// The file on disk has what the archive records. The copy gets nothing.
	readXattrsFile = func(f *os.File, _ string) (map[string][]byte, error) {
		if strings.HasSuffix(f.Name(), "a.txt") {
			return recorded, nil
		}
		return nil, nil
	}
	setXattr = func(*os.File, string, []byte) error { return nil }

	var got []string
	res, err := diffExtract(t, path, tree.Root, DiffConfig{})
	for _, d := range res.Differences {
		got = append(got, fmt.Sprintf("%s:%v", foundX(DiffResult{Differences: []Difference{d}})[0], d.Names))
	}
	want := []string{"t/a.txt xattrs extracted:[user.a]", "t/a.txt acls extracted:[system.posix_acl_access]"}
	if meta.IsRoot() {
		want[0] = "t/a.txt xattrs extracted:[trusted.x user.a]"
	}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("%q, %v; want %q", got, err, want)
	}
	res, err = diffExtract(t, path, tree.Root, DiffConfig{Metadata: MetadataOptions{NoACLs: true}})
	if got, want := foundX(res), []string{"t/a.txt xattrs extracted"}; err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("--no-acls: %q, %v; want %q", got, err, want)
	}
}

func TestDiffExtractOfAScratchThatIsNotThere(t *testing.T) {
	tree := diffFixture(t)
	archivePath := diffArchive(t, tree, "tree")
	_, err := DiffArchive(DiffConfig{Archive: archivePath, BaseDir: tree.Root, Extract: true,
		ScratchDir: filepath.Join(t.TempDir(), "no such directory")})
	if !errors.Is(err, fs.ErrNotExist) || !strings.Contains(err.Error(), "creating the scratch directory") {
		t.Errorf("err = %v", err)
	}

	saved := openDest
	t.Cleanup(func() { openDest = saved })
	openDest = func(string) (destDir, error) { return nil, syscall.EIO }
	parent := t.TempDir()
	_, err = DiffArchive(DiffConfig{Archive: archivePath, BaseDir: tree.Root, Extract: true, ScratchDir: parent})
	if !errors.Is(err, syscall.EIO) {
		t.Errorf("a scratch directory that does not open: %v", err)
	}
	if left, _ := os.ReadDir(parent); len(left) != 0 {
		t.Errorf("left behind: %v", left)
	}
}

// Without --scratch-dir, the scratch directory goes in $TMPDIR, and the
// check of the tree applies to that.
func TestDiffExtractUsesTMPDIR(t *testing.T) {
	tree := diffFixture(t)
	archivePath := diffArchive(t, tree, "tree")
	t.Setenv("TMPDIR", tree.Path("tree/gonedir"))
	_, err := DiffArchive(DiffConfig{Archive: archivePath, BaseDir: tree.Root, Extract: true})
	if !errors.Is(err, ErrScratchInTree) {
		t.Errorf("$TMPDIR in the tree: %v, want ErrScratchInTree", err)
	}
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	if _, err := DiffArchive(DiffConfig{Archive: archivePath, BaseDir: tree.Root, Extract: true}); err != nil {
		t.Fatal(err)
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Errorf("left behind in $TMPDIR: %v", left)
	}
}

// As root, a copy gets the owner and device nodes are made: each is
// compared. The CI job as root runs this test.
func TestDiffExtractAsRoot(t *testing.T) {
	if !meta.IsRoot() {
		t.Skip("needs root")
	}
	t.Run("owner", func(t *testing.T) {
		tree := diffFixture(t)
		if err := os.Chown(tree.Path("tree/same.txt"), 1234, 1234); err != nil {
			t.Fatal(err)
		}
		archivePath := diffArchive(t, tree, "tree/same.txt")
		if res, err := diffExtract(t, archivePath, tree.Root, DiffConfig{}); err != nil || len(res.Differences) != 0 {
			t.Fatalf("unchanged: %q, %v", foundX(res), err)
		}
		twistScratch(t, "owner")
		res, err := diffExtract(t, archivePath, tree.Root, DiffConfig{})
		if got, want := foundX(res), []string{"tree/same.txt owner extracted"}; err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("a wrong owner: %q, %v; want %q", got, err, want)
		}
		if res, err := diffExtract(t, archivePath, tree.Root, DiffConfig{Metadata: MetadataOptions{NoOwner: true}}); err != nil ||
			len(res.Differences) != 0 {
			t.Errorf("--no-owner: %q, %v", foundX(res), err)
		}
	})
	t.Run("device", func(t *testing.T) {
		if fi, err := os.Lstat("/dev/null"); err != nil || fi.Mode()&fs.ModeCharDevice == 0 {
			t.Skip("no /dev/null")
		}
		archivePath := filepath.Join(t.TempDir(), "dev.ect")
		if _, err := CreateArchive(CreateConfig{Archive: archivePath, Paths: []string{"null"}, BaseDir: "/dev"}); err != nil {
			t.Fatal(err)
		}
		if res, err := diffExtract(t, archivePath, "/dev", DiffConfig{}); err != nil || len(res.Differences) != 0 {
			t.Fatalf("the same device: %q, %v", foundX(res), err)
		}
		saved := mknod
		t.Cleanup(func() { mknod = saved })
		mknod = func(dir *os.File, name string, char bool, mode, major, minor uint32) error {
			return saved(dir, name, char, mode, major, minor+1)
		}
		res, err := diffExtract(t, archivePath, "/dev", DiffConfig{})
		if got, want := foundX(res), []string{"null device extracted"}; err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("other numbers: %q, %v; want %q", got, err, want)
		}
	})
}

// TestDiffExtractSourceFaultsAreNeverSilent makes each operation on the
// tree fail in turn, as the tests of --diff do: the reads of the
// comparison, of a dense and of a sparse file, and the reads of the
// attributes of each copy. Each fault fails the run with that fault.
func TestDiffExtractSourceFaultsAreNeverSilent(t *testing.T) {
	tree := diffFixture(t)
	tree.Sparse("tree/holes", 0o644, 1<<20, testutil.Segment{Offset: 1 << 19, Data: []byte("data in the middle")})
	settle(tree)
	archivePath := diffArchive(t, tree, "tree")

	run := func(ff *faultFS) error {
		t.Helper()
		var open openSet
		err := withSrc(ff, &open, func() error {
			_, err := diffExtract(t, archivePath, tree.Root, DiffConfig{Workers: 2})
			return err
		})
		for _, what := range open.m {
			t.Errorf("fault %s: %s stays open", cmp.Or(ff.failed, "none"), what)
		}
		return err
	}
	count := &faultFS{}
	if err := run(count); err != nil {
		t.Fatalf("with no fault: %v", err)
	}
	t.Logf("%d operations", count.n)
	check := func(ff *faultFS) {
		t.Helper()
		err := run(ff)
		switch {
		case ff.failed == "" || ff.harmless:
		case err == nil:
			t.Errorf("fault %s: the run reported success", ff.failed)
		case !errors.Is(err, syscall.EIO):
			t.Errorf("fault %s: the error is not the fault: %v", ff.failed, err)
		}
	}
	for k := 1; k <= count.n; k++ {
		check(&faultFS{failAt: k})
	}
	// The first operation of each kind, which is the same one in each run.
	for _, op := range []string{"open", "openroot", "lstat", "stat", "readlink", "evalsymlinks",
		"read", "readdir", "close", "holes", "xattrs"} {
		check(&faultFS{failIf: func(o, _ string) bool { return o == op }})
	}
}

// Where the platform cannot set the time of a link, the time of a copy of
// a link is not compared. That of a file still is.
func TestDiffExtractWithoutTimesOfLinks(t *testing.T) {
	tree := diffFixture(t)
	archivePath := diffArchive(t, tree, "tree/link", "tree/same.txt")
	saved := setLinkTimes
	t.Cleanup(func() { setLinkTimes = saved })
	setLinkTimes = func(*os.File, string, int64, int64) error { return meta.ErrUnsupported }
	twistScratch(t, "time")

	res, err := diffExtract(t, archivePath, tree.Root, DiffConfig{})
	if got, want := foundX(res), []string{"tree/same.txt mtime extracted"}; err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("%q, %v; want %q", got, err, want)
	}
}

// An attribute of a copy with another value is a difference, as is one
// that the copy lacks.
func TestDiffExtractOfAnAttributeWithAnotherValue(t *testing.T) {
	tree := mutTree(t)
	path := copyArchive(t, mkArchive(t, tree, false, "t/a.txt"))
	recorded := map[string][]byte{"user.a": []byte("1")}
	forgeIndex(t, path, nil, func(ix *format.Index) { ix.Members[0].Xattrs = recorded })
	ff, sx := readXattrsFile, setXattr
	t.Cleanup(func() { readXattrsFile, setXattr = ff, sx })
	readXattrsFile = func(f *os.File, _ string) (map[string][]byte, error) {
		if strings.HasSuffix(f.Name(), "a.txt") {
			return recorded, nil
		}
		return map[string][]byte{"user.a": []byte("2")}, nil
	}
	setXattr = func(*os.File, string, []byte) error { return nil }

	res, err := diffExtract(t, path, tree.Root, DiffConfig{})
	if got, want := foundX(res), []string{"t/a.txt xattrs extracted"}; err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("%q, %v; want %q", got, err, want)
	}
}

// The lines of one path are in the order of their kinds, wherever they came
// from: a change of mode on disk, and a wrong byte in the copy.
func TestDiffExtractSortsTheKindsOfAPath(t *testing.T) {
	tree := diffFixture(t)
	archivePath := diffArchive(t, tree, "tree/same.txt")
	tree.Chmod("tree/same.txt", 0o600)
	settle(tree)
	twistScratch(t, "byte")
	res, err := diffExtract(t, archivePath, tree.Root, DiffConfig{})
	if got, want := foundX(res), []string{"tree/same.txt content extracted", "tree/same.txt mode"}; err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("%q, %v; want %q", got, err, want)
	}
}

// The workers of --diff-extract decode, so the memory bound of extraction
// limits them. That of --diff does not.
func TestDiffExtractWorkers(t *testing.T) {
	tree := diffFixture(t)
	archivePath := diffArchive(t, tree, "tree") // chunks of 4 KiB
	r, err := OpenWith(archivePath, OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	d := &differ{cfg: DiffConfig{Workers: 8, MemoryLimit: 3 * 2 * 4096}, r: r,
		want: map[string]*format.Member{}, byID: map[uint64]*format.Member{}}
	for i := range r.index.Members {
		m := &r.index.Members[i]
		d.want[m.Path], d.byID[m.ID] = m, m
	}
	if got := d.workers(); got != 8 {
		t.Errorf("--diff: %d workers, want 8", got)
	}
	d.scratch = &scratch{}
	if got := d.workers(); got != 3 {
		t.Errorf("--diff-extract: %d workers, want the 3 that the memory allows", got)
	}
}

// The meter advances by the size of each member, as for --diff.
func TestDiffExtractProgress(t *testing.T) {
	tree := diffFixture(t)
	archivePath := diffArchive(t, tree, "tree")
	p := &progressRecorder{}
	if _, err := diffExtract(t, archivePath, tree.Root, DiffConfig{Reporter: p}); err != nil {
		t.Fatal(err)
	}
	if p.total == 0 || p.advanced != p.total {
		t.Errorf("advanced %d of %d", p.advanced, p.total)
	}
}
