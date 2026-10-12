package archive

import (
	"bytes"
	"errors"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/philmalin/eictar/src/internal/format"
	"github.com/philmalin/eictar/src/internal/meta"
	"github.com/philmalin/eictar/src/internal/testutil"
)

// Tests of the walk and of the capture of each entry (walk.go, capture.go)
// for what the tests of create do not reach.

// TestClassify: each kind of file has its kind of member.
func TestClassify(t *testing.T) {
	for _, tc := range []struct {
		mode fs.FileMode
		want entryKind
	}{
		{fs.ModeDir | 0o755, kindDir},
		{0o644, kindFile},
		{fs.ModeSymlink | 0o777, kindSymlink},
		{fs.ModeNamedPipe | 0o644, kindFIFO},
		{fs.ModeSocket | 0o755, kindSocket},
		{fs.ModeDevice | fs.ModeCharDevice | 0o666, kindCharDev},
		{fs.ModeDevice | 0o660, kindBlockDev},
		{fs.ModeIrregular, kindUnsupported},
	} {
		if got := classify(tc.mode); got != tc.want {
			t.Errorf("classify(%v) = %d, want %d", tc.mode, got, tc.want)
		}
	}
}

// TestStorable: a link with an empty target cannot be stored, and a socket
// is skipped with a notice.
func TestStorable(t *testing.T) {
	if err := storable(entry{Kind: kindSymlink, Stored: "l"}); err == nil || !strings.Contains(err.Error(), "empty target") {
		t.Errorf("a link with no target: %v", err)
	}
	var skipped *errSkipped
	if err := storable(entry{Kind: kindSocket, Src: "s"}); !errors.As(err, &skipped) {
		t.Errorf("a socket: %v, want a notice", err)
	}
}

// TestCharacterDevice: a character device is stored as one, with its
// device number. /dev/null is one on each Unix.
func TestCharacterDevice(t *testing.T) {
	if fi, err := os.Lstat("/dev/null"); err != nil || fi.Mode()&fs.ModeCharDevice == 0 {
		t.Skip("no /dev/null")
	}
	path := filepath.Join(t.TempDir(), "x.ect")
	if _, err := CreateArchive(CreateConfig{Archive: path, Paths: []string{"null"}, BaseDir: "/dev"}); err != nil {
		t.Fatal(err)
	}
	r, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	m := r.index.Members[0]
	if m.Type != format.TypeCharDev || len(m.RDev) != 2 {
		t.Errorf("/dev/null is a %s with device %v, want a character device", m.Type, m.RDev)
	}
}

// TestOutside: the parts of a data region that no stored segment covers.
func TestOutside(t *testing.T) {
	segs := []format.SparseSegment{{Offset: 10, Length: 20}, {Offset: 50, Length: 10}}
	for _, tc := range []struct {
		c    meta.Segment
		want []meta.Segment
	}{
		{meta.Segment{Offset: 0, Length: 100}, []meta.Segment{{Offset: 0, Length: 10}, {Offset: 30, Length: 20}, {Offset: 60, Length: 40}}},
		{meta.Segment{Offset: 10, Length: 20}, nil},                                      // a segment, exactly
		{meta.Segment{Offset: 30, Length: 20}, []meta.Segment{{Offset: 30, Length: 20}}}, // between two: they touch it
		{meta.Segment{Offset: 20, Length: 40}, []meta.Segment{{Offset: 30, Length: 20}}},
		{meta.Segment{Offset: 55, Length: 5}, nil}, // up to the end of a segment
	} {
		if got := outside(tc.c, segs); !slices.Equal(got, tc.want) {
			t.Errorf("outside(%v) = %v, want %v", tc.c, got, tc.want)
		}
	}
}

// TestAllZero: zeros to the end, a byte that is not, and a read that fails.
func TestAllZero(t *testing.T) {
	zeros := make([]byte, 200<<10)
	if ok, err := allZero(bytes.NewReader(zeros)); !ok || err != nil {
		t.Errorf("zeros: %v, %v", ok, err)
	}
	some := slices.Clone(zeros)
	some[150<<10] = 1
	if ok, err := allZero(bytes.NewReader(some)); ok || err != nil {
		t.Errorf("a byte that is not zero: %v, %v", ok, err)
	}
	errRead := errors.New("read failed")
	if _, err := allZero(io.MultiReader(bytes.NewReader(zeros[:10]), iotest.ErrReader(errRead))); !errors.Is(err, errRead) {
		t.Errorf("a read that fails: %v", err)
	}
}

// withXattrs makes readXattrsFile and readXattrsPath give xattrs, and counts
// the calls of each.
func withXattrs(t *testing.T, xattrs map[string][]byte) (fromFile, fromPath *int) {
	t.Helper()
	ff, fp := readXattrsFile, readXattrsPath
	t.Cleanup(func() { readXattrsFile, readXattrsPath = ff, fp })
	fromFile, fromPath = new(int), new(int)
	readXattrsFile = func(*os.File, string) (map[string][]byte, error) { *fromFile++; return xattrs, nil }
	readXattrsPath = func(string, bool) (map[string][]byte, error) { *fromPath++; return xattrs, nil }
	return fromFile, fromPath
}

// TestReadXattrsLimits: an attribute larger than the format allows is left
// out, and reported; one at the limit is kept.
func TestReadXattrsLimits(t *testing.T) {
	long := "user." + strings.Repeat("n", format.MaxXattrName-len("user."))
	withXattrs(t, map[string][]byte{
		long:                 []byte("1"),
		long + "x":           []byte("1"),
		"user.full":          make([]byte, format.MaxXattrValue),
		"user.over":          make([]byte, format.MaxXattrValue+1),
		"system.posix_acl_a": []byte("1"),
	})
	var tooLarge []string
	got, err := readXattrs(entry{}, osSrcFile{}, MetadataOptions{}, func(name string, _ int) { tooLarge = append(tooLarge, name) })
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(tooLarge)
	if want := []string{long + "x", "user.over"}; !slices.Equal(tooLarge, want) {
		t.Errorf("too large: %q, want %q", tooLarge, want)
	}
	if _, ok := got[long]; !ok || len(got["user.full"]) != format.MaxXattrValue || len(got) != 3 {
		t.Errorf("kept %d attributes, want the name and the value at the limit, and the plain name", len(got))
	}
	if _, err := readXattrs(entry{}, osSrcFile{}, MetadataOptions{}, nil); err != nil {
		t.Errorf("with no report: %v", err)
	}

	// The capture reports one as a warning.
	var warnings []string
	c := &capturer{warn: func(f string, args ...any) { warnings = append(warnings, f) }}
	var m format.Member
	if err := c.recordXattrs(&m, entry{}, osSrcFile{}); err != nil || len(warnings) != 2 {
		t.Errorf("recordXattrs: %v, %d warnings, want 2", err, len(warnings))
	}
}

// TestReadXattrsOptions: --no-xattrs and --no-acls each leave out their
// part, and both read nothing. An entry with no open file is read by its
// path.
func TestReadXattrsOptions(t *testing.T) {
	fromFile, fromPath := withXattrs(t, map[string][]byte{
		"user.a":                  []byte("1"),
		"system.posix_acl_access": []byte("2"),
	})
	for _, tc := range []struct {
		opt  MetadataOptions
		want []string
	}{
		{MetadataOptions{}, []string{"system.posix_acl_access", "user.a"}},
		{MetadataOptions{NoXattrs: true}, []string{"system.posix_acl_access"}},
		{MetadataOptions{NoACLs: true}, []string{"user.a"}},
		{MetadataOptions{NoXattrs: true, NoACLs: true}, nil},
	} {
		*fromFile = 0
		got, err := readXattrs(entry{}, osSrcFile{}, tc.opt, nil)
		names := slices.Sorted(func(yield func(string) bool) {
			for n := range got {
				if !yield(n) {
					return
				}
			}
		})
		if err != nil || !slices.Equal(names, tc.want) {
			t.Errorf("%+v: %v, %v; want %v", tc.opt, names, err, tc.want)
		}
		if read := *fromFile > 0; read != (tc.want != nil) {
			t.Errorf("%+v: read %v", tc.opt, read)
		}
	}
	if _, err := readXattrs(entry{Src: "p"}, nil, MetadataOptions{}, nil); err != nil || *fromPath != 1 {
		t.Errorf("by the path: %v, %d reads by the path", err, *fromPath)
	}
}

// TestOpenWalkedDoesNotBlockOnAPipe: a file that became a pipe after the
// walk found it is refused, not opened: the open of a pipe with no writer
// waits for one, for ever.
func TestOpenWalkedDoesNotBlockOnAPipe(t *testing.T) {
	if !pipesExtracted(t) {
		t.Skip("no pipes made through a directory on this platform")
	}
	tree := testutil.NewTree(t)
	tree.Text("f", 0o644, "a file")
	root, err := os.OpenRoot(tree.Root)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	fi, err := root.Lstat("f")
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(tree.Path("f"))
	tree.Fifo("f", 0o644)

	done := make(chan error, 1)
	go func() {
		f, err := openWalked(entry{Src: tree.Path("f"), Kind: kindFile, Info: fi, dir: osSrc{root}, name: "f"})
		if f != nil {
			f.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, errChangedDuringWalk) {
			t.Errorf("openWalked = %v, want %v", err, errChangedDuringWalk)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the open of the pipe waits for a writer")
	}
}

// sparseFile writes a file of 1 MiB with data at its first 4 KiB only.
func sparseFile(t *testing.T, tree *testutil.Tree, rel string) {
	t.Helper()
	tree.Sparse(rel, 0o644, 1<<20, testutil.Segment{Offset: 0, Data: bytes.Repeat([]byte("d"), 4096)})
}

// TestUpdateDigestOfASparseFile: -u --update-mode=digest finds a file with
// holes unchanged when its data is, and changed when bytes that were a hole
// are not zero now, even when the file has no holes left.
func TestUpdateDigestOfASparseFile(t *testing.T) {
	tree := testutil.NewTree(t)
	sparseFile(t, tree, "s")
	if !tree.Holes("s") {
		t.Skip("this file system stores the file dense")
	}
	archive := mkArchive(t, tree, false, "s")
	update := func() Stats {
		t.Helper()
		stats, err := appendTo(t, archive, tree, false, func(c *AppendConfig) { c.UpdateMode = UpdateDigest }, "s")
		if err != nil {
			t.Fatal(err)
		}
		return stats
	}
	if s := update(); s.Unchanged != 1 {
		t.Errorf("the file as it was: %+v, want unchanged", s)
	}
	// Dense now, with the same data region, and one byte where a hole was.
	dense := make([]byte, 1<<20)
	copy(dense, bytes.Repeat([]byte("d"), 4096))
	dense[1<<19] = 1
	if err := os.WriteFile(tree.Path("s"), dense, 0o644); err != nil {
		t.Fatal(err)
	}
	if s := update(); s.Unchanged != 0 || s.Members != 1 {
		t.Errorf("a byte in a hole: %+v, want the file archived again", s)
	}
}

// TestUpdateFindsAChangeOfTypeOrTarget: -u in any mode finds a path that is
// now of another type, or a link to another target, out of date.
func TestUpdateFindsAChangeOfTypeOrTarget(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Text("d/x", 0o644, "a file")
	tree.Symlink("d/l", "x")
	archive := mkArchive(t, tree, false, "d")
	os.Remove(tree.Path("d/x"))
	tree.Dir("d/x", 0o755)
	os.Remove(tree.Path("d/l"))
	tree.Symlink("d/l", "y")
	// Old times, so that only the type and the target tell. The link gets
	// its own: os.Chtimes would set those of its target.
	old := time.Unix(1, 0)
	if err := os.Chtimes(tree.Path("d/x"), old, old); err != nil {
		t.Fatal(err)
	}
	tree.SetLinkTimes("d/l", old, old)
	stats, err := appendTo(t, archive, tree, false, func(c *AppendConfig) { c.UpdateMode = UpdateNewer }, "d/x", "d/l")
	if err != nil {
		t.Fatal(err)
	}
	if stats.Members != 2 {
		t.Errorf("%+v, want both archived again", stats)
	}
}

// TestHardlinkToSharedContent: the first name of a hardlink pair can share
// content that the archive holds. The second name is still a hardlink to
// it, not a second member with that content.
func TestHardlinkToSharedContent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the walk finds no identity of a file on Windows")
	}
	tree := testutil.NewTree(t)
	tree.Text("d/a.txt", 0o644, "the content")
	archive := mkArchive(t, tree, false, "d")
	tree.Text("d/c.txt", 0o644, "the content")
	tree.Hardlink("d/b-link", "d/c.txt") // walked first: b before c
	p := &progressRecorder{}
	if _, err := appendTo(t, archive, tree, false, func(c *AppendConfig) { c.Reporter = p }, "d/b-link", "d/c.txt"); err != nil {
		t.Fatal(err)
	}
	r, err := Open(archive, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	byPath := map[string]format.Member{}
	for _, m := range r.Members() {
		byPath[m.Path] = m
	}
	first, second := byPath["d/b-link"], byPath["d/c.txt"]
	if first.Data == 0 || second.Type != format.TypeHardlink || second.HardlinkTo != first.ID {
		t.Errorf("d/b-link shares %d; d/c.txt is a %s to %d; want a share and a hardlink to it", first.Data, second.Type, second.HardlinkTo)
	}
	if p.advanced != int64(len("the content")) {
		t.Errorf("the meter advanced by %d, want the content of the shared file", p.advanced)
	}
}

// readAtFails is a file whose reads past from fail.
type readAtFails struct {
	srcFile
	from int64
}

var errReadPast = errors.New("read failed")

func (f readAtFails) ReadAt(b []byte, off int64) (int, error) {
	if off+int64(len(b)) > f.from {
		return 0, errReadPast
	}
	return f.srcFile.ReadAt(b, off)
}

// TestSameContentReadError: the bytes outside the stored segments are read
// to check that they are zero. A read that fails there is the error, not an
// answer.
func TestSameContentReadError(t *testing.T) {
	tree := testutil.NewTree(t)
	sparseFile(t, tree, "s")
	if !tree.Holes("s") {
		t.Skip("this file system stores the file dense")
	}
	archive := mkArchive(t, tree, false, "s")
	r, err := Open(archive, nil)
	if err != nil {
		t.Fatal(err)
	}
	old := r.index.Members[0]
	r.Close()
	if len(old.Sparse) == 0 {
		t.Skip("this platform finds no holes in a file, and stores it dense")
	}
	// Dense now: the whole file is data, and the part past the stored
	// segment must be read.
	dense := make([]byte, 1<<20)
	copy(dense, bytes.Repeat([]byte("d"), 4096))
	if err := os.WriteFile(tree.Path("s"), dense, 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(tree.Path("s"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	e := entry{Src: tree.Path("s"), Info: fi, Sys: meta.StatPath(tree.Path("s"), fi)}
	newHash := func() hash.Hash { return newDigest(nil) }
	if same, err := sameContentOf(&old, osSrcFile{f}, e, newHash); err != nil || !same {
		t.Fatalf("the same content: %v, %v", same, err)
	}
	if _, err := sameContentOf(&old, readAtFails{osSrcFile{f}, 4096}, e, newHash); !errors.Is(err, errReadPast) {
		t.Errorf("a read that fails past the segment: %v, want %v", err, errReadPast)
	}
}
