package archive

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/philmalin/eictar/src/internal/format"
	"github.com/philmalin/eictar/src/internal/fsutil"
	"github.com/philmalin/eictar/src/internal/meta"
	"github.com/philmalin/eictar/src/internal/testutil"
)

// Tests of the parts of extraction that the fault tests do not reach.

// TestApplyOwner: the owner is set only with --preserve-owner, and only when
// the archive recorded both ids. An error of chown is the member's error.
func TestApplyOwner(t *testing.T) {
	uid, gid := uint32(4242), uint32(4343)
	errDenied := errors.New("denied")
	for _, tc := range []struct {
		name     string
		owner    bool
		uid, gid *uint32
		fail     error
		want     string // the call, or "" for none
	}{
		{"asked and recorded", true, &uid, &gid, nil, "4242:4343"},
		{"not asked", false, &uid, &gid, nil, ""},
		{"no uid", true, nil, &gid, nil, ""},
		{"no gid", true, &uid, nil, nil, ""},
		{"chown fails", true, &uid, &gid, errDenied, "4242:4343"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := &extraction{cfg: ExtractConfig{Restore: RestoreOptions{Owner: tc.owner}}, names: meta.NewNames()}
			var called string
			err := x.applyOwner(&format.Member{Path: "f", UID: tc.uid, GID: tc.gid}, func(u, g int) error {
				called = fmt.Sprintf("%d:%d", u, g)
				return tc.fail
			})
			if called != tc.want {
				t.Errorf("chown called with %q, want %q", called, tc.want)
			}
			if !errors.Is(err, tc.fail) || (tc.fail == nil) != (err == nil) {
				t.Errorf("applyOwner = %v, want %v", err, tc.fail)
			}
		})
	}
}

// TestAccessTime: the recorded access time, or the modification time when
// the archive recorded none.
func TestAccessTime(t *testing.T) {
	x := &extraction{}
	if got := x.atime(&format.Member{MTimeNanos: 5, ATimeNanos: 7}); got != 7 {
		t.Errorf("recorded: %d, want 7", got)
	}
	if got := x.atime(&format.Member{MTimeNanos: 5}); got != 5 {
		t.Errorf("not recorded: %d, want the modification time, 5", got)
	}
}

// TestRefusedXattrsAreReported: the extended attributes that the destination
// does not take, and the ACLs that only -p restores, are each reported in
// one notice, with their counts (doc/design.md 7.7).
func TestRefusedXattrsAreReported(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the names that the destination refuses here are those that Linux does not know")
	}
	if meta.IsRoot() {
		t.Skip("root restores ACLs without -p")
	}
	path := copyArchive(t, mkArchive(t, mutTree(t), false, "t"))
	forgeIndex(t, path, nil, func(ix *format.Index) {
		for i := range ix.Members {
			m := &ix.Members[i]
			switch m.Path {
			case "t/a.txt":
				m.Xattrs = map[string][]byte{"system.posix_acl_access": []byte("1")}
				for _, c := range "abcdefghij" {
					m.Xattrs["com.apple."+string(c)] = []byte("1")
				}
			case "t/b.txt":
				m.Xattrs = map[string][]byte{"com.apple.a": []byte("1")}
			}
		}
	})
	rep := &recordingReporter{}
	if _, err := Extract(ExtractConfig{Archive: path, Destination: t.TempDir(), Reporter: rep}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"1 ACLs or privileged extended attributes were not restored; -p restores them",
		"the destination did not take 11 extended attributes (10 names): com.apple.a, com.apple.b, com.apple.c, " +
			"com.apple.d, com.apple.e, com.apple.f, com.apple.g, com.apple.h, and 2 more",
	}
	if !slices.Equal(rep.warnings, want) {
		t.Errorf("warnings:\n%s\nwant:\n%s", strings.Join(rep.warnings, "\n"), strings.Join(want, "\n"))
	}
}

// TestDirectoriesAreFinishedDeepestFirst: a directory gets its mode after
// the directories in it got theirs. A mode with no search bit, given first,
// would shut the extraction out of the directories below.
func TestDirectoriesAreFinishedDeepestFirst(t *testing.T) {
	if runtime.GOOS == "windows" || meta.IsRoot() {
		t.Skip("needs a mode that shuts a user out of a directory")
	}
	tree := mutTree(t)
	tree.Dir("t/sub/inner", 0o755)
	path := copyArchive(t, mkArchive(t, tree, false, "t"))
	forgeIndex(t, path, nil, func(ix *format.Index) {
		for i := range ix.Members {
			if ix.Members[i].Path == "t/sub" {
				ix.Members[i].Mode = 0o600
			}
		}
	})
	dest := t.TempDir()
	t.Cleanup(func() { os.Chmod(filepath.Join(dest, "t", "sub"), 0o700) })
	if _, err := Extract(ExtractConfig{Archive: path, Destination: dest, Restore: RestoreOptions{Permissions: true}}); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if fi := mustStat(t, filepath.Join(dest, "t", "sub")); fi.Mode().Perm() != 0o600 {
		t.Errorf("t/sub has mode %04o, want 0600", fi.Mode().Perm())
	}
}

// TestLongFileName: the temporary name of a file of 250 bytes is cut to
// what a file system takes.
func TestLongFileName(t *testing.T) {
	long := "t/" + strings.Repeat("n", 250)
	tree := mutTree(t)
	tree.Text(long, 0o644, "a long name")
	dest := t.TempDir()
	if _, err := Extract(ExtractConfig{Archive: mkArchive(t, tree, false, "t"), Destination: dest}); err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, filepath.Join(dest, filepath.FromSlash(long))); string(got) != "a long name" {
		t.Errorf("content %q", got)
	}
}

// sparseArchive makes an archive of one file of 64 KiB with three data
// segments and a hole at its end, in chunks of 3000 bytes. The chunks do not
// fall on the segments, so a write of a chunk starts in the middle of a
// segment and crosses into the next one.
func sparseArchive(t *testing.T) (archive string, want []byte) {
	t.Helper()
	tree := testutil.NewTree(t)
	block := func(c byte) []byte { return bytes.Repeat([]byte{c}, 4096) }
	tree.Sparse("s", 0o644, 64<<10,
		testutil.Segment{Offset: 0, Data: block('a')},
		testutil.Segment{Offset: 16 << 10, Data: block('b')},
		testutil.Segment{Offset: 20 << 10, Data: block('c')})
	want = readAll(t, tree.Path("s"))
	archive = filepath.Join(t.TempDir(), "s.ect")
	if _, err := CreateArchive(CreateConfig{Archive: archive, Paths: []string{"s"}, BaseDir: tree.Root,
		Options: Options{Codec: "zstd", ChunkSize: 3000}}); err != nil {
		t.Fatal(err)
	}
	return archive, want
}

// TestSparseFileAcrossChunks: a file with holes, in chunks that do not fall
// on its segments, is the same after an extraction to disk and to stdout.
func TestSparseFileAcrossChunks(t *testing.T) {
	archive, want := sparseArchive(t)
	dest := t.TempDir()
	if _, err := Extract(ExtractConfig{Archive: archive, Destination: dest}); err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, filepath.Join(dest, "s")); !bytes.Equal(got, want) {
		t.Error("the file extracted to disk differs")
	}
	var out bytes.Buffer
	if _, err := Extract(ExtractConfig{Archive: archive, ToStdout: &out}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), want) {
		t.Errorf("the file extracted to stdout differs: %d bytes, want %d", out.Len(), len(want))
	}
}

// failingWriter fails the one write that would take it past n bytes, and
// takes the writes after it: a write that fails once, as on a pipe that
// the reader closed and opened again, must still fail the extraction.
type failingWriter struct {
	n      int
	failed bool
}

var errStdout = errors.New("stdout is closed")

func (w *failingWriter) Write(p []byte) (int, error) {
	if !w.failed && len(p) > w.n {
		w.failed = true
		return w.n, errStdout
	}
	w.n -= len(p)
	return len(p), nil
}

// TestStdoutWriteFails: a write to stdout that fails is the extraction's
// error, wherever it falls: in data, or in a hole.
func TestStdoutWriteFails(t *testing.T) {
	archive, want := sparseArchive(t)
	for _, n := range []int{0, 100, 5000, 8 << 10, 30 << 10, len(want) - 1} {
		if _, err := Extract(ExtractConfig{Archive: archive, ToStdout: &failingWriter{n: n}}); !errors.Is(err, errStdout) {
			t.Errorf("stdout fails after %d bytes: %v", n, err)
		}
	}
}

// memberRecorder records the members that a run reports, and its warnings.
type memberRecorder struct {
	recordingReporter
	members []string
}

func (r *memberRecorder) Member(m *format.Member) { r.members = append(r.members, m.Path) }

// TestExtractToStdout: each member with content goes to stdout, in order; a
// hardlink gives its target's content; a member with no content gives none.
// A damaged member fails, and with --keep-going the others still go out. The
// counts are those of the members written.
func TestExtractToStdout(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Dir("d", 0o755)
	tree.Text("d/a", 0o644, "alpha.")
	tree.Text("d/b", 0o644, "bravo.")
	tree.Hardlink("d/c", "d/a")
	tree.Symlink("d/l", "a")
	path := copyArchive(t, mkArchive(t, tree, false, "d"))

	var out bytes.Buffer
	rep := &memberRecorder{}
	stats, err := Extract(ExtractConfig{Archive: path, ToStdout: &out, Reporter: rep})
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != "alpha.bravo.alpha." {
		t.Errorf("stdout %q, want the contents of a, b and the hardlink c", out.String())
	}
	if stats.Members != 3 || stats.Bytes != 18 || !slices.Equal(rep.members, []string{"d/a", "d/b", "d/c"}) {
		t.Errorf("%d members, %d bytes, reported %v; want 3, 18, [d/a d/b d/c]", stats.Members, stats.Bytes, rep.members)
	}

	// Damage b.
	r, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	var off int64
	for _, m := range r.index.Members {
		if m.Path == "d/b" {
			off = int64(m.Offset)
		}
	}
	r.Close()
	b := readAll(t, path)
	b[off] ^= 0xff
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	if _, err := Extract(ExtractConfig{Archive: path, ToStdout: &out}); !IsDamage(err) {
		t.Errorf("a damaged member: %v, want damage", err)
	}
	out.Reset()
	rep = &memberRecorder{}
	stats, err = Extract(ExtractConfig{Archive: path, ToStdout: &out, KeepGoing: true, Reporter: rep})
	if err != nil {
		t.Fatalf("with --keep-going: %v", err)
	}
	if !strings.HasPrefix(out.String(), "alpha.") || !strings.HasSuffix(out.String(), "alpha.") ||
		stats.Members != 2 || stats.Failed != 1 || len(rep.warnings) != 1 {
		t.Errorf("with --keep-going: stdout %q, %d members, %d failed, warnings %v", out.String(), stats.Members, stats.Failed, rep.warnings)
	}
}

// progressRecorder is a Reporter with a meter.
type progressRecorder struct {
	recordingReporter
	mu       sync.Mutex
	total    int64
	advanced int64
}

func (p *progressRecorder) Total(n int64) { p.total = n }
func (p *progressRecorder) Advance(n int64) {
	p.mu.Lock()
	p.advanced += n
	p.mu.Unlock()
}

// TestExtractProgress: the meter gets the total of the content first, and
// then advances by all of it.
func TestExtractProgress(t *testing.T) {
	tree := mutTree(t)
	tree.Text("t/big.txt", 0o644, strings.Repeat("several chunks of text. ", 2000))
	archive := mkArchive(t, tree, false, "t")
	p := &progressRecorder{}
	if _, err := Extract(ExtractConfig{Archive: archive, Destination: t.TempDir(), Reporter: p}); err != nil {
		t.Fatal(err)
	}
	want := int64(len("alpha") + len("bravo") + len("charlie") + 48000)
	if p.total != want || p.advanced != want {
		t.Errorf("total %d, advanced %d; want %d each", p.total, p.advanced, want)
	}
}

// TestExtractDestination: no destination is the current directory. A
// destination that cannot be made, or opened, is the error.
func TestExtractDestination(t *testing.T) {
	archive := mkArchive(t, mutTree(t), false, "t")
	cwd := t.TempDir()
	t.Chdir(cwd)
	if _, err := Extract(ExtractConfig{Archive: archive}); err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, filepath.Join(cwd, "t", "a.txt")); string(got) != "alpha" {
		t.Errorf("t/a.txt in the current directory holds %q", got)
	}

	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Extract(ExtractConfig{Archive: archive, Destination: filepath.Join(file, "below")}); err == nil || !strings.Contains(err.Error(), "creating") {
		t.Errorf("a destination below a file: %v, want the error of creating it", err)
	}

	errOpen := errors.New("cannot open")
	saved := openDest
	t.Cleanup(func() { openDest = saved })
	openDest = func(string) (destDir, error) { return nil, errOpen }
	if _, err := Extract(ExtractConfig{Archive: archive, Destination: t.TempDir()}); !errors.Is(err, errOpen) {
		t.Errorf("a destination that does not open: %v, want %v", err, errOpen)
	}
}

// TestRefusedNamesListed: the notice lists eight names, and counts the rest.
func TestRefusedNamesListed(t *testing.T) {
	for _, n := range []int{8, 9} {
		rep := &recordingReporter{}
		x := &extraction{cfg: ExtractConfig{Reporter: rep}, refused: map[string]int{}}
		for i := range n {
			x.refused[fmt.Sprintf("n%d", i)] = 1
		}
		x.reportRefused()
		more := strings.Contains(strings.Join(rep.warnings, ""), "more")
		if len(rep.warnings) != 1 || more != (n > 8) {
			t.Errorf("%d names: %q", n, rep.warnings)
		}
	}
}

// TestExtractStopsAtTheFirstFailure: without --keep-going, a member that
// fails stops the extraction: the members after it are not written.
func TestExtractStopsAtTheFirstFailure(t *testing.T) {
	tree := testutil.NewTree(t)
	for _, c := range "abcd" {
		tree.Text("d/"+string(c), 0o644, strings.Repeat(string(c), 100))
	}
	path := copyArchive(t, mkArchive(t, tree, false, "d"))
	r, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	var off int64
	for _, m := range r.index.Members {
		if m.Path == "d/a" {
			off = int64(m.Offset)
		}
	}
	r.Close()
	b := readAll(t, path)
	b[off] ^= 0xff
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	if _, err := Extract(ExtractConfig{Archive: path, Destination: dest, Workers: 1}); !IsDamage(err) {
		t.Fatalf("Extract = %v, want damage", err)
	}
	for _, c := range "bcd" {
		if _, err := os.Lstat(filepath.Join(dest, "d", string(c))); err == nil {
			t.Errorf("d/%c was written after d/a failed", c)
		}
	}
}

// TestUnsafePathsOfNodes: the index checks do not check paths (doc/format.md
// 8.6), so extraction refuses a member with a path that is not in stored
// form: a directory, a link and a hardlink as well as a file (§9.1). A path
// such as t/./x stays inside the destination, so only this check stops it.
func TestUnsafePathsOfNodes(t *testing.T) {
	tree := mutTree(t)
	tree.Symlink("t/sym", "a.txt")
	tree.Hardlink("t/hard", "t/a.txt")
	archive := mkArchive(t, tree, false, "t")
	for _, name := range []string{"t/sub", "t/sym", "t/hard"} {
		for _, bad := range []string{"t/./x", "t/../../x"} {
			path := copyArchive(t, archive)
			forgeIndex(t, path, nil, func(ix *format.Index) {
				for i := range ix.Members {
					if ix.Members[i].Path == name {
						ix.Members[i].Path = bad
					}
				}
			})
			dest := t.TempDir()
			if _, err := Extract(ExtractConfig{Archive: path, Destination: filepath.Join(dest, "d")}); !errors.Is(err, fsutil.ErrUnsafePath) {
				t.Errorf("%s as %s: %v, want %v", name, bad, err, fsutil.ErrUnsafePath)
			}
			if _, err := os.Lstat(filepath.Join(dest, "d", "t", "x")); err == nil {
				t.Errorf("%s as %s: t/x was made", name, bad)
			}
		}
	}
}

// TestSamePathKeepsIndexOrder: two live members with one path come only from
// a forged index. They are written in index order, so the later one is what
// stays, on every run.
func TestSamePathKeepsIndexOrder(t *testing.T) {
	path := copyArchive(t, mkArchive(t, mutTree(t), false, "t"))
	forgeIndex(t, path, nil, func(ix *format.Index) {
		for i := range ix.Members {
			if ix.Members[i].Path == "t/b.txt" {
				ix.Members[i].Path = "t/a.txt"
			}
		}
	})
	dest := t.TempDir()
	if _, err := Extract(ExtractConfig{Archive: path, Destination: dest, Workers: 1}); err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, filepath.Join(dest, "t", "a.txt")); string(got) != "bravo" {
		t.Errorf("t/a.txt holds %q, want the later member's bravo", got)
	}
}
