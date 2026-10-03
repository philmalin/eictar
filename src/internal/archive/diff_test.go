//go:build unix

package archive

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/philmalin/eictar/src/internal/fsutil"
	"github.com/philmalin/eictar/src/internal/meta"
	"github.com/philmalin/eictar/src/internal/testutil"
)

var diffStamp = time.Unix(1_600_000_000, 0)

// diffFixture is a tree with one entry for each kind of difference, all with
// the same times, so that a change of one entry is the only difference.
func diffFixture(t *testing.T) *testutil.Tree {
	t.Helper()
	tree := testutil.NewTree(t)
	tree.Dir("tree", 0o755).Dir("tree/gonedir", 0o755)
	for _, name := range []string{"same.txt", "content.txt", "size.txt", "mode.txt", "mtime.txt",
		"type", "gone.txt", "gonedir/a", "gonedir/b", "dup1", "dup2"} {
		content := "content of " + name
		if strings.HasPrefix(name, "dup") {
			content = "the same content twice" // the second shares the first's blob
		}
		tree.Text("tree/"+name, 0o644, content)
	}
	tree.Hardlink("tree/hard", "tree/same.txt").Symlink("tree/link", "same.txt")
	settle(tree)
	return tree
}

// settle gives every entry of the tree the fixture's times.
func settle(tree *testutil.Tree) {
	filepath.Walk(tree.Root, func(p string, fi os.FileInfo, err error) error {
		if err != nil || p == tree.Root {
			return err
		}
		rel, _ := filepath.Rel(tree.Root, p)
		if fi.Mode()&os.ModeSymlink != 0 {
			tree.SetLinkTimes(rel, diffStamp, diffStamp)
		} else {
			tree.SetTimes(rel, diffStamp, diffStamp)
		}
		return nil
	})
}

func diffArchive(t *testing.T, tree *testutil.Tree, paths ...string) string {
	t.Helper()
	archivePath := filepath.Join(t.TempDir(), "a.ect")
	if _, err := CreateArchive(CreateConfig{
		Archive: archivePath, Paths: paths, BaseDir: tree.Root,
		Options: Options{Codec: "zstd", ChunkSize: 4096},
	}); err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}
	return archivePath
}

// found renders the differences as "path kind" lines, for comparison.
func found(res DiffResult) []string {
	var out []string
	for _, d := range res.Differences {
		out = append(out, d.Path+" "+d.Kind)
	}
	return out
}

func TestDiffOfAnUnchangedTree(t *testing.T) {
	tree := diffFixture(t)
	archivePath := diffArchive(t, tree, "tree")

	res, err := DiffArchive(DiffConfig{Archive: archivePath, BaseDir: tree.Root})
	if err != nil {
		t.Fatalf("DiffArchive: %v", err)
	}
	if len(res.Differences) != 0 {
		t.Errorf("an unchanged tree has differences: %v", found(res))
	}
	if res.Compared != 15 {
		t.Errorf("compared %d members, want 15", res.Compared)
	}
}

func TestDiffFindsEachKind(t *testing.T) {
	tree := diffFixture(t)
	archivePath := diffArchive(t, tree, "tree")

	tree.Text("tree/content.txt", 0o644, "content of content.tx!") // the same size
	tree.Text("tree/size.txt", 0o644, "longer content of size.txt")
	tree.Chmod("tree/mode.txt", 0o600)
	tree.SetTimes("tree/mtime.txt", diffStamp, diffStamp.Add(time.Hour))
	os.Remove(tree.Path("tree/link"))
	tree.Symlink("tree/link", "other")
	os.Remove(tree.Path("tree/type"))
	tree.Dir("tree/type", 0o755)
	os.Remove(tree.Path("tree/gone.txt"))
	os.RemoveAll(tree.Path("tree/gonedir"))
	os.Remove(tree.Path("tree/hard"))
	tree.Text("tree/hard", 0o644, "content of same.txt") // a copy, not a link
	tree.Text("tree/new.txt", 0o644, "new")
	tree.Text("tree/newdir/x", 0o644, "x").Text("tree/newdir/y", 0o644, "y")
	settle(tree)
	tree.SetTimes("tree/mtime.txt", diffStamp, diffStamp.Add(time.Hour))

	res, err := DiffArchive(DiffConfig{Archive: archivePath, BaseDir: tree.Root})
	if err != nil {
		t.Fatalf("DiffArchive: %v", err)
	}
	want := []string{
		"tree/content.txt content",
		"tree/gone.txt missing",
		"tree/gonedir missing", // its files are not reported one by one
		"tree/link link",
		"tree/mode.txt mode",
		"tree/mtime.txt mtime",
		"tree/new.txt extra",
		"tree/newdir extra", // nor are the files of a new directory
		// The walk found hard first, so same.txt is the hardlink member,
		// and hard is now a copy.
		"tree/same.txt hardlink",
		"tree/size.txt size",
		"tree/type type",
	}
	if got := found(res); !reflect.DeepEqual(got, want) {
		t.Errorf("differences:\n got %q\nwant %q", got, want)
	}
	if res.Paths != len(want) {
		t.Errorf("Paths = %d, want %d", res.Paths, len(want))
	}
}

// The workers read the files in any order; the result must not depend on it.
func TestDiffDoesNotDependOnWorkers(t *testing.T) {
	tree := diffFixture(t)
	archivePath := diffArchive(t, tree, "tree")
	tree.Text("tree/content.txt", 0o644, "content of content.tx!")
	tree.Text("tree/dup1", 0o644, "the same content twicE")
	settle(tree)

	var first []string
	for _, workers := range []int{1, 2, 8} {
		res, err := DiffArchive(DiffConfig{Archive: archivePath, BaseDir: tree.Root, Workers: workers})
		if err != nil {
			t.Fatalf("-j %d: %v", workers, err)
		}
		if workers == 1 {
			first = found(res)
			continue
		}
		if got := found(res); !reflect.DeepEqual(got, first) {
			t.Errorf("-j %d: %q, -j 1: %q", workers, got, first)
		}
	}
	if len(first) != 2 {
		t.Errorf("differences: %q, want the two files", first)
	}
}

func TestDiffWithPatterns(t *testing.T) {
	tree := diffFixture(t)
	archivePath := diffArchive(t, tree, "tree")
	tree.Text("tree/new.txt", 0o644, "new")
	tree.Text("tree/new.bin", 0o644, "new")
	tree.Text("tree/size.txt", 0o644, "longer content of size.txt")
	settle(tree)

	// A path on disk that the patterns do not select is not reported, and
	// a new path that they select is, wherever it is in the tree.
	res, err := DiffArchive(DiffConfig{Archive: archivePath, BaseDir: tree.Root, Patterns: []string{"*.txt"}})
	if err != nil {
		t.Fatalf("DiffArchive: %v", err)
	}
	want := []string{"tree/new.txt extra", "tree/size.txt size"}
	if got := found(res); !reflect.DeepEqual(got, want) {
		t.Errorf("*.txt: got %q, want %q", got, want)
	}

	// A pattern that selects no member is a mistake, as for -t and -x.
	_, err = DiffArchive(DiffConfig{Archive: archivePath, BaseDir: tree.Root, Patterns: []string{"tree/nonesuch"}})
	if !errors.Is(err, ErrNoMatch) {
		t.Errorf("an unmatched pattern: %v, want ErrNoMatch", err)
	}
}

func TestDiffWithExclude(t *testing.T) {
	tree := diffFixture(t)
	tree.Text("tree/cache/x", 0o644, "x")
	settle(tree)
	archivePath := filepath.Join(t.TempDir(), "a.ect")
	if _, err := CreateArchive(CreateConfig{
		Archive: archivePath, Paths: []string{"tree"}, BaseDir: tree.Root,
		Exclude: []string{"cache"}, Options: Options{Codec: "zstd", ChunkSize: 4096},
	}); err != nil {
		t.Fatal(err)
	}

	// Without the exclude of the create, the excluded directory is a path
	// that the archive does not have. With it, there is no difference.
	res, err := DiffArchive(DiffConfig{Archive: archivePath, BaseDir: tree.Root})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := found(res), []string{"tree/cache extra"}; !reflect.DeepEqual(got, want) {
		t.Errorf("without --exclude: %q, want %q", got, want)
	}
	res, err = DiffArchive(DiffConfig{Archive: archivePath, BaseDir: tree.Root, Exclude: []string{"cache"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Differences) != 0 {
		t.Errorf("with --exclude: %q", found(res))
	}
}

// A file archived alone is compared alone: the files beside it on disk are
// not in the archive, and they are not reported.
func TestDiffOfAFileArchivedAlone(t *testing.T) {
	tree := diffFixture(t)
	archivePath := diffArchive(t, tree, "tree/same.txt")

	res, err := DiffArchive(DiffConfig{Archive: archivePath, BaseDir: tree.Root})
	if err != nil {
		t.Fatalf("DiffArchive: %v", err)
	}
	if len(res.Differences) != 0 || res.Compared != 1 {
		t.Errorf("compared %d, differences %q; want 1 and none", res.Compared, found(res))
	}
}

// An archive made with -C dir . does not record ".", so it cannot tell that
// it holds the whole base directory. A new path at the top is not reported;
// a new path in an archived directory is (doc/design.md 9.8).
func TestDiffOfTheWholeBase(t *testing.T) {
	tree := diffFixture(t)
	archivePath := diffArchive(t, tree, ".")
	tree.Text("top.txt", 0o644, "new")
	tree.Text("tree/new.txt", 0o644, "new")
	settle(tree)

	res, err := DiffArchive(DiffConfig{Archive: archivePath, BaseDir: tree.Root})
	if err != nil {
		t.Fatalf("DiffArchive: %v", err)
	}
	if got, want := found(res), []string{"tree/new.txt extra"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// The archive is not a path that is missing from itself (doc/design.md 7.2).
func TestDiffSkipsTheArchive(t *testing.T) {
	tree := diffFixture(t)
	archivePath := tree.Path("tree/a.ect")
	if _, err := CreateArchive(CreateConfig{
		Archive: archivePath, Paths: []string{"tree"}, BaseDir: tree.Root,
		Options: Options{Codec: "zstd", ChunkSize: 4096},
	}); err != nil {
		t.Fatal(err)
	}

	// The archive changed the time of its directory when it was written,
	// and that is a real difference. The archive itself is not one.
	res, err := DiffArchive(DiffConfig{Archive: archivePath, BaseDir: tree.Root})
	if err != nil {
		t.Fatalf("DiffArchive: %v", err)
	}
	if got, want := found(res), []string{"tree mtime"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestDiffOfAnEncryptedArchive(t *testing.T) {
	for _, encryptIndex := range []bool{false, true} {
		tree := diffFixture(t)
		archivePath := encryptedArchive(t, tree, []string{"tree"}, "zstd", encryptIndex)
		tree.Text("tree/content.txt", 0o644, "content of content.tx!")
		settle(tree)

		// The digests are keyed, so the content check needs the key.
		res, err := DiffArchive(DiffConfig{Archive: archivePath, BaseDir: tree.Root,
			Open: OpenOptions{Passphrase: passphrase("correct horse")}})
		if err != nil {
			t.Fatalf("index encrypted %v: %v", encryptIndex, err)
		}
		if got, want := found(res), []string{"tree/content.txt content"}; !reflect.DeepEqual(got, want) {
			t.Errorf("index encrypted %v: got %q, want %q", encryptIndex, got, want)
		}
	}
}

func TestDiffOfExtendedAttributes(t *testing.T) {
	if !meta.Supports.Xattrs {
		t.Skip("no extended attributes on this platform")
	}
	tree := diffFixture(t)
	tree.Xattr("tree/same.txt", "user.kept", []byte("1"))
	archivePath := diffArchive(t, tree, "tree")
	tree.Xattr("tree/same.txt", "user.kept", []byte("2")).Xattr("tree/same.txt", "user.added", []byte("3"))

	res, err := DiffArchive(DiffConfig{Archive: archivePath, BaseDir: tree.Root})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Differences) != 1 || res.Differences[0].Kind != DiffXattrs ||
		!reflect.DeepEqual(res.Differences[0].Names, []string{"user.added", "user.kept"}) {
		t.Errorf("differences: %+v, want user.added and user.kept on tree/same.txt", res.Differences)
	}

	// --no-xattrs compares none.
	res, err = DiffArchive(DiffConfig{Archive: archivePath, BaseDir: tree.Root,
		Metadata: MetadataOptions{NoXattrs: true}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Differences) != 0 {
		t.Errorf("--no-xattrs: %+v", res.Differences)
	}
}

func TestDiffOfAnUnreadableFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every file")
	}
	tree := diffFixture(t)
	archivePath := diffArchive(t, tree, "tree")
	tree.Chmod("tree/content.txt", 0)
	t.Cleanup(func() { os.Chmod(tree.Path("tree/content.txt"), 0o644) })

	if _, err := DiffArchive(DiffConfig{Archive: archivePath, BaseDir: tree.Root}); err == nil {
		t.Error("a file that cannot be read did not stop the run")
	}
	res, err := DiffArchive(DiffConfig{Archive: archivePath, BaseDir: tree.Root, KeepGoing: true})
	if err != nil {
		t.Fatalf("--keep-going: %v", err)
	}
	if res.Failed != 1 {
		t.Errorf("--keep-going: %d failed, want 1", res.Failed)
	}
	if got, want := found(res), []string{"tree/content.txt mode"}; !reflect.DeepEqual(got, want) {
		t.Errorf("--keep-going: %q, want %q", got, want)
	}
}

// The paths that the walk starts from come from the archive, which can be
// hostile. A symbolic link on disk must not take the walk out of the base
// directory: the archive could ask what any file of the system holds.
func TestDiffDoesNotLeaveTheBaseThroughALink(t *testing.T) {
	tree := diffFixture(t)
	archivePath := diffArchive(t, tree, "tree/same.txt") // no member for tree itself

	outside := testutil.NewTree(t)
	outside.Text("same.txt", 0o644, "content of same.txt")
	os.RemoveAll(tree.Path("tree"))
	tree.Symlink("tree", outside.Root)

	_, err := DiffArchive(DiffConfig{Archive: archivePath, BaseDir: tree.Root})
	if !errors.Is(err, fsutil.ErrUnsafePath) {
		t.Errorf("a walk through a link out of the base: %v, want ErrUnsafePath", err)
	}
}
