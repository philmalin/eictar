package archive

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/philmalin/eictar/src/internal/fsutil"
	"github.com/philmalin/eictar/src/internal/meta"
	"github.com/philmalin/eictar/src/internal/testutil"
)

// Tests of the walk (walk.go) for what the tests of create do not reach.

// storedPaths creates an archive of paths, with cfg changed by mod, and
// gives the paths of its members.
func storedPaths(t *testing.T, mod func(*CreateConfig), paths ...string) ([]string, error) {
	t.Helper()
	cfg := CreateConfig{Archive: filepath.Join(t.TempDir(), "x.ect"), Paths: paths, Options: Options{Codec: "none"}}
	mod(&cfg)
	if _, err := CreateArchive(cfg); err != nil {
		return nil, err
	}
	r, err := Open(cfg.Archive, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	var out []string
	for _, m := range r.Members() {
		out = append(out, m.Path)
	}
	slices.Sort(out)
	return out, nil
}

// TestRequestedPaths: an absolute path is not under -C, "." and ".." are
// walked, the root of the walk is not a member, and an empty path is
// refused.
func TestRequestedPaths(t *testing.T) {
	tree := mutTree(t)
	other := t.TempDir()

	got, err := storedPaths(t, func(c *CreateConfig) { c.BaseDir = other }, tree.Path("t/a.txt"))
	if err != nil || len(got) != 1 || !strings.HasSuffix(got[0], "t/a.txt") {
		t.Errorf("an absolute path under another -C: %v, %v", got, err)
	}
	got, err = storedPaths(t, func(c *CreateConfig) { c.BaseDir = tree.Path("t") }, ".")
	if want := []string{"a.txt", "b.txt", "sub", "sub/c.txt"}; err != nil || !slices.Equal(got, want) {
		t.Errorf(`".": %v, %v; want %v, with no member for the root`, got, err, want)
	}
	got, err = storedPaths(t, func(c *CreateConfig) { c.BaseDir = tree.Path("t/sub") }, "..")
	if err != nil || !slices.Contains(got, "a.txt") {
		t.Errorf(`"..": %v, %v; want the members of t`, got, err)
	}
	if _, err := storedPaths(t, func(c *CreateConfig) { c.BaseDir = tree.Root }, ""); !errors.Is(err, fsutil.ErrUnsafePath) {
		t.Errorf("an empty path: %v, want %v", err, fsutil.ErrUnsafePath)
	}
}

// TestOneFileSystemOnOneFileSystem: --one-file-system enters each directory
// of a tree that is on one file system.
func TestOneFileSystemOnOneFileSystem(t *testing.T) {
	tree := mutTree(t)
	got, err := storedPaths(t, func(c *CreateConfig) { c.BaseDir, c.OneFileSystem = tree.Root, true }, "t")
	if want := []string{"t", "t/a.txt", "t/b.txt", "t/sub", "t/sub/c.txt"}; err != nil || !slices.Equal(got, want) {
		t.Errorf("%v, %v; want %v", got, err, want)
	}
}

// TestRequestedPathErrorsStop: a requested path that the walk cannot read
// stops it, even with --keep-going: it is a mistake in what was asked for.
func TestRequestedPathErrorsStop(t *testing.T) {
	tree := mutTree(t)
	_, err := storedPaths(t, func(c *CreateConfig) { c.BaseDir, c.KeepGoing = tree.Root, true }, "t", "missing")
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a missing path with --keep-going: %v, want %v", err, os.ErrNotExist)
	}
}

// TestWalkErrorsNameTheFullPath: an error of the walk names the path on
// disk, not only the name inside its directory.
func TestWalkErrorsNameTheFullPath(t *testing.T) {
	if runtime.GOOS == "windows" || meta.IsRoot() {
		t.Skip("needs a directory that the user cannot list")
	}
	tree := mutTree(t)
	tree.Dir("t/locked", 0o755)
	tree.Text("t/locked/f", 0o644, "x")
	if err := os.Chmod(tree.Path("t/locked"), 0o300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(tree.Path("t/locked"), 0o755) })
	var failed []string
	wk := newWalker(walkOptions{baseDir: tree.Root, onError: func(_ string, err error) error {
		failed = append(failed, err.Error())
		return nil
	}}, func(entry) error { return nil })
	if err := wk.Walk("t"); err != nil {
		t.Fatal(err)
	}
	if len(failed) != 1 || !strings.Contains(failed[0], tree.Path("t/locked")) {
		t.Errorf("errors %q, want one that names %s", failed, tree.Path("t/locked"))
	}
}

// TestLinkReadThroughTheHeldDirectory: a link is read through the directory
// that the walk holds. If its directory becomes a link to another one after
// the lstat, the link of the other directory, which can lead anywhere, is
// not what the archive stores (doc/Security_Audit.md, finding 11).
func TestLinkReadThroughTheHeldDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not rename a directory that the walk holds open")
	}
	tree := testutil.NewTree(t)
	tree.Dir("tree/d", 0o755)
	tree.Symlink("tree/d/l", "mine")
	outside := testutil.NewTree(t)
	outside.Symlink("l", "/the/secret")

	var targets []string
	wk := newWalker(walkOptions{
		baseDir: tree.Root,
		afterLstat: func(src string) {
			if src == tree.Path("tree/d/l") {
				swapForLink(t, tree.Path("tree/d"), outside.Root)
			}
		},
	}, func(e entry) error {
		if e.Kind == kindSymlink {
			targets = append(targets, e.LinkTarget)
		}
		return nil
	})
	if err := wk.Walk("tree"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(targets, []string{"mine"}) {
		t.Errorf("link targets %q, want the one of the tree", targets)
	}
}

// TestConflictOnADirectoryStops: -r with --on-conflict=error refuses a
// directory that the archive holds, as it refuses a file, even when each
// file below it is new.
func TestConflictOnADirectoryStops(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Dir("t", 0o755)
	archive := mkArchive(t, tree, false, "t")
	tree.Text("t/new.txt", 0o644, "new")
	_, err := appendTo(t, archive, tree, false, func(c *AppendConfig) { c.OnConflict = ConflictError }, "t")
	if !errors.Is(err, ErrConflict) {
		t.Errorf("AppendArchive = %v, want %v", err, ErrConflict)
	}
}

// TestDotPathsFromTheCurrentDirectory: "." and ".." given as they are, with
// no -C, have no parent of their own to open: the walk takes them by their
// path.
func TestDotPathsFromTheCurrentDirectory(t *testing.T) {
	tree := mutTree(t)
	t.Chdir(tree.Path("t/sub"))
	for _, tc := range []struct {
		path string
		want string
	}{{".", "c.txt"}, {"..", "a.txt"}} {
		got, err := storedPaths(t, func(*CreateConfig) {}, tc.path)
		if err != nil || !slices.Contains(got, tc.want) {
			t.Errorf("%q: %v, %v; want %s in it", tc.path, got, err, tc.want)
		}
	}
}
