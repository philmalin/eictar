package archive

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/philmalin/eictar/src/internal/format"
	"github.com/philmalin/eictar/src/internal/fsutil"
	"github.com/philmalin/eictar/src/internal/testutil"
)

func TestStripPath(t *testing.T) {
	for _, tc := range []struct {
		in   string
		n    int
		want string
		ok   bool
	}{
		{"a/b/c", 0, "a/b/c", true},
		{"a/b/c", 1, "b/c", true},
		{"a/b/c", 2, "c", true},
		{"a/b/c", 3, "", false},
		{"a", 1, "", false},
		{"a/b", 5, "", false},
	} {
		got, ok := stripPath(tc.in, tc.n)
		if got != tc.want || ok != tc.ok {
			t.Errorf("stripPath(%q, %d) = %q, %v; want %q, %v", tc.in, tc.n, got, ok, tc.want, tc.ok)
		}
	}
}

// stripFixture is two releases of one project side by side. Both have
// src/a, so --strip-components 1 gives them one path.
func stripFixture(t *testing.T) (*testutil.Tree, string) {
	t.Helper()
	tree := testutil.NewTree(t)
	tree.Dir("p1/src", 0o755).Dir("p2/src", 0o755)
	tree.Text("p1/README", 0o644, "readme")
	tree.Text("p1/src/a", 0o644, "one")
	tree.Text("p1/src/b", 0o644, "bee")
	tree.Hardlink("p1/src/hl", "p1/src/b")
	tree.Symlink("p1/link", "README")
	tree.Text("p2/src/a", 0o644, "two")
	settle(tree)

	archivePath := filepath.Join(t.TempDir(), "a.ect")
	if _, err := CreateArchive(CreateConfig{
		Archive: archivePath, Paths: []string{"p1", "p2"}, BaseDir: tree.Root,
		Options: Options{Codec: "zstd", ChunkSize: 4096},
	}); err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}
	return tree, archivePath
}

func readText(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestExtractStripComponents: the paths lose their first components, the
// later member of a collision wins with a warning, a hardlink links to its
// target's new path, and the patterns match the stored paths.
func TestExtractStripComponents(t *testing.T) {
	_, archivePath := stripFixture(t)
	dest := t.TempDir()
	rep := &recordingReporter{}
	stats, err := Extract(ExtractConfig{Archive: archivePath, Destination: dest, StripComponents: 1, Reporter: rep})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if stats.Collided != 1 {
		t.Errorf("Collided = %d, want 1", stats.Collided)
	}
	if want := "p1/src/a: not extracted: p2/src/a has the same path after --strip-components"; !slices.Contains(rep.warnings, want) {
		t.Errorf("warnings %q, want %q", rep.warnings, want)
	}
	if got := readText(t, filepath.Join(dest, "src/a")); got != "two" {
		t.Errorf("src/a = %q, want the later member's %q", got, "two")
	}
	if got := readText(t, filepath.Join(dest, "README")); got != "readme" {
		t.Errorf("README = %q", got)
	}
	if target, err := os.Readlink(filepath.Join(dest, "link")); err != nil || target != "README" {
		t.Errorf("link -> %q (%v), want README", target, err)
	}
	b, errB := os.Stat(filepath.Join(dest, "src/b"))
	hl, errH := os.Stat(filepath.Join(dest, "src/hl"))
	if errB != nil || errH != nil || !os.SameFile(b, hl) {
		t.Errorf("src/hl is not a link to src/b (%v, %v)", errB, errH)
	}
	for _, gone := range []string{"p1", "p2"} {
		if _, err := os.Lstat(filepath.Join(dest, gone)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s exists (%v): the strip left it in", gone, err)
		}
	}

	// The pattern names a stored path, and selects only one release.
	dest = t.TempDir()
	stats, err = Extract(ExtractConfig{Archive: archivePath, Destination: dest, StripComponents: 1, Patterns: []string{"p1"}})
	if err != nil || stats.Collided != 0 {
		t.Fatalf("Extract p1: %v, Collided %d", err, stats.Collided)
	}
	if got := readText(t, filepath.Join(dest, "src/a")); got != "one" {
		t.Errorf("src/a = %q, want %q", got, "one")
	}
}

// TestStripLeavesOutShortPaths: a member with N components or fewer is not
// extracted, and a hardlink whose target is left out gets the content.
func TestStripLeavesOutShortPaths(t *testing.T) {
	_, archivePath := stripFixture(t)
	dest := t.TempDir()
	if _, err := Extract(ExtractConfig{Archive: archivePath, Destination: dest, StripComponents: 2, Patterns: []string{"p1/src/hl", "p1/README"}}); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	entries, err := os.ReadDir(dest)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if !slices.Equal(names, []string{"hl"}) {
		t.Errorf("destination holds %q, want only hl", names)
	}
	if got := readText(t, filepath.Join(dest, "hl")); got != "bee" {
		t.Errorf("hl = %q, want its target's content", got)
	}
}

// TestPlanExtractStripComponents: the dry run gives the paths that
// extraction writes, and counts the collision.
func TestPlanExtractStripComponents(t *testing.T) {
	_, archivePath := stripFixture(t)
	dest := filepath.Join(t.TempDir(), "new")
	var plan planned
	stats, err := PlanExtract(ExtractConfig{Archive: archivePath, Destination: dest, StripComponents: 1, Reporter: &recordingReporter{}}, plan.add)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"README", "link", "src", "src/a", "src/b", "src/hl"}
	if !slices.Equal(plan.lines, want) || stats.Collided != 1 {
		t.Errorf("plan %q, Collided %d; want %q, 1", plan.lines, stats.Collided, want)
	}
	if _, err := os.Stat(dest); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the dry run made the destination (%v)", err)
	}
}

// TestStripKeepsAnUnsafePath: stripped, "../../escaped.txt" would be
// "escaped.txt", which passes the check. The member must be refused as it
// is without the option.
func TestStripKeepsAnUnsafePath(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Text("a.txt", 0o644, "content")
	archivePath := filepath.Join(t.TempDir(), "a.ect")
	if _, err := CreateArchive(CreateConfig{
		Archive: archivePath, Paths: []string{"a.txt"}, BaseDir: tree.Root, Options: Options{Codec: "none"},
	}); err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}
	forgeMemberPath(t, archivePath, "../../escaped.txt")

	dest := t.TempDir()
	_, err := Extract(ExtractConfig{Archive: archivePath, Destination: dest, StripComponents: 2})
	if !errors.Is(err, fsutil.ErrUnsafePath) {
		t.Errorf("error = %v, want an unsafe path", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "escaped.txt")); err == nil {
		t.Error("the member with an unsafe path was extracted")
	}
}

// TestDiffStripComponents: --diff compares the tree that extraction with
// the same option writes, matches the patterns and excludes against stored
// paths, and checks a hardlink against its target's new path.
func TestDiffStripComponents(t *testing.T) {
	_, archivePath := stripFixture(t)
	dest := t.TempDir()
	if _, err := Extract(ExtractConfig{Archive: archivePath, Destination: dest, StripComponents: 1, Reporter: &recordingReporter{}}); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	diff := func(cfg DiffConfig) DiffResult {
		t.Helper()
		cfg.Archive, cfg.BaseDir, cfg.StripComponents = archivePath, dest, 1
		if cfg.Reporter == nil {
			cfg.Reporter = &recordingReporter{}
		}
		res, err := DiffArchive(cfg)
		if err != nil {
			t.Fatalf("DiffArchive: %v", err)
		}
		return res
	}

	rep := &recordingReporter{}
	res := diff(DiffConfig{Reporter: rep})
	if len(res.Differences) != 0 || res.Collided != 1 {
		t.Errorf("differences %q, Collided %d; want none, 1", found(res), res.Collided)
	}
	if want := "p1/src/a: not compared: p2/src/a has the same path after --strip-components"; !slices.Contains(rep.warnings, want) {
		t.Errorf("warnings %q, want %q", rep.warnings, want)
	}

	// A pattern selects stored paths. The paths on disk that it selects are
	// compared, and nothing else is reported.
	if res := diff(DiffConfig{Patterns: []string{"p1/*"}}); len(res.Differences) != 0 || res.Compared == 0 {
		t.Errorf("p1/*: differences %q, %d compared", found(res), res.Compared)
	}

	// A path that the archive lacks is reported, unless an exclude for its
	// stored path leaves it out.
	if err := os.WriteFile(filepath.Join(dest, "src/new"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if res := diff(DiffConfig{}); !slices.Contains(found(res), "src/new extra") {
		t.Errorf("differences %q, want src/new extra", found(res))
	}
	if res := diff(DiffConfig{Exclude: []string{"*/src/new"}}); slices.Contains(found(res), "src/new extra") {
		t.Errorf("--exclude */src/new: differences %q, want no src/new", found(res))
	}

	// src/hl as a copy, not a link to src/b, is a difference.
	hl := filepath.Join(dest, "src/hl")
	if err := os.Remove(hl); err != nil {
		t.Fatal(err)
	}
	copyFile(t, filepath.Join(dest, "src/b"), hl)
	if res := diff(DiffConfig{}); !slices.Contains(found(res), "src/hl hardlink") {
		t.Errorf("differences %q, want src/hl hardlink", found(res))
	}
}

// TestStripMembersKeepsOneDirectory: two directories with one path are one
// directory, with no warning; two files are a collision.
func TestStripMembersKeepsOneDirectory(t *testing.T) {
	members := []format.Member{
		{Path: "p1", Type: format.TypeDir},
		{Path: "p1/d", Type: format.TypeDir, Mode: 0o700},
		{Path: "p1/d/f", Type: format.TypeReg},
		{Path: "p2/d", Type: format.TypeDir, Mode: 0o755},
		{Path: "p2/d/f", Type: format.TypeReg},
	}
	rep := &recordingReporter{}
	out, collided := stripMembers(members, 1, rep, "not extracted")
	var got []string
	for _, m := range out {
		got = append(got, m.Path)
	}
	if !slices.Equal(got, []string{"d", "d/f"}) || collided != 1 || len(rep.warnings) != 1 ||
		!strings.HasPrefix(rep.warnings[0], "p1/d/f:") {
		t.Errorf("paths %q, collided %d, warnings %q", got, collided, rep.warnings)
	}
	if out[0].Mode != 0o755 {
		t.Errorf("the directory has mode %o, want the later member's 755", out[0].Mode)
	}
}
