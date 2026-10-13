//go:build unix

package archive

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/philmalin/eictar/src/internal/fsutil"
	"github.com/philmalin/eictar/src/internal/testutil"
)

// Tests of the dry runs (plan.go) that the comparisons with the real runs
// in plan_test.go do not reach: the refusals, the counts, and the warnings.

// sizes collects the planned paths with their sizes.
type sizes []string

func (s *sizes) add(p Planned) {
	line := p.Path + " " + strings.Repeat("+", int(p.Size))
	if p.Replaces {
		line += " replaces"
	}
	*s = append(*s, line)
}

// TestPlanRefuses: a dry run refuses what its real run refuses.
func TestPlanRefuses(t *testing.T) {
	tree := mutTree(t)
	archive := mkArchive(t, tree, false, "t")
	missing := filepath.Join(t.TempDir(), "missing.ect")
	none := func(Planned) {}
	for _, tc := range []struct {
		name string
		run  func() error
		want error
	}{
		{"add: a policy that is not valid", func() error {
			_, err := PlanAdd(AppendConfig{CreateConfig: CreateConfig{Archive: archive, Paths: []string{"t"}, BaseDir: tree.Root}, OnConflict: "x"}, true, none)
			return err
		}, nil},
		{"add: no archive", func() error {
			_, err := PlanAdd(AppendConfig{CreateConfig: CreateConfig{Archive: missing, Paths: []string{"t"}, BaseDir: tree.Root}}, true, none)
			return err
		}, fs.ErrNotExist},
		{"extract: no archive", func() error {
			_, err := PlanExtract(ExtractConfig{Archive: missing, Destination: t.TempDir()}, none)
			return err
		}, fs.ErrNotExist},
		{"extract: a pattern that matches nothing", func() error {
			_, err := PlanExtract(ExtractConfig{Archive: archive, Destination: t.TempDir(), Patterns: []string{"nothing"}}, none)
			return err
		}, ErrNoMatch},
		{"delete: no pattern", func() error {
			_, err := PlanDelete(DeleteConfig{Archive: archive}, none)
			return err
		}, nil},
		{"delete: no archive", func() error {
			_, err := PlanDelete(DeleteConfig{Archive: missing, Patterns: []string{"t"}}, none)
			return err
		}, fs.ErrNotExist},
		{"delete: a pattern that matches nothing", func() error {
			_, err := PlanDelete(DeleteConfig{Archive: archive, Patterns: []string{"nothing"}}, none)
			return err
		}, ErrNoMatch},
	} {
		if err := tc.run(); err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
	// With one -R and no pattern, delete has what it needs.
	if _, err := PlanDelete(DeleteConfig{Archive: archive, Regex: mustRegexps(t, `t/a\.txt`)}, none); err != nil {
		t.Errorf("delete with -R alone: %v", err)
	}
}

// TestPlanSizesAndCounts: only regular files have a size, a second name
// of one file has none, and the counts are those of the paths.
func TestPlanSizesAndCounts(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Text("t/a", 0o644, "aa")
	tree.Text("t/b", 0o644, "bbb")
	if err := os.Symlink("a-long-target", tree.Path("t/l")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(tree.Path("t/b"), tree.Path("t/c")); err != nil {
		t.Fatal(err)
	}
	archive := mkArchive(t, tree, false, "t")
	want := []string{"t ", "t/a ++", "t/b +++", "t/c ", "t/l "}

	var add sizes
	stats, err := PlanAdd(AppendConfig{CreateConfig: CreateConfig{Archive: filepath.Join(t.TempDir(), "n.ect"), Paths: []string{"t"}, BaseDir: tree.Root}}, false, add.add)
	if err != nil || !slices.Equal(add, want) || stats.Members != 5 || stats.Bytes != 5 {
		t.Errorf("add: %q, %+v, %v", add, stats, err)
	}

	var ext sizes
	stats, err = PlanExtract(ExtractConfig{Archive: archive, Destination: t.TempDir()}, ext.add)
	if err != nil || !slices.Equal(ext, want) || stats.Members != 5 || stats.Bytes != 5 {
		t.Errorf("extract: %q, %+v, %v", ext, stats, err)
	}

	var del sizes
	stats, err = PlanDelete(DeleteConfig{Archive: archive, Patterns: []string{"t"}}, del.add)
	slices.Sort(del)
	if err != nil || !slices.Equal(del, want) || stats.Members != 5 || stats.Bytes != 5 {
		t.Errorf("delete: %q, %+v, %v", del, stats, err)
	}
}

// TestPlanAddOneFileTwiceByOneName: under -h, a link and its target are
// one file with one name. Each is stored with its content, as create does.
func TestPlanAddOneFileTwiceByOneName(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Text("t/a", 0o644, "aa")
	if err := os.Symlink("a", tree.Path("t/l")); err != nil {
		t.Fatal(err)
	}
	cfg := CreateConfig{Archive: filepath.Join(t.TempDir(), "n.ect"), Paths: []string{"t"}, BaseDir: tree.Root, Dereference: true}
	var add sizes
	stats, err := PlanAdd(AppendConfig{CreateConfig: cfg}, false, add.add)
	if err != nil || !slices.Equal(add, []string{"t ", "t/a ++", "t/l ++"}) {
		t.Errorf("%q, %v", add, err)
	}
	real, err := CreateArchive(cfg)
	if err != nil || real.Bytes != stats.Bytes {
		t.Errorf("create stored %d bytes, the dry run %d (%v)", real.Bytes, stats.Bytes, err)
	}
}

// TestPlanExtractToStdout: -O writes the content of the files, and of the
// file that a hardlink names, and nothing else. (Validate refuses a
// hardlink to a member that is not there.)
func TestPlanExtractToStdout(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Text("t/a", 0o644, "aa")
	tree.Text("t/b", 0o644, "bbb")
	if err := os.Link(tree.Path("t/b"), tree.Path("t/c")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a", tree.Path("t/l")); err != nil {
		t.Fatal(err)
	}
	archive := copyArchive(t, mkArchive(t, tree, false, "t"))
	var out sizes
	stats, err := PlanExtract(ExtractConfig{Archive: archive, ToStdout: &bytes.Buffer{}}, out.add)
	if want := []string{"t/a ++", "t/b +++", "t/c +++"}; err != nil || !slices.Equal(out, want) || stats.Members != 3 || stats.Bytes != 8 {
		t.Errorf("%q, %+v, %v; want %q", out, stats, err, want)
	}
}

// TestPlanExtractInTheCurrentDirectory: with no destination, it is the
// current directory, as for extract.
func TestPlanExtractInTheCurrentDirectory(t *testing.T) {
	tree := mutTree(t)
	archive := mkArchive(t, tree, false, "t")
	t.Chdir(tree.Root)
	var out planned
	if _, err := PlanExtract(ExtractConfig{Archive: archive}, out.add); err != nil || !slices.Contains(out.lines, "t/a.txt replaces") {
		t.Errorf("%q, %v; want t/a.txt to replace the file", out.lines, err)
	}
}

// TestPlanExtractSkipsAndFails: a device without --preserve-devices and a
// file that -k keeps are skipped, and a member that fails is a failure.
// Each skip by policy and each failure under --keep-going has its warning.
func TestPlanExtractSkipsAndFails(t *testing.T) {
	if fi, err := os.Lstat("/dev/null"); err != nil || fi.Mode()&fs.ModeCharDevice == 0 {
		t.Skip("no /dev/null")
	}
	dev := filepath.Join(t.TempDir(), "dev.ect")
	if _, err := CreateArchive(CreateConfig{Archive: dev, Paths: []string{"null"}, BaseDir: "/dev"}); err != nil {
		t.Fatal(err)
	}
	rep := &recordingReporter{}
	stats, err := PlanExtract(ExtractConfig{Archive: dev, Destination: t.TempDir(), Reporter: rep}, func(Planned) {})
	if err != nil || stats.Skipped != 1 || stats.Members != 0 || len(rep.warnings) != 1 || !strings.Contains(rep.warnings[0], "device node skipped") {
		t.Errorf("a device: %+v, %v, warnings %q", stats, err, rep.warnings)
	}
	if stats, err := PlanExtract(ExtractConfig{Archive: dev, Destination: t.TempDir()}, func(Planned) {}); err != nil || stats.Skipped != 1 {
		t.Errorf("a device, no reporter: %+v, %v", stats, err)
	}
	var out planned
	stats, err = PlanExtract(ExtractConfig{Archive: dev, Destination: t.TempDir(), Restore: RestoreOptions{Devices: true}}, out.add)
	if err != nil || stats.Members != 1 || !slices.Equal(out.lines, []string{"null"}) {
		t.Errorf("a device with --preserve-devices: %q, %+v, %v", out.lines, stats, err)
	}

	// -k keeps t/a.txt, which is there; t/sub/c.txt is under a link that
	// leads out of the destination.
	tree := mutTree(t)
	archive := mkArchive(t, tree, false, "t")
	dest := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dest, "t"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dest, "t/a.txt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(dest, "t/sub")); err != nil {
		t.Fatal(err)
	}
	rep = &recordingReporter{}
	stats, err = PlanExtract(ExtractConfig{Archive: archive, Destination: dest, Overwrite: OverwriteNever, KeepGoing: true, Reporter: rep}, func(Planned) {})
	if err != nil || stats.Skipped != 1 || stats.Failed != 1 || len(rep.warnings) != 1 || !strings.Contains(rep.warnings[0], "t/sub/c.txt") {
		t.Errorf("-k and a link: %+v, %v, warnings %q", stats, err, rep.warnings)
	}
	if stats, err := PlanExtract(ExtractConfig{Archive: archive, Destination: dest, Overwrite: OverwriteNever, KeepGoing: true}, func(Planned) {}); err != nil || stats.Failed != 1 {
		t.Errorf("-k and a link, no reporter: %+v, %v", stats, err)
	}
	if _, err := PlanExtract(ExtractConfig{Archive: archive, Destination: dest, Overwrite: OverwriteNever}, func(Planned) {}); !errors.Is(err, fsutil.ErrUnsafePath) {
		t.Errorf("a link without --keep-going: %v, want %v", err, fsutil.ErrUnsafePath)
	}
}
