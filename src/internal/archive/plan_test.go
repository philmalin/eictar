//go:build unix

package archive

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/philmalin/eictar/src/internal/format"
	"github.com/philmalin/eictar/src/internal/fsutil"
	"github.com/philmalin/eictar/src/internal/testutil"
)

// memberReporter collects the paths of the members an operation writes, and
// its warnings.
type memberReporter struct {
	mu       sync.Mutex
	paths    []string
	warnings []string
}

func (r *memberReporter) Member(m *format.Member) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.paths = append(r.paths, m.Path)
}

func (r *memberReporter) Warn(f string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.warnings = append(r.warnings, fmt.Sprintf(f, args...))
}

// planned collects the paths of a dry run, as "path" or "path replaces".
type planned struct{ lines []string }

func (p *planned) add(pl Planned) {
	line := pl.Path
	if pl.Replaces {
		line += " replaces"
	}
	p.lines = append(p.lines, line)
}

func sorted(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

// fileBytes reads a file, to show that a dry run left it as it was.
func fileBytes(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPlanAddIsWhatCreateWrites(t *testing.T) {
	tree := diffFixture(t)
	tree.Text("tree/skip.log", 0o644, "left out by -R").Socket("tree/sock")
	cfg := CreateConfig{
		Paths: []string{"tree"}, BaseDir: tree.Root,
		Options:      Options{Codec: "zstd", ChunkSize: 4096},
		Regex:        mustRegexps(t, `tree(/.*)?`),
		ExcludeRegex: mustRegexps(t, `.*\.log`),
		Exclude:      []string{"tree/gonedir/b"},
	}

	var plan planned
	cfg.Archive = filepath.Join(t.TempDir(), "a.ect")
	rep := &memberReporter{}
	cfg.Reporter = rep
	stats, err := PlanAdd(AppendConfig{CreateConfig: cfg}, false, plan.add)
	if err != nil {
		t.Fatalf("PlanAdd: %v", err)
	}
	if _, err := os.Stat(cfg.Archive); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the dry run made %s (%v)", cfg.Archive, err)
	}
	if stats.Skipped != 1 || !strings.Contains(strings.Join(rep.warnings, "\n"), "socket ignored") {
		t.Errorf("stats %+v, warnings %q: want the socket skipped with a notice", stats, rep.warnings)
	}

	rep = &memberReporter{}
	cfg.Reporter = rep
	if _, err := CreateArchive(cfg); err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}
	if got, want := sorted(plan.lines), sorted(rep.paths); !reflect.DeepEqual(got, want) {
		t.Errorf("dry run %q, create wrote %q", got, want)
	}

	// The content of a hardlinked file counts once, as create stores it
	// once.
	members, err := List(ListConfig{Archive: cfg.Archive})
	if err != nil {
		t.Fatal(err)
	}
	var want uint64
	for _, m := range members {
		if m.Type == format.TypeReg {
			want += m.Size
		}
	}
	if stats.Bytes != want || stats.Members != len(rep.paths) {
		t.Errorf("stats %+v, want %d members and %d bytes", stats, len(rep.paths), want)
	}
}

func TestPlanAddLeavesTheArchiveOut(t *testing.T) {
	tree := diffFixture(t)
	cfg := CreateConfig{Archive: filepath.Join(tree.Root, "tree", "a.ect"), Paths: []string{"tree"}, BaseDir: tree.Root}
	if _, err := CreateArchive(cfg); err != nil {
		t.Fatal(err)
	}
	var plan planned
	if _, err := PlanAdd(AppendConfig{CreateConfig: cfg}, false, plan.add); err != nil {
		t.Fatal(err)
	}
	for _, line := range plan.lines {
		if line == "tree/a.ect" {
			t.Errorf("the dry run lists the archive itself: %q", plan.lines)
		}
	}
}

// update makes the changes that -u and -r find: one file changed, one new.
func update(tree *testutil.Tree) {
	tree.Text("tree/content.txt", 0o644, "content of content.tx!")
	tree.Text("tree/new.txt", 0o644, "new")
	settle(tree)
	tree.SetTimes("tree/content.txt", diffStamp.Add(time.Hour), diffStamp.Add(time.Hour))
}

func TestPlanAddIsWhatUpdateWrites(t *testing.T) {
	for _, mode := range []string{UpdateNewer, UpdateDifferent, UpdateDigest} {
		tree := diffFixture(t)
		archivePath := diffArchive(t, tree, "tree")
		update(tree)
		before := fileBytes(t, archivePath)

		cfg := AppendConfig{CreateConfig: CreateConfig{Archive: archivePath, Paths: []string{"tree"}, BaseDir: tree.Root}, UpdateMode: mode}
		var plan planned
		stats, err := PlanAdd(cfg, true, plan.add)
		if err != nil {
			t.Fatalf("%s: PlanAdd: %v", mode, err)
		}
		if !bytes.Equal(before, fileBytes(t, archivePath)) {
			t.Errorf("%s: the dry run changed the archive", mode)
		}
		// settle gave the directory its old time again, so it is unchanged.
		want := []string{"tree/content.txt replaces", "tree/new.txt"}
		if got := sorted(plan.lines); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: dry run %q, want %q", mode, got, want)
		}
		if stats.Replaced != 1 || stats.Unchanged == 0 {
			t.Errorf("%s: stats %+v, want 1 replaced and the rest unchanged", mode, stats)
		}

		rep := &memberReporter{}
		cfg.Reporter = rep
		if _, err := AppendArchive(cfg); err != nil {
			t.Fatalf("%s: AppendArchive: %v", mode, err)
		}
		var paths []string
		for _, line := range plan.lines {
			paths = append(paths, strings.TrimSuffix(line, " replaces"))
		}
		if got, want := sorted(paths), sorted(rep.paths); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: dry run %q, update wrote %q", mode, got, want)
		}
	}
}

// The digests of an encrypted archive are keyed: without the key, a dry run
// of -u --update-mode=digest would find every file out of date.
func TestPlanAddUpdatesByDigestWithTheKey(t *testing.T) {
	tree := diffFixture(t)
	archivePath := encryptedArchive(t, tree, []string{"tree"}, "zstd", true)
	tree.SetTimes("tree/same.txt", diffStamp.Add(time.Hour), diffStamp.Add(time.Hour))

	var plan planned
	_, err := PlanAdd(AppendConfig{
		CreateConfig: CreateConfig{Archive: archivePath, Paths: []string{"tree"}, BaseDir: tree.Root},
		UpdateMode:   UpdateDigest,
		Open:         OpenOptions{Passphrase: passphrase("correct horse")},
	}, true, plan.add)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.lines) != 0 {
		t.Errorf("dry run %q, want nothing: only a time changed", plan.lines)
	}
}

func TestPlanAddFollowsOnConflict(t *testing.T) {
	tree := diffFixture(t)
	archivePath := diffArchive(t, tree, "tree/same.txt")
	tree.Text("tree/other.txt", 0o644, "other")
	cfg := AppendConfig{CreateConfig: CreateConfig{Archive: archivePath, Paths: []string{"tree/same.txt", "tree/other.txt"}, BaseDir: tree.Root}}

	for policy, want := range map[string][]string{
		ConflictReplace: {"tree/other.txt", "tree/same.txt replaces"},
		ConflictSkip:    {"tree/other.txt"},
	} {
		cfg.OnConflict = policy
		var plan planned
		if _, err := PlanAdd(cfg, true, plan.add); err != nil {
			t.Fatalf("%s: %v", policy, err)
		}
		if got := sorted(plan.lines); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: dry run %q, want %q", policy, got, want)
		}
	}
	cfg.OnConflict = ConflictError
	if _, err := PlanAdd(cfg, true, func(Planned) {}); !errors.Is(err, ErrConflict) {
		t.Errorf("error policy: got %v, want ErrConflict", err)
	}
}

func TestPlanExtractFollowsTheOverwritePolicy(t *testing.T) {
	tree := diffFixture(t)
	archivePath := diffArchive(t, tree, "tree")
	dest := t.TempDir()
	if _, err := Extract(ExtractConfig{Archive: archivePath, Destination: dest}); err != nil {
		t.Fatal(err)
	}
	// One file older than its member, one newer, one gone.
	old, newer := diffStamp.Add(-time.Hour), diffStamp.Add(time.Hour)
	for name, when := range map[string]time.Time{"tree/mtime.txt": old, "tree/size.txt": newer} {
		if err := os.Chtimes(filepath.Join(dest, name), when, when); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(filepath.Join(dest, "tree/gone.txt")); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		policy OverwritePolicy
		want   []string
	}{
		{OverwriteNever, []string{"tree", "tree/gone.txt", "tree/gonedir"}},
		{OverwriteNewer, []string{"tree", "tree/gone.txt", "tree/gonedir", "tree/mtime.txt replaces"}},
	}
	for _, c := range cases {
		var plan planned
		if _, err := PlanExtract(ExtractConfig{Archive: archivePath, Destination: dest, Overwrite: c.policy}, plan.add); err != nil {
			t.Fatal(err)
		}
		if got := sorted(plan.lines); !reflect.DeepEqual(got, c.want) {
			t.Errorf("policy %d: dry run %q, want %q", c.policy, got, c.want)
		}
	}

	// Under the default every member is written, and an existing file is
	// replaced. The real run writes the same paths.
	var plan planned
	stats, err := PlanExtract(ExtractConfig{Archive: archivePath, Destination: dest}, plan.add)
	if err != nil {
		t.Fatal(err)
	}
	rep := &memberReporter{}
	if _, err := Extract(ExtractConfig{Archive: archivePath, Destination: dest, Reporter: rep}); err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, line := range plan.lines {
		if !strings.HasSuffix(line, " replaces") && line != "tree" && line != "tree/gonedir" && line != "tree/gone.txt" {
			t.Errorf("%q: want it to replace the file on disk", line)
		}
		paths = append(paths, strings.TrimSuffix(line, " replaces"))
	}
	if got, want := sorted(paths), sorted(rep.paths); !reflect.DeepEqual(got, want) {
		t.Errorf("dry run %q, extract wrote %q", got, want)
	}
	if stats.Members != len(rep.paths) {
		t.Errorf("stats %+v, want %d members", stats, len(rep.paths))
	}
}

func TestPlanExtractDoesNotMakeTheDestination(t *testing.T) {
	tree := diffFixture(t)
	archivePath := diffArchive(t, tree, "tree")
	dest := filepath.Join(t.TempDir(), "new")

	var plan planned
	if _, err := PlanExtract(ExtractConfig{Archive: archivePath, Destination: dest, Patterns: []string{"tree/gonedir"}}, plan.add); err != nil {
		t.Fatal(err)
	}
	if want := []string{"tree/gonedir", "tree/gonedir/a", "tree/gonedir/b"}; !reflect.DeepEqual(sorted(plan.lines), want) {
		t.Errorf("dry run %q, want %q", plan.lines, want)
	}
	if _, err := os.Stat(dest); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the dry run made %s (%v)", dest, err)
	}
}

func TestPlanExtractRefusesAnUnsafePath(t *testing.T) {
	tree := diffFixture(t)
	archivePath := diffArchive(t, tree, "tree/same.txt")
	forgeMemberPath(t, archivePath, "../escaped")

	_, err := PlanExtract(ExtractConfig{Archive: archivePath, Destination: t.TempDir()}, func(Planned) {})
	if !errors.Is(err, fsutil.ErrUnsafePath) {
		t.Errorf("got %v, want ErrUnsafePath, as extract gives", err)
	}
}

func TestPlanDeleteIsWhatDeleteRemoves(t *testing.T) {
	tree := diffFixture(t)
	archivePath := diffArchive(t, tree, "tree")
	before := fileBytes(t, archivePath)
	cfg := DeleteConfig{Archive: archivePath,
		Regex: mustRegexps(t, `.*\.txt`)}

	var plan planned
	if _, err := PlanDelete(cfg, plan.add); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, fileBytes(t, archivePath)) {
		t.Error("the dry run changed the archive")
	}
	rep := &memberReporter{}
	cfg.Reporter = rep
	if _, err := DeleteMembers(cfg); err != nil {
		t.Fatal(err)
	}
	if len(plan.lines) == 0 || !reflect.DeepEqual(sorted(plan.lines), sorted(rep.paths)) {
		t.Errorf("dry run %q, delete removed %q", plan.lines, rep.paths)
	}
}

func mustRegexps(t *testing.T, exprs ...string) fsutil.Regexps {
	t.Helper()
	rs, err := fsutil.CompileRegexps(exprs)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}
