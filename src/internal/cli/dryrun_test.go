package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/philmalin/eictar/src/internal/archive"
)

// TestDryRunThroughRun checks what -n prints for each operation, and that it
// changes nothing.
func TestDryRunThroughRun(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"a.txt": "hello", "b.log": "log"} {
		if err := os.WriteFile(filepath.Join(src, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	archivePath := filepath.Join(dir, "a.ect")
	run := func(argv ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Run(argv, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}

	// -n with -R shows what the expression picks up, and makes no archive.
	code, stdout, stderr := run("-cnf", archivePath, "-C", dir, "-R", `.*\.txt`, "src")
	if code != ExitOK || stdout != "src/a.txt\n" {
		t.Errorf("create: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "dry run, nothing written: 1 path, 5 B of file content") {
		t.Errorf("create: stderr %q", stderr)
	}
	if _, err := os.Stat(archivePath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the dry run made the archive (%v)", err)
	}

	if code, _, stderr := run("-cf", archivePath, "-C", dir, "src"); code != ExitOK {
		t.Fatalf("create: exit %d: %s", code, stderr)
	}
	before, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}

	// -q leaves the paths, which are the result, and hides the summary. -v
	// says what happens to each path.
	if err := os.WriteFile(filepath.Join(src, "c.txt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = run("-rnqf", archivePath, "-C", dir, "src/a.txt", "src/c.txt")
	if code != ExitOK || stdout != "src/a.txt\nsrc/c.txt\n" || stderr != "" {
		t.Errorf("append -q: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	code, stdout, _ = run("-rnvf", archivePath, "-C", dir, "src/a.txt", "src/c.txt")
	if want := "replace  src/a.txt\nadd      src/c.txt\n"; code != ExitOK || stdout != want {
		t.Errorf("append -v: exit %d, stdout %q, want %q", code, stdout, want)
	}

	code, stdout, stderr = run("--delete", "-nvf", archivePath, "*.log")
	if code != ExitOK || stdout != "delete   src/b.log\n" || !strings.Contains(stderr, "nothing deleted") {
		t.Errorf("delete: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}

	dest := filepath.Join(dir, "out")
	code, stdout, _ = run("-xnf", archivePath, "-d", dest)
	if code != ExitOK || stdout != "src\nsrc/a.txt\nsrc/b.log\n" {
		t.Errorf("extract: exit %d, stdout %q", code, stdout)
	}
	if _, err := os.Stat(dest); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the dry run made the destination (%v)", err)
	}

	after, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("a dry run changed the archive")
	}
}

// TestDryRunDropsProgressFromAConfiguration: --progress typed with -n is a
// mistake, but from a configuration it is a preference for the runs that do
// work, as encrypt-index is.
func TestDryRunDropsProgressFromAConfiguration(t *testing.T) {
	home := t.TempDir()
	writeConfig(t, filepath.Join(home, ".eictarrc"), "progress = true\n")
	withEnv(t, home)
	o := mustParse(t, "-cnf", "a", "p")
	if !o.DryRun || o.Progress {
		t.Errorf("DryRun %v, Progress %v: want a dry run with no meter", o.DryRun, o.Progress)
	}
}

func TestDryRunSummary(t *testing.T) {
	for _, tc := range []struct {
		op    Operation
		stats archive.Stats
		want  string
	}{
		{OpCreate, archive.Stats{Members: 1, Bytes: 5}, "dry run, nothing written: 1 path, 5 B of file content"},
		{OpUpdate, archive.Stats{Members: 3, Bytes: 2048, Replaced: 1, Unchanged: 7, Skipped: 1, Failed: 2},
			"dry run, nothing written: 3 paths, 2.0 KiB of file content; 1 replace a member; 7 unchanged; 1 skipped; 2 failed"},
		{OpDelete, archive.Stats{Members: 2}, "dry run, nothing deleted: 2 paths, 0 B of file content"},
	} {
		if got := dryRunSummary(tc.op, tc.stats); got != tc.want {
			t.Errorf("got %q, want %q", got, tc.want)
		}
	}
}
