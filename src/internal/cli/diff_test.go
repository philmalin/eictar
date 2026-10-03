package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/philmalin/eictar/src/internal/archive"
)

// TestDiffThroughRun checks what --diff prints and its exit codes: 0 when
// the tree is as archived, 1 when it differs, as for diff(1) and tar -d.
func TestDiffThroughRun(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(dir, "a.ect")
	run := func(argv ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Run(argv, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	if code, _, stderr := run("-cf", archivePath, "-C", dir, "src"); code != ExitOK {
		t.Fatalf("create: exit %d: %s", code, stderr)
	}

	code, stdout, stderr := run("--diff", "-f", archivePath, "-C", dir)
	if code != ExitOK || !strings.Contains(stdout, "no differences, 2 members compared") {
		t.Errorf("unchanged: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if code, stdout, _ := run("--diff", "-q", "-f", archivePath, "-C", dir); code != ExitOK || stdout != "" {
		t.Errorf("unchanged with -q: exit %d, stdout %q", code, stdout)
	}

	if err := os.WriteFile(filepath.Join(src, "new.txt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	// -q does not hide the differences: they are the result.
	code, stdout, stderr = run("--diff", "-q", "-f", archivePath, "-C", dir, "*.txt")
	if code != ExitPartial {
		t.Errorf("changed: exit %d, want %d", code, ExitPartial)
	}
	if want := "src/new.txt: not in the archive\n"; stdout != want {
		t.Errorf("changed: stdout %q, want %q", stdout, want)
	}
	if !strings.Contains(stderr, "1 path differs") {
		t.Errorf("changed: stderr %q", stderr)
	}

	// As for -t and -x, a pattern must select a member: a path that is new
	// on disk is found inside the archived tree, not named.
	if code, _, stderr := run("--diff", "-f", archivePath, "-C", dir, "src/new.txt"); code != ExitUsage {
		t.Errorf("a pattern of a new path: exit %d, want %d (%s)", code, ExitUsage, stderr)
	}
}

func TestDifferenceLine(t *testing.T) {
	for _, tc := range []struct {
		d    archive.Difference
		want string
	}{
		{archive.Difference{Path: "a", Kind: archive.DiffMissing}, "a: not on disk"},
		{archive.Difference{Path: "a", Kind: archive.DiffExtra}, "a: not in the archive"},
		{archive.Difference{Path: "a", Kind: archive.DiffContent}, "a: content differs"},
		{archive.Difference{Path: "a", Kind: archive.DiffType, Archive: "file", Disk: "directory"},
			"a: type differs: archive file, disk directory"},
		{archive.Difference{Path: "a", Kind: archive.DiffMode, Archive: "0644", Disk: "0600"},
			"a: mode differs: archive 0644, disk 0600"},
		{archive.Difference{Path: "a", Kind: archive.DiffLink, Archive: "x y", Disk: "z"},
			`a: link target differs: archive "x y", disk "z"`},
		{archive.Difference{Path: "a", Kind: archive.DiffHardlink, Archive: "b"}, "a: not a hardlink of b"},
		{archive.Difference{Path: "a", Kind: archive.DiffXattrs, Names: []string{"user.a", "user.b"}},
			"a: extended attributes differ: user.a, user.b"},
		{archive.Difference{Path: "a", Kind: archive.DiffACLs, Names: []string{"system.posix_acl_access"}},
			"a: ACLs differ: system.posix_acl_access"},
	} {
		if got := differenceLine(tc.d); got != tc.want {
			t.Errorf("differenceLine(%+v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}
