//go:build operational

// Package operational drives the compiled eictar binary the way a user does,
// asserting on exit status, streams and the filesystem. It never imports the
// internal packages: what is tested here is the program, not its parts
// (doc/design.md 13.2).
//
// Run with: go test -tags operational ./src/operational/
package operational

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/philmalin/eictar/src/internal/testutil"
)

// Exit codes, repeated here rather than imported. The operational suite is a
// black-box consumer of the program, so it must notice if these change.
const (
	exitOK       = 0
	exitUsage    = 2
	exitInternal = 70
)

func TestVersion(t *testing.T) {
	res := testutil.Run(t, t.TempDir(), "--version")
	if res.ExitCode != exitOK {
		t.Fatalf("exit %d, want %d (stderr: %s)", res.ExitCode, exitOK, res.Stderr)
	}
	if !strings.HasPrefix(res.Stdout, "eictar ") {
		t.Errorf("stdout = %q, want it to start with %q", res.Stdout, "eictar ")
	}
	if res.Stderr != "" {
		t.Errorf("stderr = %q, want it empty", res.Stderr)
	}
}

func TestHelp(t *testing.T) {
	res := testutil.Run(t, t.TempDir(), "--help")
	if res.ExitCode != exitOK {
		t.Fatalf("exit %d, want %d", res.ExitCode, exitOK)
	}
	for _, want := range []string{"--create", "--extract", "--list", "-f, --file"} {
		if !strings.Contains(res.Stdout, want) {
			t.Errorf("--help does not mention %q", want)
		}
	}
}

func TestUsageErrors(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no operation", []string{"-f", "a.ect"}, "no operation selected"},
		{"two operations", []string{"-c", "-x", "-f", "a.ect", "p"}, "only one operation"},
		{"no archive", []string{"-t"}, "requires -f"},
		{"archive is a pipe", []string{"-cf", "-", "p"}, "cannot be a pipe"},
		{"unknown option", []string{"-tf", "a.ect", "--nonesuch"}, "unknown flag"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := testutil.Run(t, dir, tc.args...)
			if res.ExitCode != exitUsage {
				t.Errorf("exit %d, want %d", res.ExitCode, exitUsage)
			}
			if res.Stdout != "" {
				t.Errorf("a usage error wrote to stdout: %q", res.Stdout)
			}
			if !strings.Contains(res.Stderr, tc.want) {
				t.Errorf("stderr = %q, want it to contain %q", res.Stderr, tc.want)
			}
		})
	}
}

// TestBareInvocationPrintsHelp: running the program with nothing at all is a
// question about what it does, and gets the full help on stdout rather than a
// one-line complaint on stderr.
func TestBareInvocationPrintsHelp(t *testing.T) {
	bare := testutil.Run(t, t.TempDir())
	if bare.ExitCode != exitOK {
		t.Errorf("exit %d, want %d", bare.ExitCode, exitOK)
	}
	if bare.Stderr != "" {
		t.Errorf("stderr = %q, want it empty", bare.Stderr)
	}

	help := testutil.Run(t, t.TempDir(), "--help")
	if bare.Stdout != help.Stdout {
		t.Errorf("a bare run and --help printed different things")
	}
	for _, want := range []string{"--create", "--extract", "-f, --file"} {
		if !strings.Contains(bare.Stdout, want) {
			t.Errorf("the help does not mention %q", want)
		}
	}
}

// TestConfigurationThroughTheBinary: a configuration file in HOME and an
// EICTAR_* variable reach the program, -v names the file, a bad variable is
// exit 2, and --show-config runs with no operation and no archive.
func TestConfigurationThroughTheBinary(t *testing.T) {
	home := t.TempDir()
	rc := filepath.Join(home, ".eictarrc")
	if err := os.WriteFile(rc, []byte("compress = xz\n[codec.xz]\npreset = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tree := testutil.NewTree(t)
	tree.Text("f.txt", 0o644, strings.Repeat("configured ", 1000))
	archive := filepath.Join(t.TempDir(), "a.ect")
	env := []string{"HOME=" + home, "XDG_CONFIG_HOME=" + filepath.Join(home, "none")}

	create := testutil.RunEnv(t, tree.Root, env, "-cvf", archive, "f.txt")
	if create.ExitCode != exitOK || !strings.Contains(create.Stderr, "using configuration file "+rc) {
		t.Fatalf("create: exit %d, stderr %q", create.ExitCode, create.Stderr)
	}
	if long := testutil.RunEnv(t, tree.Root, env, "-tvf", archive).Stdout; !strings.Contains(long, "xz:preset=1") {
		t.Errorf("the configured codec was not used:\n%s", long)
	}

	bad := testutil.RunEnv(t, tree.Root, append(env, "EICTAR_WORKRES=4"), "-tf", archive)
	if bad.ExitCode != exitUsage || !strings.Contains(bad.Stderr, "EICTAR_WORKRES") {
		t.Errorf("a misspelled variable: exit %d, stderr %q", bad.ExitCode, bad.Stderr)
	}

	show := testutil.RunEnv(t, tree.Root, append(env, "EICTAR_WORKERS=6"), "--show-config")
	if show.ExitCode != exitOK || !strings.Contains(show.Stdout, "(EICTAR_WORKERS)") || !strings.Contains(show.Stdout, rc) {
		t.Errorf("--show-config: exit %d\n%s%s", show.ExitCode, show.Stdout, show.Stderr)
	}
}
