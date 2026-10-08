package testutil

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// Binary builds cmd/eictar once per test binary and returns the path to it.
//
// The operational tests drive the compiled program rather than calling into
// the packages, so that what is tested is what a user runs: argument parsing,
// exit codes and streams included (doc/design.md 13.2).
func Binary(tb testing.TB) string {
	tb.Helper()

	buildOnce.Do(func() {
		root, err := moduleRoot()
		if err != nil {
			buildErr = err
			return
		}

		// Build into a directory that outlives any single test, and that the
		// OS clears eventually; t.TempDir would vanish between tests.
		dir, err := os.MkdirTemp("", "eictar-bin-")
		if err != nil {
			buildErr = err
			return
		}
		binPath = filepath.Join(dir, "eictar")
		if runtime.GOOS == "windows" {
			binPath += ".exe" // exec finds a program on Windows by its extension
		}

		cmd := exec.Command(goTool(), "build", "-o", binPath, "./src/cmd/eictar")
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			buildErr = &buildFailure{out: string(out), err: err}
			return
		}
	})

	if buildErr != nil {
		tb.Fatalf("testutil: building eictar: %v", buildErr)
	}
	return binPath
}

var (
	buildOnce sync.Once
	binPath   string
	buildErr  error
)

type buildFailure struct {
	out string
	err error
}

func (b *buildFailure) Error() string { return b.err.Error() + ": " + b.out }

// goTool returns the go command to build with.
//
// GOROOT is consulted before PATH because the toolchain that runs the tests is
// not always on PATH, and building with a different one than the caller
// intended is the kind of difference that wastes an afternoon.
func goTool() string {
	if p := os.Getenv("GOTOOL"); p != "" {
		return p
	}
	if root := runtime.GOROOT(); root != "" {
		if p := filepath.Join(root, "bin", "go"); isExecutable(p) {
			return p
		}
	}
	if p, err := exec.LookPath("go"); err == nil {
		return p
	}
	return "go"
}

func isExecutable(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0
}

// moduleRoot walks up from the working directory to the directory holding
// go.mod.
func moduleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}

// isolatedEnv is the environment of the test process without anything that
// configures eictar: no EICTAR_* variable, and a HOME and XDG_CONFIG_HOME
// with no configuration file in them. A test must not depend on the
// configuration of whoever runs it (doc/design.md 11).
func isolatedEnv(tb testing.TB) []string {
	home := tb.TempDir()
	var out []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, "EICTAR_") || name == "HOME" || name == "XDG_CONFIG_HOME" {
			continue
		}
		out = append(out, kv)
	}
	return append(out, "HOME="+home, "XDG_CONFIG_HOME="+filepath.Join(home, ".config"))
}

// Result is the outcome of one eictar invocation.
type Result struct {
	ExitCode int
	Stdout   string
	Stderr   string
}

// Run executes the eictar binary with the given arguments in dir.
//
// It does not fail the test on a non-zero exit: an exit code is frequently
// what the caller is asserting on.
func Run(tb testing.TB, dir string, args ...string) Result {
	tb.Helper()
	return RunEnv(tb, dir, nil, args...)
}

// RunEnv is Run with extra environment variables, for the options that read
// one.
func RunEnv(tb testing.TB, dir string, env []string, args ...string) Result {
	tb.Helper()

	cmd := exec.Command(Binary(tb), args...)
	cmd.Dir = dir
	cmd.Env = append(isolatedEnv(tb), env...)

	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	res := Result{Stdout: stdout.String(), Stderr: stderr.String()}
	switch e := err.(type) {
	case nil:
	case *exec.ExitError:
		res.ExitCode = e.ExitCode()
	default:
		tb.Fatalf("testutil: running eictar %v: %v", args, err)
	}
	return res
}
