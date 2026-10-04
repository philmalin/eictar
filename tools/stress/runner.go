//go:build unix

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// commandTimeout bounds one eictar command. A hang is a failure, not a wait.
const commandTimeout = 2 * time.Minute

// runner runs the eictar binary for one sequence, and keeps every command,
// so that a failure can be replayed by hand.
type runner struct {
	bin     string
	dir     string   // the sequence's directory: commands run here
	crypt   []string // the passphrase options, for an encrypted archive
	history []string // shell lines, for replay.sh
	calls   int

	// slow keeps the slowest commands of the run, and seed and profile say
	// where each one came from (slow.go).
	slow    *slowest
	seed    uint64
	profile string
}

type result struct {
	code           int
	stdout, stderr string
	args           []string
}

func (r result) String() string {
	return fmt.Sprintf("eictar %s\n  exit %d\n  stdout: %s\n  stderr: %s",
		shellJoin(r.args), r.code, clip(r.stdout), clip(r.stderr))
}

func clip(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 2000 {
		s = s[:2000] + " ..."
	}
	return s
}

// run runs eictar with args, and --no-config, so that the tester's own
// configuration file or EICTAR_* variables cannot change what it tests.
// withKey adds the passphrase options.
func (r *runner) run(withKey bool, args ...string) (result, error) {
	// The options go first: the arguments can end with "--" and paths.
	full := []string{"--no-config"}
	if withKey {
		full = append(full, r.crypt...)
	}
	full = append(full, args...)
	r.history = append(r.history, "eictar "+shellJoin(full))
	r.calls++

	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.bin, full...)
	cmd.Dir = r.dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	began := time.Now()
	err := cmd.Run()
	took := time.Since(began)

	res := result{stdout: stdout.String(), stderr: stderr.String(), args: full}
	var exit *exec.ExitError
	switch {
	case ctx.Err() != nil:
		return res, fmt.Errorf("hung for %v:\n%s", commandTimeout, res)
	case errors.As(err, &exit):
		res.code = exit.ExitCode()
	case err != nil:
		return res, fmt.Errorf("could not run eictar: %w", err)
	}
	r.record(full, took)
	// A panic or a runtime error is a failure whatever the exit code.
	if strings.Contains(res.stderr, "panic:") || strings.Contains(res.stderr, "fatal error:") {
		return res, fmt.Errorf("eictar crashed:\n%s", res)
	}
	return res, nil
}

// expect runs a command that must succeed.
func (r *runner) expect(withKey bool, args ...string) (result, error) {
	res, err := r.run(withKey, args...)
	if err != nil {
		return res, err
	}
	if res.code != 0 {
		return res, fmt.Errorf("exit %d, want 0:\n%s", res.code, res)
	}
	return res, nil
}

// writeReplay saves the commands so far as a shell script.
func (r *runner) writeReplay() error {
	var b strings.Builder
	b.WriteString("#!/bin/sh\n# The eictar commands of a failed stress sequence, in order.\n")
	b.WriteString("# The source tree they read is in src/, as it was at the failure.\n")
	fmt.Fprintf(&b, "set -x\ncd %s\n", shellQuote(r.dir))
	fmt.Fprintf(&b, "eictar() { %s \"$@\"; }\n", shellQuote(r.bin))
	for _, line := range r.history {
		b.WriteString(line + "\n")
	}
	return os.WriteFile(filepath.Join(r.dir, "replay.sh"), []byte(b.String()), 0o755)
}

func shellJoin(args []string) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = shellQuote(a)
	}
	return strings.Join(q, " ")
}

func shellQuote(s string) string {
	if s != "" && strings.IndexFunc(s, func(r rune) bool {
		return !(r == '-' || r == '_' || r == '.' || r == '/' || r == '=' || r == ':' || r == ',' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'))
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
