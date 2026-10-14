//go:build unix

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestGoCmdLeavesNothingRunning: a process that the command starts, and
// that would run for ever, stops with the command. A mutant can make the
// eictar binary of an operational test do that. The process writes elsewhere, as
// that binary writes to the pipes of its test, not to those of go test.
func TestGoCmdLeavesNothingRunning(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pid")
	cfg := config{goTool: "/bin/sh"}
	if _, err := goCmd(context.Background(), cfg, "-c", "sleep 300 >/dev/null 2>&1 & echo $! > "+pidFile); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { syscall.Kill(pid, syscall.SIGKILL) })
	for range 50 {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("the process %d that the command started still runs", pid)
}
