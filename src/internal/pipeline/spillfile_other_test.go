//go:build !windows

package pipeline

import (
	"errors"
	"os"
	"testing"
)

// TestSpillFileUnlinkFails: a spill file that cannot be unlinked is an error.
// A spill file left in the directory would keep a copy of the data after the
// run.
func TestSpillFileUnlinkFails(t *testing.T) {
	failed := errors.New("unlink failed")
	removeSpillFile = func(string) error { return failed }
	defer func() { removeSpillFile = os.Remove }()
	if f, err := createSpillFile(t.TempDir()); !errors.Is(err, failed) {
		if f != nil {
			f.Close()
		}
		t.Fatalf("got %v, want the unlink error", err)
	}
}
