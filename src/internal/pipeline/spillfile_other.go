//go:build !windows

package pipeline

import (
	"fmt"
	"os"
)

// createSpillFile creates a temporary file in dir and unlinks it at once.
// The file stays usable through the descriptor, and a crash cannot leave it
// behind.
func createSpillFile(dir string) (*os.File, error) {
	f, err := os.CreateTemp(dir, ".eictar-spool-*")
	if err != nil {
		return nil, fmt.Errorf("pipeline: creating spill file: %w", err)
	}
	if err := os.Remove(f.Name()); err != nil {
		f.Close()
		return nil, fmt.Errorf("pipeline: unlinking spill file: %w", err)
	}
	return f, nil
}
