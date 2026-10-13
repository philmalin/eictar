//go:build unix && !aix

package archive

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestLockFileFails: a lock that fails for another reason than a lock that
// is held is that error, not ErrLocked.
func TestLockFileFails(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "a.ect"))
	if err != nil {
		t.Fatal(err)
	}
	f.Close() // its descriptor is no longer valid
	if err := lockFile(f); err == nil || errors.Is(err, ErrLocked) {
		t.Errorf("a closed file: %v, want the error of flock", err)
	}
}
