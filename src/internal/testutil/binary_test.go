package testutil

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRemoveBinary: the directory of the binary goes, so that each run of
// the operational tests does not leave a binary in TMPDIR.
func TestRemoveBinary(t *testing.T) {
	bin := Binary(t)
	RemoveBinary()
	if _, err := os.Stat(filepath.Dir(bin)); !os.IsNotExist(err) {
		t.Errorf("the directory of the binary is still there: %v", err)
	}
}
