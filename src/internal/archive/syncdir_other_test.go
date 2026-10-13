//go:build !windows

package archive

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestSyncDirOfAMissingDirectory: the open fails, and says so.
func TestSyncDirOfAMissingDirectory(t *testing.T) {
	err := syncDir(filepath.Join(t.TempDir(), "missing"))
	if err == nil || !strings.HasPrefix(err.Error(), "opening ") {
		t.Errorf("%v, want the failure of the open", err)
	}
}
