//go:build unix

package testutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBindSocketInALongDirectory: where mknod cannot make a socket (macOS,
// the BSDs), the fixture binds one. The CI runner's temporary directories are
// longer than sun_path allows, so the bind must work from inside the
// directory. This runs on Linux too, where Socket itself never needs it.
func TestBindSocketInALongDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), strings.Repeat("d", 60), strings.Repeat("e", 60))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "sock")
	if len(p) <= 108 {
		t.Fatalf("the path is %d bytes; the test needs one longer than sun_path", len(p))
	}
	cwd, _ := os.Getwd()

	if err := bindSocket(t, p); err != nil {
		t.Fatalf("bindSocket: %v", err)
	}
	fi, err := os.Lstat(p)
	if err != nil || fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("no socket at %s: %v", p, err)
	}
	if now, _ := os.Getwd(); now != cwd {
		t.Errorf("the working directory is %s, want it back at %s", now, cwd)
	}
}
