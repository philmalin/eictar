//go:build unix

package testutil

import (
	"path/filepath"
	"testing"
)

// TestFreeSpace checks that each platform reads the free space of a file
// system, and gives an error for a path that does not exist.
func TestFreeSpace(t *testing.T) {
	dir := t.TempDir()
	free, err := FreeSpace(dir)
	if err != nil {
		t.Fatal(err)
	}
	if free <= 0 {
		t.Fatalf("FreeSpace(%s) = %d; want more than 0", dir, free)
	}
	if _, err := FreeSpace(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("FreeSpace of a missing path: no error")
	}
}
