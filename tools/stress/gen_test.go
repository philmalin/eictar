//go:build unix

package main

import (
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"
)

// TestNewPathSkipsATakenName makes the entry that a seed names first, then
// asks for a new path with the same seed. An 8-hour run failed when two
// entries of one directory drew the same name.
func TestNewPathSkipsATakenName(t *testing.T) {
	src := t.TempDir()
	for _, sub := range []string{".", "sub"} {
		taken := newGen(rand.New(rand.NewPCG(1, 2)), src, "small").newPath(sub)
		if err := os.MkdirAll(filepath.Join(src, taken), 0o755); err != nil {
			t.Fatal(err)
		}
		got := newGen(rand.New(rand.NewPCG(1, 2)), src, "small").newPath(sub)
		if got == taken {
			t.Errorf("newPath(%q) = %q, which is taken", sub, got)
		}
		if filepath.Dir(got) != filepath.Clean(sub) {
			t.Errorf("newPath(%q) = %q, not in %q", sub, got, sub)
		}
	}
}
