package archive

import (
	"runtime"
	"slices"
	"testing"
)

// TestTotalMemory: each supported platform (doc/design.md 15.1) reads the
// size of its RAM. Without it, the budget does not shrink on a small machine,
// and the check of the key derivation does nothing.
func TestTotalMemory(t *testing.T) {
	if !slices.Contains([]string{"linux", "darwin", "freebsd", "netbsd", "openbsd", "windows"}, runtime.GOOS) {
		t.Skipf("%s does not report its RAM", runtime.GOOS)
	}
	if ram := totalMemory(); ram < 256<<20 || ram > 1<<50 {
		t.Errorf("totalMemory() = %d, want the RAM of this machine", ram)
	}
}
