//go:build linux

package archive

import (
	"strings"
	"testing"
)

// TestMemTotal: the MemTotal line, in KiB, and 0 for a file without one
// that can be read.
func TestMemTotal(t *testing.T) {
	for in, want := range map[string]int64{
		"MemFree:  100 kB\nMemTotal: 8 kB\n": 8 << 10,
		"MemTotal: 16\n":                     16 << 10,
		"MemTotal:\n":                        0,
		"MemTotal: lots kB\n":                0,
		"MemFree:  100 kB\n":                 0,
	} {
		if got := memTotal(strings.NewReader(in)); got != want {
			t.Errorf("%q: %d, want %d", in, got, want)
		}
	}
}
