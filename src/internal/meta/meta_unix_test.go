//go:build linux || darwin || freebsd || netbsd || openbsd

package meta

import (
	"io/fs"
	"testing"
)

// TestMayFollow is the rule of fs.protected_symlinks (doc/Security_Audit.md,
// finding 4), for users that a test cannot be.
func TestMayFollow(t *testing.T) {
	sticky := fs.ModeDir | fs.ModeSticky | 0o777
	for _, tc := range []struct {
		name                 string
		dirMode              fs.FileMode
		linkUID, dirUID, uid uint32
		want                 bool
	}{
		{"/tmp, a link of another user", sticky, 1001, 0, 1000, false},
		{"/tmp, a link of root, for a user", sticky, 0, 0, 1000, true}, // the directory's owner
		{"/tmp, one's own link", sticky, 1000, 0, 1000, true},
		{"a private directory", fs.ModeDir | 0o755, 1001, 1001, 1000, true},
		{"world-writable, not sticky", fs.ModeDir | 0o777, 1001, 0, 1000, true},
	} {
		if got := mayFollow(tc.dirMode, tc.linkUID, tc.dirUID, tc.uid); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}
