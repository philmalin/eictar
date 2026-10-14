//go:build unix

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// ownedBy is a FileInfo with another owner.
type ownedBy struct {
	os.FileInfo
	st syscall.Stat_t
}

func (o ownedBy) Sys() any { return &o.st }

// TestConfigOwner: a file of the user or of root is used, and one of any
// other user is refused.
func TestConfigOwner(t *testing.T) {
	p := filepath.Join(t.TempDir(), "rc")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	st := *fi.Sys().(*syscall.Stat_t)
	for uid, refused := range map[int]bool{os.Geteuid(): false, 0: false, os.Geteuid() + 4242: true} {
		st.Uid = uint32(uid)
		err := checkConfigOwner(nil, ownedBy{fi, st})
		if (err != nil) != refused || (err != nil && !strings.Contains(err.Error(), "not by you")) {
			t.Errorf("uid %d: %v; refused: %v", uid, err, refused)
		}
	}
}
