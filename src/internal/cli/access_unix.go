//go:build unix

package cli

import (
	"fmt"
	"os"
	"syscall"
)

// checkConfigOwner refuses a configuration file that another user owns, or
// that the group or other users can write (doc/design.md 11.4). root may own
// it, for a file that an administrator installs.
func checkConfigOwner(_ *os.File, fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if uid := int(st.Uid); uid != os.Geteuid() && uid != 0 {
		return fmt.Errorf("it is owned by uid %d, not by you; refusing to use it", st.Uid)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("the group or other users can write it (mode %04o); refusing to use it", fi.Mode().Perm())
	}
	return nil
}

// passphraseFileExposure gives the warning for a passphrase file that other
// users can read, or "" (doc/Security_Audit.md, finding 8).
func passphraseFileExposure(path string) string {
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm()&0o044 == 0 {
		return ""
	}
	return fmt.Sprintf("%s can be read by other users (mode %04o); chmod 600 it", path, fi.Mode().Perm())
}
