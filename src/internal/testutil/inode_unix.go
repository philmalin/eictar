//go:build unix

package testutil

import (
	"os"
	"syscall"
)

// inodeKey identifies a file by device and inode, which is how hardlinks are
// detected: two names for one inode.
type inodeKey struct {
	dev uint64
	ino uint64
}

// inodeOf returns the identity of fi, the file at path, and its link count.
// The final result reports whether the platform supplied the information at
// all.
func inodeOf(_ string, fi os.FileInfo) (inodeKey, uint64, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return inodeKey{}, 0, false
	}
	return inodeKey{dev: uint64(st.Dev), ino: uint64(st.Ino)}, uint64(st.Nlink), true
}
