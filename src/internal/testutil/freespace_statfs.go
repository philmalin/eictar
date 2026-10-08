//go:build linux || darwin || freebsd || dragonfly || aix

package testutil

import "golang.org/x/sys/unix"

// FreeSpace returns the number of bytes free to an unprivileged user in the
// file system that holds path.
func FreeSpace(path string) (int64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), nil
}
