//go:build netbsd || solaris || illumos

package testutil

import "golang.org/x/sys/unix"

// FreeSpace returns the number of bytes free to an unprivileged user in the
// file system that holds path. These systems have statvfs, not statfs.
func FreeSpace(path string) (int64, error) {
	var st unix.Statvfs_t
	if err := unix.Statvfs(path, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Frsize), nil
}
