package testutil

import "golang.org/x/sys/unix"

// FreeSpace returns the number of bytes free to an unprivileged user in the
// file system that holds path. The OpenBSD statfs fields have an F_ prefix.
func FreeSpace(path string) (int64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, err
	}
	return st.F_bavail * int64(st.F_bsize), nil
}
