//go:build unix

package ect

import (
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// linkTimes sets the times of the symbolic link p, through the directory
// that holds it, because os.Root.Chtimes follows a link.
func linkTimes(root *os.Root, p string, atime, mtime time.Time) error {
	dir, base := filepath.Split(p)
	if dir == "" {
		dir = "."
	}
	d, err := root.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	ts := []unix.Timespec{unix.NsecToTimespec(atime.UnixNano()), unix.NsecToTimespec(mtime.UnixNano())}
	return unix.UtimesNanoAt(int(d.Fd()), base, ts, unix.AT_SYMLINK_NOFOLLOW)
}
