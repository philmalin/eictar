//go:build unix

package testutil

import (
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// fillSys records ownership, allocation and user attributes for comparison.
func fillSys(e *Entry, path string, fi os.FileInfo) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		e.Blocks = int64(st.Blocks)
		e.UID, e.GID = st.Uid, st.Gid
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return
	}
	e.Xattrs = userXattrs(path)
}

// SetLinkTimes sets a symbolic link's own times, not its target's.
func (t *Tree) SetLinkTimes(rel string, atime, mtime time.Time) *Tree {
	t.tb.Helper()
	ts := []unix.Timespec{unix.NsecToTimespec(atime.UnixNano()), unix.NsecToTimespec(mtime.UnixNano())}
	if err := unix.UtimesNanoAt(unix.AT_FDCWD, t.Path(rel), ts, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		t.tb.Fatalf("testutil: setting link times on %s: %v", rel, err)
	}
	return t
}

// Holes reports whether a file in the tree has holes.
func (t *Tree) Holes(rel string) bool {
	fi, err := os.Stat(t.Path(rel))
	if err != nil {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Blocks*512 < fi.Size()
}
