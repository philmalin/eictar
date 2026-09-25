//go:build linux || darwin || freebsd || netbsd || openbsd

package meta

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// The metadata code for the UNIX-like platforms (doc/design.md 15.1). What
// differs between them is in sys_<os>.go (the stat fields, pipes and device
// nodes), xattr_*.go and holes_*.go.

// Stat extracts Info from a FileInfo produced by os.Stat or os.Lstat.
func Stat(fi fs.FileInfo) Info {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return Info{}
	}
	return statInfo(st)
}

// Mkfifo creates a named pipe as name inside the directory dir. dir must have
// come from os.Root, and name must be one path component: together those
// keep the operation inside the extraction root. A platform without mkfifoat
// returns ErrUnsupported: a path-based mkfifo could be redirected by a planted
// link (doc/design.md 7.6).
func Mkfifo(dir *os.File, name string, mode uint32) error {
	if err := oneComponent(name); err != nil {
		return err
	}
	return mkfifoat(int(dir.Fd()), name, mode&0o7777)
}

// Mknod creates a character or block device as name inside dir. A platform
// without mknodat returns ErrUnsupported, for the reason given at Mkfifo.
func Mknod(dir *os.File, name string, char bool, mode, major, minor uint32) error {
	if err := oneComponent(name); err != nil {
		return err
	}
	kind := uint32(unix.S_IFBLK)
	if char {
		kind = unix.S_IFCHR
	}
	return mknodat(int(dir.Fd()), name, kind|(mode&0o7777), unix.Mkdev(major, minor))
}

// SetLinkTimes sets the times of a symbolic link itself, not of what it
// points at. os.Chtimes and os.Root.Chtimes follow the link, which silently
// retimes the target; this is the call that does not.
func SetLinkTimes(dir *os.File, name string, atimeNanos, mtimeNanos int64) error {
	if err := oneComponent(name); err != nil {
		return err
	}
	ts := []unix.Timespec{unix.NsecToTimespec(atimeNanos), unix.NsecToTimespec(mtimeNanos)}
	return unix.UtimesNanoAt(int(dir.Fd()), name, ts, unix.AT_SYMLINK_NOFOLLOW)
}

// Lchown changes the owner of name inside dir without following a final
// symbolic link.
func Lchown(dir *os.File, name string, uid, gid uint32) error {
	if err := oneComponent(name); err != nil {
		return err
	}
	return unix.Fchownat(int(dir.Fd()), name, int(uid), int(gid), unix.AT_SYMLINK_NOFOLLOW)
}

// oneComponent refuses anything but a single, ordinary path component. The
// *at calls resolve name against dir, so a slash or a ".." would step out of
// the directory os.Root vouched for.
func oneComponent(name string) error {
	if name == "" || name == "." || name == ".." {
		return fmt.Errorf("meta: %q is not a file name", name)
	}
	for i := 0; i < len(name); i++ {
		if name[i] == '/' || name[i] == 0 {
			return fmt.Errorf("meta: %q is not a single path component", name)
		}
	}
	return nil
}

// growRead calls a size-then-fill style system call, growing the buffer if
// the value grew between the two calls.
func growRead(call func(buf []byte) (int, error)) ([]byte, error) {
	for range 8 {
		size, err := call(nil)
		if err != nil {
			return nil, err
		}
		if size == 0 {
			return nil, nil
		}
		buf := make([]byte, size)
		n, err := call(buf)
		if errors.Is(err, unix.ERANGE) {
			continue // it grew; ask again
		}
		if err != nil {
			return nil, err
		}
		return buf[:n], nil
	}
	return nil, fmt.Errorf("extended attribute kept changing size")
}

func isUnsupported(err error) bool {
	return errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP)
}
