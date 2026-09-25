package meta

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

var errNoAttr = unix.ENOATTR

// Supports is this platform's row of the table in doc/design.md 15.1.
var Supports = Capabilities{Metadata: true, Xattrs: true, Holes: true, Fifos: true, Devices: true}

func statInfo(st *syscall.Stat_t) Info {
	return Info{
		Dev: st.Dev, Ino: st.Ino, Nlink: st.Nlink,
		UID: st.Uid, GID: st.Gid,
		Major: unix.Major(st.Rdev), Minor: unix.Minor(st.Rdev),
		ATimeNanos: st.Atimespec.Nano(), MTimeNanos: st.Mtimespec.Nano(),
		Blocks: st.Blocks, OK: true,
	}
}

// mkfifoat is system call 497 on FreeBSD. x/sys has the number but no
// wrapper.
func mkfifoat(dirfd int, name string, mode uint32) error {
	p, err := unix.BytePtrFromString(name)
	if err != nil {
		return err
	}
	_, _, errno := unix.Syscall(unix.SYS_MKFIFOAT, uintptr(dirfd), uintptr(unsafe.Pointer(p)), uintptr(mode))
	if errno != 0 {
		return errno
	}
	return nil
}

func mknodat(dirfd int, name string, mode uint32, dev uint64) error {
	return unix.Mknodat(dirfd, name, mode, dev)
}
