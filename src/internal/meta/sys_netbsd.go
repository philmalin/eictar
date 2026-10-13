package meta

import (
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

var errNoAttr = unix.ENOATTR

// Supports is this platform's row of the table in doc/design.md 15.1.
var Supports = Capabilities{Metadata: true, Xattrs: true, Fifos: true, Devices: true}

func statInfo(st *syscall.Stat_t) Info {
	return Info{
		Dev: st.Dev, Ino: st.Ino, Nlink: uint64(st.Nlink),
		UID: st.Uid, GID: st.Gid,
		Major: unix.Major(st.Rdev), Minor: unix.Minor(st.Rdev),
		ATimeNanos: st.Atimespec.Nano(), MTimeNanos: st.Mtimespec.Nano(),
		Blocks: st.Blocks, OK: true, HasID: true,
	}
}

func mkfifoat(dirfd int, name string, mode uint32) error {
	return unix.Mkfifoat(dirfd, name, mode)
}

// mknodat makes the system call itself. NetBSD declares it as mknodat(int fd,
// const char *path, mode_t mode, int PAD, dev_t dev), and unix.Mknodat puts
// dev where the padding is: the kernel then read 0, and each device node
// was 0:0 (TestMknodAsRoot, as root). A 64-bit dev_t takes two words on a
// 32-bit platform, low word first.
func mknodat(dirfd int, name string, mode uint32, dev uint64) error {
	p, err := unix.BytePtrFromString(name)
	if err != nil {
		return err
	}
	high := uintptr(0)
	if unsafe.Sizeof(uintptr(0)) == 4 {
		high = uintptr(dev >> 32)
	}
	_, _, e := unix.Syscall6(unix.SYS_MKNODAT, uintptr(dirfd), uintptr(unsafe.Pointer(p)), uintptr(mode), 0, uintptr(dev), high)
	runtime.KeepAlive(p)
	if e != 0 {
		return e
	}
	return nil
}
