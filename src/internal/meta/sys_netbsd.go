package meta

import (
	"syscall"

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

func mknodat(dirfd int, name string, mode uint32, dev uint64) error {
	return unix.Mknodat(dirfd, name, mode, int(dev))
}
