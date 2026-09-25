package meta

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// Supports is this platform's row of the table in doc/design.md 15.1.
var Supports = Capabilities{Metadata: true, Fifos: true, Devices: true}

func statInfo(st *syscall.Stat_t) Info {
	rdev := uint64(uint32(st.Rdev))
	return Info{
		Dev: uint64(uint32(st.Dev)), Ino: st.Ino, Nlink: uint64(st.Nlink),
		UID: st.Uid, GID: st.Gid,
		Major: unix.Major(rdev), Minor: unix.Minor(rdev),
		ATimeNanos: st.Atim.Nano(), MTimeNanos: st.Mtim.Nano(),
		Blocks: st.Blocks, OK: true,
	}
}

func mkfifoat(dirfd int, name string, mode uint32) error {
	return unix.Mkfifoat(dirfd, name, mode)
}

func mknodat(dirfd int, name string, mode uint32, dev uint64) error {
	return unix.Mknodat(dirfd, name, mode, int(dev))
}
