package meta

import (
	"syscall"

	"golang.org/x/sys/unix"
)

var errNoAttr = unix.ENOATTR

// Supports is this platform's row of the table in doc/design.md 15.1.
var Supports = Capabilities{Metadata: true, Xattrs: true, Holes: true}

func statInfo(st *syscall.Stat_t) Info {
	rdev := uint64(uint32(st.Rdev))
	return Info{
		Dev: uint64(uint32(st.Dev)), Ino: st.Ino, Nlink: uint64(st.Nlink),
		UID: st.Uid, GID: st.Gid,
		Major: unix.Major(rdev), Minor: unix.Minor(rdev),
		ATimeNanos: st.Atimespec.Nano(), MTimeNanos: st.Mtimespec.Nano(),
		Blocks: st.Blocks, OK: true, HasID: true,
	}
}

// macOS has mkfifoat and mknodat since 13, but x/sys does not wrap them, and
// a path-based call can be redirected by a planted link (doc/design.md 15.1).
// Extraction skips pipes and device nodes here, with a notice.
func mkfifoat(int, string, uint32) error        { return ErrUnsupported }
func mknodat(int, string, uint32, uint64) error { return ErrUnsupported }
