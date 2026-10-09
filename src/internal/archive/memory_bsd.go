//go:build darwin || freebsd || netbsd || openbsd

package archive

import (
	"runtime"

	"golang.org/x/sys/unix"
)

// totalMemory returns the machine's RAM in bytes from sysctl, or 0 when it
// cannot be read. The budget falls back to a worker-count figure then.
func totalMemory() int64 {
	name := "hw.physmem64" // NetBSD asks the kernel for the MIB of a name
	switch runtime.GOOS {
	case "darwin":
		name = "hw.memsize"
	case "freebsd":
		name = "hw.physmem"
	case "openbsd":
		// x/sys/unix finds an OpenBSD name in its own table, which has no
		// hw.physmem64. Its hw.physmem is MIB {6, 19}, which is
		// HW_PHYSMEM64 in OpenBSD's sysctl.h.
		name = "hw.physmem"
	}
	n, err := unix.SysctlUint64(name)
	if err != nil {
		return 0
	}
	return int64(n)
}
