//go:build darwin || freebsd || netbsd || openbsd

package archive

import (
	"runtime"

	"golang.org/x/sys/unix"
)

// totalMemory returns the machine's RAM in bytes from sysctl, or 0 when it
// cannot be read. The budget falls back to a worker-count figure then.
func totalMemory() int64 {
	name := "hw.physmem64" // NetBSD, OpenBSD
	switch runtime.GOOS {
	case "darwin":
		name = "hw.memsize"
	case "freebsd":
		name = "hw.physmem"
	}
	n, err := unix.SysctlUint64(name)
	if err != nil {
		return 0
	}
	return int64(n)
}
