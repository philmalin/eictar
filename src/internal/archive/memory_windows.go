//go:build windows

package archive

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// memoryStatusEx is MEMORYSTATUSEX. x/sys/windows does not wrap
// GlobalMemoryStatusEx.
type memoryStatusEx struct {
	length               uint32
	memoryLoad           uint32
	totalPhys            uint64
	availPhys            uint64
	totalPageFile        uint64
	availPageFile        uint64
	totalVirtual         uint64
	availVirtual         uint64
	availExtendedVirtual uint64
}

var procGlobalMemoryStatusEx = windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalMemoryStatusEx")

// totalMemory returns the machine's RAM in bytes from GlobalMemoryStatusEx,
// or 0 when it cannot be read. The budget falls back to a worker-count
// figure then.
func totalMemory() int64 {
	st := memoryStatusEx{length: uint32(unsafe.Sizeof(memoryStatusEx{}))}
	if r, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&st))); r == 0 {
		return 0
	}
	return int64(st.totalPhys)
}
