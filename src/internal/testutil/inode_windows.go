package testutil

import (
	"os"

	"golang.org/x/sys/windows"
)

// inodeKey identifies a file by volume and file index, which is how
// hardlinks are detected: two names for one file.
type inodeKey struct {
	volume uint32
	index  uint64
}

// inodeOf returns the identity of fi, the file at path, and its link count.
// The FileInfo of Windows does not hold them, so it reads them from an open
// handle. The final result reports whether that worked.
func inodeOf(path string, _ os.FileInfo) (inodeKey, uint64, bool) {
	f, err := os.Open(path)
	if err != nil {
		return inodeKey{}, 0, false
	}
	defer f.Close()
	var d windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &d); err != nil {
		return inodeKey{}, 0, false
	}
	key := inodeKey{volume: d.VolumeSerialNumber, index: uint64(d.FileIndexHigh)<<32 | uint64(d.FileIndexLow)}
	return key, uint64(d.NumberOfLinks), true
}
