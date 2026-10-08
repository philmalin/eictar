//go:build windows

package archive

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// lockOffset is the byte that the lock covers: the last byte that a file
// offset can name, far past the end of any archive. A LockFileEx lock is
// mandatory: another handle cannot read or write the bytes it covers. A lock
// on byte 0, as before, stopped a second eictar from reading the header of
// an archive that another one was changing. On Unix, flock does not stop a
// reader, and a lock here does not either.
const lockOffset = 1<<63 - 1

// lockFile takes an exclusive LockFileEx lock on f without waiting. Windows
// releases it when the handle is closed or the process exits.
func lockFile(f *os.File) error {
	ol := windows.Overlapped{Offset: uint32(lockOffset & 0xffffffff), OffsetHigh: uint32(lockOffset >> 32)}
	err := windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, &ol)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return ErrLocked
	}
	if err != nil {
		return fmt.Errorf("locking: %w", err)
	}
	return nil
}
