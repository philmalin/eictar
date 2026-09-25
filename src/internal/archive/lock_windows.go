//go:build windows

package archive

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// lockFile takes an exclusive LockFileEx lock on f without waiting. Windows
// releases it when the handle is closed or the process exits.
func lockFile(f *os.File) error {
	var ol windows.Overlapped
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
