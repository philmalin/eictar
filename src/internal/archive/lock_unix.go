//go:build unix && !aix

package archive

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// lockFile takes an exclusive flock(2) on f without waiting. The kernel
// releases it when f is closed, and when the process dies, so a crash leaves
// no stale lock behind.
func lockFile(f *os.File) error {
	err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) {
		return ErrLocked
	}
	if err != nil {
		return fmt.Errorf("locking: %w", err)
	}
	return nil
}
