package archive

import (
	"errors"
	"fmt"
	"os"
)

// ErrLocked means another process is changing the archive. The caller does
// not wait: a backup job that waits can hang with no message, and the second
// of two overlapping jobs is better stopped with a clear error
// (doc/design.md 9.6).
var ErrLocked = errors.New("another eictar is changing this archive; try again when it has finished")

// lockArchive takes the writer's exclusive lock on f, the open archive at
// path, without waiting.
//
// A lock on a file is a lock on one inode, and a compact or a create renames
// a new inode over the path. A process that opened the path just before such
// a rename would lock the old, unlinked file, and whatever it wrote there
// would be lost. So once the lock is held, the path must still name the file
// that was locked.
func lockArchive(f *os.File, path string) error {
	if err := lockFile(f); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	held, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	now, err := os.Stat(path)
	if err != nil || !os.SameFile(held, now) {
		return fmt.Errorf("%s: %w (it was replaced while this run started)", path, ErrLocked)
	}
	return nil
}
