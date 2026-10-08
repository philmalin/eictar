package pipeline

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/windows"
)

// createSpillFile creates a temporary file in dir that Windows deletes when
// its handle closes. Windows cannot delete an open file, so the unlink of
// the other platforms fails there. FILE_FLAG_DELETE_ON_CLOSE gives the same
// result: the process exit closes the handle, so a crash cannot leave the
// file behind.
func createSpillFile(dir string) (*os.File, error) {
	if dir == "" {
		dir = os.TempDir()
	}
	for range 100 {
		p := filepath.Join(dir, ".eictar-spool-"+strconv.FormatUint(rand.Uint64(), 36))
		name, err := windows.UTF16PtrFromString(p)
		if err != nil {
			return nil, fmt.Errorf("pipeline: creating spill file: %w", err)
		}
		h, err := windows.CreateFile(name,
			windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.CREATE_NEW,
			windows.FILE_ATTRIBUTE_TEMPORARY|windows.FILE_FLAG_DELETE_ON_CLOSE, 0)
		if errors.Is(err, windows.ERROR_FILE_EXISTS) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("pipeline: creating spill file: %w", &os.PathError{Op: "create", Path: p, Err: err})
		}
		return os.NewFile(uintptr(h), p), nil
	}
	return nil, fmt.Errorf("pipeline: creating spill file in %s: no free name", dir)
}
