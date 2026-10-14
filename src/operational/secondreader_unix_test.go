//go:build operational && unix

package operational

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// specialFiles adds a named pipe and a sparse file to dir.
func specialFiles(t *testing.T, dir string) {
	t.Helper()
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe"), 0o640); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(dir, "sparse.bin"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, off := range []int64{0, 1 << 20, 3 << 20} {
		if _, err := f.WriteAt([]byte("data in a sparse file"), off); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Truncate(5 << 20); err != nil {
		t.Fatal(err)
	}
}
