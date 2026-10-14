//go:build faultinject

package archive

// Faults for the stress tester (doc/design.md 13.5, step 3). A binary built
// with -tags faultinject makes one operation on an archive file fail, as
// EICTAR_FAULT says: KIND:N makes the Nth operation of that kind fail with
// EIO. KIND is one of
//
//	open create write short sync truncate close rename remove syncdir
//
// short is a write: half of the bytes reach the file, and it fails with
// ENOSPC. The Nth write is counted for write and for short alike. When the
// fault happens, a line on stderr says so, for the tester:
//
//	eictar-fault: write 3
//
// A release binary has none of this: it is not built with the tag.

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

func init() {
	spec := os.Getenv("EICTAR_FAULT")
	if spec == "" {
		return
	}
	kind, n, ok := strings.Cut(spec, ":")
	at, err := strconv.Atoi(n)
	if !ok || err != nil || at < 1 || !faultKinds[kind] {
		fmt.Fprintf(os.Stderr, "eictar-fault: EICTAR_FAULT=%q: want KIND:N\n", spec)
		os.Exit(70)
	}
	fsys = &injectFS{fs: fsys, kind: kind, at: at, counts: map[string]int{}}
}

var faultKinds = map[string]bool{
	"open": true, "create": true, "write": true, "short": true, "sync": true,
	"truncate": true, "close": true, "rename": true, "remove": true, "syncdir": true,
}

// injectFS counts the operations of each kind, and makes the chosen one fail.
type injectFS struct {
	fs     fileSystem
	kind   string
	at     int
	mu     sync.Mutex
	counts map[string]int
}

// fail counts an operation of kind, and reports whether it is the one to
// fail. short counts as a write.
func (f *injectFS) fail(kind string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.counts[kind]++
	want := f.kind
	if want == "short" {
		want = "write"
	}
	if kind != want || f.counts[kind] != f.at {
		return false
	}
	fmt.Fprintf(os.Stderr, "eictar-fault: %s %d\n", f.kind, f.at)
	return true
}

func (f *injectFS) OpenArchive(path string, flag int) (archiveFile, error) {
	if f.fail("open") {
		return nil, &os.PathError{Op: "open", Path: path, Err: syscall.EIO}
	}
	af, err := f.fs.OpenArchive(path, flag)
	if err != nil {
		return nil, err
	}
	return &injectFile{archiveFile: af, fs: f}, nil
}

func (f *injectFS) CreateNew(path string, perm os.FileMode) (archiveFile, error) {
	if f.fail("create") {
		return nil, &os.PathError{Op: "open", Path: path, Err: syscall.EIO}
	}
	af, err := f.fs.CreateNew(path, perm)
	if err != nil {
		return nil, err
	}
	return &injectFile{archiveFile: af, fs: f}, nil
}

func (f *injectFS) CreateTemp(dir, pattern string) (archiveFile, error) {
	if f.fail("create") {
		return nil, &os.PathError{Op: "createtemp", Path: dir, Err: syscall.EIO}
	}
	af, err := f.fs.CreateTemp(dir, pattern)
	if err != nil {
		return nil, err
	}
	return &injectFile{archiveFile: af, fs: f}, nil
}

func (f *injectFS) Rename(oldpath, newpath string) error {
	if f.fail("rename") {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: syscall.EIO}
	}
	return f.fs.Rename(oldpath, newpath)
}

func (f *injectFS) Remove(path string) error {
	if f.fail("remove") {
		return &os.PathError{Op: "remove", Path: path, Err: syscall.EIO}
	}
	return f.fs.Remove(path)
}

func (f *injectFS) SyncDir(dir string) error {
	if f.fail("syncdir") {
		return &os.PathError{Op: "sync", Path: dir, Err: syscall.EIO}
	}
	return f.fs.SyncDir(dir)
}

// injectFile is an archive file whose operations count.
type injectFile struct {
	archiveFile
	fs *injectFS
}

func (f *injectFile) Write(p []byte) (int, error) {
	if !f.fs.fail("write") {
		return f.archiveFile.Write(p)
	}
	if f.fs.kind == "short" {
		n, _ := f.archiveFile.Write(p[:len(p)/2])
		return n, &os.PathError{Op: "write", Path: f.Name(), Err: syscall.ENOSPC}
	}
	return 0, &os.PathError{Op: "write", Path: f.Name(), Err: syscall.EIO}
}

func (f *injectFile) Sync() error {
	if f.fs.fail("sync") {
		return &os.PathError{Op: "sync", Path: f.Name(), Err: syscall.EIO}
	}
	return f.archiveFile.Sync()
}

func (f *injectFile) Truncate(size int64) error {
	if f.fs.fail("truncate") {
		return &os.PathError{Op: "truncate", Path: f.Name(), Err: syscall.EIO}
	}
	return f.archiveFile.Truncate(size)
}

func (f *injectFile) Close() error {
	if f.fs.fail("close") {
		f.archiveFile.Close()
		return &os.PathError{Op: "close", Path: f.Name(), Err: syscall.EIO}
	}
	return f.archiveFile.Close()
}
