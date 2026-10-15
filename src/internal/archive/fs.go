package archive

import (
	"io"
	"os"
)

// archiveFile is an archive file as the reader and the writer use it: an
// archive that is read or appended to, the temporary file of a create or of a
// rewrite, and the file that a create replaces. In production it is an
// *os.File. The fault tests wrap one, to make an operation fail and to
// record what reaches the disk (doc/testing.md 5, step 3).
type archiveFile interface {
	io.Reader
	io.Writer
	io.ReaderAt
	io.Seeker
	Sync() error
	Truncate(size int64) error
	Stat() (os.FileInfo, error)
	Chmod(mode os.FileMode) error
	Chown(uid, gid int) error
	Close() error
	Name() string
	// Fd is for the lock (lockFile).
	Fd() uintptr
}

// fileSystem holds the operations on archive files and on the directory that
// holds them. Each change that the program makes to an archive goes through
// it, so that a test can make any one of them fail.
type fileSystem interface {
	// OpenArchive opens an existing archive. flag is os.O_RDONLY or
	// os.O_RDWR.
	OpenArchive(path string, flag int) (archiveFile, error)
	// CreateNew makes a file that must not exist, open for writing, with
	// perm less the umask.
	CreateNew(path string, perm os.FileMode) (archiveFile, error)
	// CreateTemp makes a temporary file, as os.CreateTemp does.
	CreateTemp(dir, pattern string) (archiveFile, error)
	// Rename renames oldpath to newpath. With replace, it replaces the file at
	// newpath, which can be open. Without it, it fails with an error that
	// matches fs.ErrExist when newpath exists, and replaces nothing.
	Rename(oldpath, newpath string, replace bool) error
	Remove(path string) error
	// SyncDir makes a rename in dir durable.
	SyncDir(dir string) error
}

// fsys is the file system of the archive files. Only the fault tests change
// it.
var fsys fileSystem = osFS{}

// osFS is the file system of the operating system.
type osFS struct{}

func (osFS) OpenArchive(path string, flag int) (archiveFile, error) {
	f, err := openArchiveFile(path, flag)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (osFS) CreateNew(path string, perm os.FileMode) (archiveFile, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (osFS) CreateTemp(dir, pattern string) (archiveFile, error) {
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (osFS) Rename(oldpath, newpath string, replace bool) error {
	if replace {
		return renameOver(oldpath, newpath)
	}
	return renameNew(oldpath, newpath)
}
func (osFS) Remove(path string) error { return os.Remove(path) }
func (osFS) SyncDir(dir string) error { return syncDir(dir) }
