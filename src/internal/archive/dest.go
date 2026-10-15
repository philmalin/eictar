package archive

import (
	"io"
	"io/fs"
	"os"
	"time"

	"github.com/philmalin/eictar/src/internal/meta"
)

// destDir is a directory of the destination of an extraction: the
// destination itself, or a directory below it that a worker opened. In
// production it is an *os.Root, so that no name can lead out of the
// destination. The fault tests wrap one, to make an operation fail
// (doc/testing.md 5, step 3).
type destDir interface {
	MkdirAll(name string, perm fs.FileMode) error
	// Open opens a directory or a file to read, and to change its metadata.
	Open(name string) (destFile, error)
	OpenRoot(name string) (destDir, error)
	OpenFile(name string, flag int, perm fs.FileMode) (destFile, error)
	Lstat(name string) (fs.FileInfo, error)
	Lchown(name string, uid, gid int) error
	Chmod(name string, mode fs.FileMode) error
	Chtimes(name string, atime, mtime time.Time) error
	Symlink(oldname, newname string) error
	Link(oldname, newname string) error
	Remove(name string) error
	Rename(oldname, newname string) error
	Close() error
}

// destFile is a file that an extraction writes.
type destFile interface {
	io.Writer
	io.WriterAt
	Truncate(size int64) error
	Chown(uid, gid int) error
	Chmod(mode fs.FileMode) error
	Close() error
	// file gives the *os.File, for the extended attributes, which meta sets
	// on the descriptor.
	file() *os.File
}

// The calls of meta that an extraction makes on a descriptor: a call on the
// descriptor of a directory, with one name, cannot be sent out of it by a
// link. The fault tests replace them.
var (
	mkfifo       = meta.Mkfifo
	mknod        = meta.Mknod
	setLinkTimes = meta.SetLinkTimes
	setXattr     = meta.SetXattr
)

// openDest opens the destination of an extraction. Only the fault tests
// change it.
var openDest = func(dir string) (destDir, error) {
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return osDest{r}, nil
}

// osDest is a directory of the destination on the disk.
type osDest struct{ *os.Root }

func (d osDest) OpenRoot(name string) (destDir, error) {
	r, err := d.Root.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return osDest{r}, nil
}

func (d osDest) Open(name string) (destFile, error) {
	f, err := d.Root.Open(name)
	if err != nil {
		return nil, err
	}
	return osDestFile{f}, nil
}

func (d osDest) OpenFile(name string, flag int, perm fs.FileMode) (destFile, error) {
	f, err := d.Root.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return osDestFile{f}, nil
}

// osDestFile is a file of the destination on the disk.
type osDestFile struct{ *os.File }

func (f osDestFile) file() *os.File { return f.File }
