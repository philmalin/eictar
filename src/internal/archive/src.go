package archive

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/philmalin/eictar/src/internal/meta"
)

// srcDir is a directory of a tree that a create, an append, a --diff or the
// training of a dictionary walks. In production it is an *os.Root: each
// entry is found through the directory that holds it, by its name alone
// (doc/Security_Audit.md, finding 11). The fault tests wrap one, to make an
// operation fail (doc/design.md 13.5, step 3).
type srcDir interface {
	Lstat(name string) (fs.FileInfo, error)
	Stat(name string) (fs.FileInfo, error)
	Readlink(name string) (string, error)
	OpenRoot(name string) (srcDir, error)
	Open(name string) (srcFile, error)
	OpenFile(name string, flag int, perm fs.FileMode) (srcFile, error)
	Close() error
}

// srcFile is a file or a directory of the tree, open to read.
type srcFile interface {
	io.Reader
	io.ReaderAt
	Stat() (fs.FileInfo, error)
	ReadDir(n int) ([]fs.DirEntry, error)
	Close() error
	// file gives the *os.File, for the calls of meta on the descriptor:
	// the holes and the extended attributes.
	file() *os.File
}

// srcPathFS holds the operations on the paths that a walk reaches by their
// path: a requested path, the parent that it opens, and a link that -h
// follows.
type srcPathFS interface {
	Lstat(path string) (fs.FileInfo, error)
	Stat(path string) (fs.FileInfo, error)
	Readlink(path string) (string, error)
	OpenRoot(path string) (srcDir, error)
	Open(path string) (srcFile, error)
	// OpenNoFollow opens a file, and refuses a symbolic link.
	OpenNoFollow(path string) (srcFile, error)
	// EvalSymlinks gives path with its links resolved, as
	// filepath.EvalSymlinks.
	EvalSymlinks(path string) (string, error)
}

// srcPaths is the file system of the paths of a walk. Only the fault tests
// change it.
var srcPaths srcPathFS = osSrcPaths{}

// The calls of meta that a walk makes on a descriptor or a path. The fault
// tests replace them.
var (
	dataSegments   = meta.DataSegments
	readXattrsFile = meta.ReadXattrsFile
	readXattrsPath = meta.ReadXattrs
)

// osSrcPaths is the operating system.
type osSrcPaths struct{}

func (osSrcPaths) Lstat(path string) (fs.FileInfo, error)   { return os.Lstat(path) }
func (osSrcPaths) Stat(path string) (fs.FileInfo, error)    { return os.Stat(path) }
func (osSrcPaths) Readlink(path string) (string, error)     { return os.Readlink(path) }
func (osSrcPaths) EvalSymlinks(path string) (string, error) { return filepath.EvalSymlinks(path) }

func (osSrcPaths) OpenRoot(path string) (srcDir, error) {
	r, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	return osSrc{r}, nil
}

func (osSrcPaths) Open(path string) (srcFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return osSrcFile{f}, nil
}

func (osSrcPaths) OpenNoFollow(path string) (srcFile, error) {
	f, err := meta.OpenNoFollow(path)
	if err != nil {
		return nil, err
	}
	return osSrcFile{f}, nil
}

// osSrc is a directory of the tree on the disk.
type osSrc struct{ *os.Root }

func (d osSrc) OpenRoot(name string) (srcDir, error) {
	r, err := d.Root.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return osSrc{r}, nil
}

func (d osSrc) Open(name string) (srcFile, error) {
	f, err := d.Root.Open(name)
	if err != nil {
		return nil, err
	}
	return osSrcFile{f}, nil
}

func (d osSrc) OpenFile(name string, flag int, perm fs.FileMode) (srcFile, error) {
	f, err := d.Root.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return osSrcFile{f}, nil
}

// osSrcFile is a file of the tree on the disk.
type osSrcFile struct{ *os.File }

func (f osSrcFile) file() *os.File { return f.File }
