//go:build !windows

package archive

import (
	"errors"
	"io/fs"
	"os"
)

// openArchiveFile opens an existing archive. flag is os.O_RDONLY or
// os.O_RDWR.
func openArchiveFile(path string, flag int) (*os.File, error) {
	return os.OpenFile(path, flag, 0)
}

// renameOver renames oldpath to newpath, and replaces the file at newpath,
// which can be open.
func renameOver(oldpath, newpath string) error {
	return os.Rename(oldpath, newpath)
}

// hardLink is os.Link. A test replaces it, to be a file system with no hard
// links.
var hardLink = os.Link

// renameNew renames oldpath to newpath, and fails with an error that matches
// fs.ErrExist when newpath exists. link(2) makes the new name only when it
// is free, in one step that no other process can split; then the old name
// goes. A file system with no hard links (FAT, some FUSE file systems) gets
// a check and a rename, with a short window between them. When link(2)
// fails because newpath exists, the check finds it too.
func renameNew(oldpath, newpath string) error {
	err := hardLink(oldpath, newpath)
	if err == nil {
		return os.Remove(oldpath)
	}
	if _, err := os.Lstat(newpath); err == nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: fs.ErrExist}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return os.Rename(oldpath, newpath)
}
