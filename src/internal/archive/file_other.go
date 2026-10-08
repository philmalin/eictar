//go:build !windows

package archive

import "os"

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
