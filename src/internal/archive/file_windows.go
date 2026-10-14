package archive

import (
	"errors"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows does not let a rename replace a file that is open, and os.OpenFile
// gives no handle that allows it. A create, a compact and a change of the
// passphrase rename a new archive over the old one while the old one is open
// and locked. So on Windows, each archive handle is opened with
// FILE_SHARE_DELETE, and the rename uses POSIX semantics: the old file goes
// away from the directory, as on Unix, and stays readable through the open
// handles.

// openArchiveFile opens an existing archive. flag is os.O_RDONLY or
// os.O_RDWR.
func openArchiveFile(path string, flag int) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	access := uint32(windows.GENERIC_READ)
	if flag&(os.O_WRONLY|os.O_RDWR) != 0 {
		access |= windows.GENERIC_WRITE
	}
	h, err := windows.CreateFile(name, access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}

// fileRenameInfo is FILE_RENAME_INFO of the Windows API, with Flags in place
// of ReplaceIfExists, as FileRenameInfoEx takes it.
type fileRenameInfo struct {
	Flags          uint32
	RootDirectory  windows.Handle
	FileNameLength uint32
	FileName       [1]uint16
}

// renameOver renames oldpath to newpath, and replaces the file at newpath,
// which can be open with FILE_SHARE_DELETE. A file system without POSIX
// semantics (FAT, or Windows before 10 version 1607) gets MoveFileEx, which
// replaces only a file that is not open.
func renameOver(oldpath, newpath string) error {
	return rename(oldpath, newpath, true)
}

// renameNew renames oldpath to newpath, and fails with an error that matches
// fs.ErrExist when newpath exists: neither call replaces a file without
// its flag.
func renameNew(oldpath, newpath string) error {
	return rename(oldpath, newpath, false)
}

func rename(oldpath, newpath string, replace bool) error {
	err := renamePOSIX(oldpath, newpath, replace)
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) || errors.Is(err, windows.ERROR_NOT_SUPPORTED) ||
		errors.Is(err, windows.ERROR_INVALID_FUNCTION) {
		err = moveFile(oldpath, newpath, replace)
	}
	if err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}
	return nil
}

func renamePOSIX(oldpath, newpath string, replace bool) error {
	from, err := windows.UTF16PtrFromString(oldpath)
	if err != nil {
		return err
	}
	// With no RootDirectory, the new name must be a full path.
	abs, err := filepath.Abs(newpath)
	if err != nil {
		return err
	}
	to, err := windows.UTF16FromString(abs)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(from, windows.DELETE|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)

	nameLen := (len(to) - 1) * 2 // bytes, without the terminating zero
	size := int(unsafe.Offsetof(fileRenameInfo{}.FileName)) + len(to)*2
	buf := make([]byte, size)
	info := (*fileRenameInfo)(unsafe.Pointer(&buf[0]))
	info.Flags = windows.FILE_RENAME_POSIX_SEMANTICS
	if replace {
		info.Flags |= windows.FILE_RENAME_REPLACE_IF_EXISTS
	}
	info.FileNameLength = uint32(nameLen)
	copy(unsafe.Slice(&info.FileName[0], len(to)), to)
	return windows.SetFileInformationByHandle(h, windows.FileRenameInfoEx, &buf[0], uint32(size))
}

func moveFile(oldpath, newpath string, replace bool) error {
	from, err := windows.UTF16PtrFromString(oldpath)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(newpath)
	if err != nil {
		return err
	}
	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if replace {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}
	return windows.MoveFileEx(from, to, flags)
}
