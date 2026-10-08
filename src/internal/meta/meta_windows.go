package meta

import (
	"fmt"
	"io/fs"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// On Windows the program archives content, directories, links, hardlinks and
// the times of links. Windows has no owner as a number, no mode bits, no
// extended attributes of the user namespace and no named pipes, so the rest
// is reported as unsupported (doc/design.md 15.1).

// Supports is empty: the Metadata feature includes owners and special bits,
// which Windows does not have.
var Supports Capabilities

func Stat(fs.FileInfo) Info { return Info{} }

// StatPath gives the identity of fi, the FileInfo of path: the volume serial
// number as Dev, the file index as Ino, and the link count. The FileInfo of
// Windows does not hold them, so StatPath reads them from a handle. A link is
// not followed when fi is a link. On a failure, StatPath gives no identity,
// and the file is archived as a file of one name.
func StatPath(path string, fi fs.FileInfo) Info {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return Info{}
	}
	flags := uint32(windows.FILE_FLAG_BACKUP_SEMANTICS) // a directory needs it
	if fi.Mode()&fs.ModeSymlink != 0 {
		flags |= windows.FILE_FLAG_OPEN_REPARSE_POINT
	}
	h, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return Info{}
	}
	defer windows.CloseHandle(h)
	var d windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &d); err != nil {
		return Info{}
	}
	return Info{
		Dev:   uint64(d.VolumeSerialNumber),
		Ino:   uint64(d.FileIndexHigh)<<32 | uint64(d.FileIndexLow),
		Nlink: uint64(d.NumberOfLinks),
		HasID: true,
	}
}

func ReadXattrs(string, bool) (map[string][]byte, error) { return nil, nil }

func ReadXattrsFile(*os.File, string) (map[string][]byte, error) { return nil, nil }

func SetXattr(_ *os.File, name string, _ []byte) error {
	return fmt.Errorf("setting %s: %w", name, ErrRefused)
}

func DataSegments(*os.File, int64, int64) ([]Segment, bool, error) { return nil, false, nil }

func Mkfifo(*os.File, string, uint32) error { return ErrUnsupported }

func Mknod(*os.File, string, bool, uint32, uint32, uint32) error { return ErrUnsupported }

// SetLinkTimes sets the times of the link name inside the directory dir, and
// not of its target. The name is opened relative to the handle of dir, as
// the *at calls of Unix do, so that the operation stays inside the
// extraction root.
func SetLinkTimes(dir *os.File, name string, atimeNanos, mtimeNanos int64) error {
	if strings.ContainsAny(name, `/\`) || name == "" || name == "." || name == ".." {
		return fmt.Errorf("%q: not one path component", name)
	}
	uname, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return err
	}
	oa := windows.OBJECT_ATTRIBUTES{RootDirectory: windows.Handle(dir.Fd()), ObjectName: uname}
	oa.Length = uint32(unsafe.Sizeof(oa))
	var h windows.Handle
	var iosb windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&h, windows.FILE_WRITE_ATTRIBUTES|windows.SYNCHRONIZE, &oa, &iosb, nil, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		windows.FILE_OPEN, windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	if err != nil {
		if st, ok := err.(windows.NTStatus); ok {
			err = st.Errno()
		}
		return fmt.Errorf("opening %s: %w", name, err)
	}
	defer windows.CloseHandle(h)
	a, m := windows.NsecToFiletime(atimeNanos), windows.NsecToFiletime(mtimeNanos)
	return windows.SetFileTime(h, nil, &a, &m)
}

func Lchown(*os.File, string, uint32, uint32) error { return ErrUnsupported }

// Umask is 0: Windows has no mode creation mask.
func Umask() uint32 { return 0 }

// NoBlock is 0: Windows has no named pipes in the file system to wait on.
const NoBlock = 0

// OpenNoFollow opens a file for reading. Windows has no O_NOFOLLOW;
// the caller still compares the file with the walked entry.
func OpenNoFollow(path string) (*os.File, error) { return os.Open(path) }

// MayFollow allows every link: Windows has no sticky directories.
func MayFollow(string, fs.FileInfo) bool { return true }
