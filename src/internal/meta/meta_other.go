//go:build !(linux || darwin || freebsd || netbsd || openbsd || windows)

package meta

import (
	"fmt"
	"io/fs"
	"os"
)

// On the other platforms (illumos, Plan 9 and the rest) the program
// archives content, directories and links, and reports anything more as
// unsupported rather than pretending (doc/design.md 15.1).

// Supports is empty: none of the metadata features exists here.
var Supports Capabilities

func Stat(fs.FileInfo) Info { return Info{} }

func StatPath(string, fs.FileInfo) Info { return Info{} }

func ReadXattrs(string, bool) (map[string][]byte, error) { return nil, nil }

func ReadXattrsFile(*os.File, string) (map[string][]byte, error) { return nil, nil }

func SetXattr(_ *os.File, name string, _ []byte) error {
	return fmt.Errorf("setting %s: %w", name, ErrRefused)
}

func DataSegments(*os.File, int64, int64) ([]Segment, bool, error) { return nil, false, nil }

func Mkfifo(*os.File, string, uint32) error { return ErrUnsupported }

func Mknod(*os.File, string, bool, uint32, uint32, uint32) error { return ErrUnsupported }

func SetLinkTimes(*os.File, string, int64, int64) error { return ErrUnsupported }

func Lchown(*os.File, string, uint32, uint32) error { return ErrUnsupported }

// Umask is 0: these platforms have no mode creation mask.
func Umask() uint32 { return 0 }

// NoBlock is 0: these platforms have no named pipes to wait on.
const NoBlock = 0

// OpenNoFollow opens a file for reading. These platforms have no O_NOFOLLOW;
// the caller still compares the file with the walked entry.
func OpenNoFollow(path string) (*os.File, error) { return os.Open(path) }

// MayFollow allows every link: these platforms have no sticky directories.
func MayFollow(string, fs.FileInfo) bool { return true }
