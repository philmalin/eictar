//go:build !(linux || darwin || freebsd || netbsd || openbsd)

package meta

import (
	"fmt"
	"io/fs"
	"os"
)

// On the other platforms (Windows, illumos, Plan 9 and the rest) the program
// archives content, directories and links, and reports anything more as
// unsupported rather than pretending (doc/design.md 15.1).

// Supports is empty: none of the metadata features exists here.
var Supports Capabilities

func Stat(fs.FileInfo) Info { return Info{} }

func ReadXattrs(string, bool) (map[string][]byte, error) { return nil, nil }

func SetXattr(_ *os.File, name string, _ []byte) error {
	return fmt.Errorf("setting %s: %w", name, ErrRefused)
}

func DataSegments(*os.File, int64, int64) ([]Segment, bool, error) { return nil, false, nil }

func Mkfifo(*os.File, string, uint32) error { return ErrUnsupported }

func Mknod(*os.File, string, bool, uint32, uint32, uint32) error { return ErrUnsupported }

func SetLinkTimes(*os.File, string, int64, int64) error { return ErrUnsupported }

func Lchown(*os.File, string, uint32, uint32) error { return ErrUnsupported }
