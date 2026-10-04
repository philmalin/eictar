//go:build linux || darwin

package meta

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// ReadXattrs returns every extended attribute of path. It does not follow a
// final symbolic link unless follow is true (for -h).
//
// Linux and macOS list the names NUL-separated. The names are recorded
// exactly as the platform gives them: user.foo on Linux, com.apple.quarantine
// on macOS (doc/design.md 7.7). A filesystem without extended attributes is
// not an error: it returns none.
func ReadXattrs(path string, follow bool) (map[string][]byte, error) {
	list := unix.Llistxattr
	get := unix.Lgetxattr
	if follow {
		list = unix.Listxattr
		get = unix.Getxattr
	}
	return readXattrs(path,
		func(buf []byte) (int, error) { return list(path, buf) },
		func(name string, buf []byte) (int, error) { return get(path, name, buf) })
}

// ReadXattrsFile returns every extended attribute of an open file or
// directory. Working on the descriptor, not a path, reads the attributes of
// the file that the walk opened, whatever the path names by now
// (doc/Security_Audit.md, finding 11). where names the file in an error.
func ReadXattrsFile(f *os.File, where string) (map[string][]byte, error) {
	fd := int(f.Fd())
	return readXattrs(where,
		func(buf []byte) (int, error) { return unix.Flistxattr(fd, buf) },
		func(name string, buf []byte) (int, error) { return unix.Fgetxattr(fd, name, buf) })
}

func readXattrs(path string, list func(buf []byte) (int, error),
	get func(name string, buf []byte) (int, error)) (map[string][]byte, error) {
	names, err := growRead(list)
	if err != nil {
		if isUnsupported(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("listing extended attributes of %s: %w", path, err)
	}

	var out map[string][]byte
	for _, name := range bytes.Split(names, []byte{0}) {
		if len(name) == 0 {
			continue
		}
		n := string(name)
		value, err := growRead(func(buf []byte) (int, error) { return get(n, buf) })
		if err != nil {
			// Removed between the list and the read: not an error.
			if errors.Is(err, errNoAttr) {
				continue
			}
			return nil, fmt.Errorf("reading extended attribute %s of %s: %w", n, path, err)
		}
		if out == nil {
			out = map[string][]byte{}
		}
		out[n] = value
	}
	return out, nil
}

// SetXattr sets one attribute on an open file or directory. Working on the
// descriptor, not a path, keeps the operation inside the os.Root that opened
// it. A name that this platform or filesystem does not take returns
// ErrRefused.
func SetXattr(f *os.File, name string, value []byte) error {
	if err := unix.Fsetxattr(int(f.Fd()), name, value, 0); err != nil {
		if refused(err) {
			return fmt.Errorf("setting %s: %w", name, ErrRefused)
		}
		return fmt.Errorf("setting %s: %w", name, err)
	}
	return nil
}

// refused reports an error that means "not this name, here": no extended
// attributes on the filesystem, a namespace the kernel does not know (Linux
// refuses com.apple.* that way), or a name that only the system may set
// (macOS protects some com.apple.* names).
func refused(err error) bool {
	return isUnsupported(err) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) ||
		errors.Is(err, unix.EINVAL)
}
