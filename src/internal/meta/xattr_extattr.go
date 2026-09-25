//go:build freebsd || netbsd

package meta

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// FreeBSD and NetBSD keep extended attributes in two namespaces, user and
// system. The names are recorded as user.NAME and system.NAME, which is how
// Linux spells them too (doc/design.md 15.1).
//
// This calls the extattr system calls directly. The xattr wrappers of x/sys
// v0.48 for these platforms return the raw list format - a length byte, then
// the name, with no namespace - where Linux returns NUL-separated full names,
// and their per-namespace list functions return nil where the call failed.

var namespaces = [...]struct {
	id     int
	prefix string
}{
	{unix.EXTATTR_NAMESPACE_USER, "user."},
	{unix.EXTATTR_NAMESPACE_SYSTEM, "system."},
}

// ReadXattrs returns every extended attribute of path that this process may
// read. It does not follow a final symbolic link unless follow is true.
func ReadXattrs(path string, follow bool) (map[string][]byte, error) {
	list, get := unix.ExtattrListLink, unix.ExtattrGetLink
	if follow {
		list, get = unix.ExtattrListFile, unix.ExtattrGetFile
	}

	var out map[string][]byte
	for _, ns := range namespaces {
		raw, err := growRead(func(buf []byte) (int, error) {
			return list(path, ns.id, bufPtr(buf), len(buf))
		})
		if err != nil {
			// The system namespace needs privilege to read, and a
			// filesystem can have no extended attributes at all.
			if isUnsupported(err) || (ns.id == unix.EXTATTR_NAMESPACE_SYSTEM && errors.Is(err, unix.EPERM)) {
				continue
			}
			return nil, fmt.Errorf("listing extended attributes of %s: %w", path, err)
		}
		for len(raw) > 0 {
			n := int(raw[0])
			if 1+n > len(raw) {
				return nil, fmt.Errorf("listing extended attributes of %s: a malformed list", path)
			}
			name := string(raw[1 : 1+n])
			raw = raw[1+n:]

			value, err := growRead(func(buf []byte) (int, error) {
				return get(path, ns.id, name, bufPtr(buf), len(buf))
			})
			if err != nil {
				if errors.Is(err, errNoAttr) {
					continue // removed between the list and the read
				}
				return nil, fmt.Errorf("reading extended attribute %s%s of %s: %w", ns.prefix, name, path, err)
			}
			if out == nil {
				out = map[string][]byte{}
			}
			out[ns.prefix+name] = value
		}
	}
	return out, nil
}

// bufPtr is the data pointer the extattr calls take: 0 asks for the size.
func bufPtr(buf []byte) uintptr {
	if len(buf) == 0 {
		return 0
	}
	return uintptr(unsafe.Pointer(&buf[0]))
}

// SetXattr sets one attribute on an open file or directory. A name outside
// the user and system namespaces - security.selinux from Linux, or
// com.apple.* from macOS - has no place here, and returns ErrRefused.
func SetXattr(f *os.File, name string, value []byte) error {
	for _, ns := range namespaces {
		attr, ok := cutPrefix(name, ns.prefix)
		if !ok {
			continue
		}
		var p uintptr
		if len(value) > 0 {
			p = uintptr(unsafe.Pointer(&value[0]))
		}
		if _, err := unix.ExtattrSetFd(int(f.Fd()), ns.id, attr, p, len(value)); err != nil {
			if isUnsupported(err) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EINVAL) {
				return fmt.Errorf("setting %s: %w", name, ErrRefused)
			}
			return fmt.Errorf("setting %s: %w", name, err)
		}
		return nil
	}
	return fmt.Errorf("setting %s: %w", name, ErrRefused)
}

func cutPrefix(s, prefix string) (string, bool) {
	if len(s) > len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):], true
	}
	return s, false
}
