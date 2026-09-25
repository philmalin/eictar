//go:build freebsd || netbsd

package testutil

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// userXattrs reads the user namespace of path, as user.NAME, for comparison.
// The extattr list is a length byte and the name, with no terminator.
func userXattrs(path string) map[string][]byte {
	size, err := unix.ExtattrListLink(path, unix.EXTATTR_NAMESPACE_USER, 0, 0)
	if err != nil || size <= 0 {
		return nil
	}
	buf := make([]byte, size)
	n, err := unix.ExtattrListLink(path, unix.EXTATTR_NAMESPACE_USER, uintptr(unsafe.Pointer(&buf[0])), len(buf))
	if err != nil {
		return nil
	}
	var out map[string][]byte
	for raw := buf[:n]; len(raw) > 0; {
		l := int(raw[0])
		if 1+l > len(raw) {
			break
		}
		name := string(raw[1 : 1+l])
		raw = raw[1+l:]
		vsize, err := unix.ExtattrGetLink(path, unix.EXTATTR_NAMESPACE_USER, name, 0, 0)
		if err != nil {
			continue
		}
		v := make([]byte, max(vsize, 1))
		vn, err := unix.ExtattrGetLink(path, unix.EXTATTR_NAMESPACE_USER, name, uintptr(unsafe.Pointer(&v[0])), vsize)
		if err != nil {
			continue
		}
		if out == nil {
			out = map[string][]byte{}
		}
		out["user."+name] = v[:vn]
	}
	return out
}

// Xattr sets a user.* attribute on an existing entry. It skips the test when
// the filesystem has no extended attributes.
func (t *Tree) Xattr(rel, name string, value []byte) *Tree {
	t.tb.Helper()
	if err := unix.Setxattr(t.Path(rel), name, value, 0); err != nil {
		if err == unix.ENOTSUP || err == unix.EOPNOTSUPP {
			t.tb.Skipf("testutil: this filesystem has no extended attributes: %v", err)
		}
		t.tb.Fatalf("testutil: setxattr %s on %s: %v", name, rel, err)
	}
	return t
}
