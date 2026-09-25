//go:build linux || darwin

package testutil

import (
	"bytes"
	"strings"

	"golang.org/x/sys/unix"
)

// userXattrs reads the user.* attributes of path, for comparison. It is a
// reader of its own, not the one under test in package meta. On macOS the
// fixtures' user.* names are plain names, which it reads the same way.
func userXattrs(path string) map[string][]byte {
	size, err := unix.Llistxattr(path, nil)
	if err != nil || size == 0 {
		return nil
	}
	buf := make([]byte, size)
	n, err := unix.Llistxattr(path, buf)
	if err != nil {
		return nil
	}
	var out map[string][]byte
	for _, name := range bytes.Split(buf[:n], []byte{0}) {
		if !strings.HasPrefix(string(name), "user.") {
			continue
		}
		vsize, err := unix.Lgetxattr(path, string(name), nil)
		if err != nil {
			continue
		}
		v := make([]byte, vsize)
		vn, err := unix.Lgetxattr(path, string(name), v)
		if err != nil {
			continue
		}
		if out == nil {
			out = map[string][]byte{}
		}
		out[string(name)] = v[:vn]
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
