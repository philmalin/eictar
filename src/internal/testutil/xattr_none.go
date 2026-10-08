//go:build !(linux || darwin || freebsd || netbsd)

package testutil

// userXattrs finds nothing: this platform has no extended attributes.
func userXattrs(string) map[string][]byte { return nil }

// Xattr skips the test: this platform has no extended attributes.
func (t *Tree) Xattr(rel, name string, value []byte) *Tree {
	t.tb.Helper()
	t.tb.Skip("testutil: this platform has no extended attributes")
	return t
}
