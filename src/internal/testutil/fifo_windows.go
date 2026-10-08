package testutil

// Fifo skips the test: Windows has no named pipe in the file system.
func (t *Tree) Fifo(rel string, mode uint32) *Tree {
	t.tb.Helper()
	t.tb.Skip("testutil: Windows has no named pipe in the file system")
	return t
}

// Socket skips the test. Windows can bind a socket to a path, but this
// fixture does not make one there yet.
func (t *Tree) Socket(rel string) *Tree {
	t.tb.Helper()
	t.tb.Skip("testutil: no socket node fixture on Windows")
	return t
}

// Unreadable skips the test: a mode cannot make a file unreadable on
// Windows. Only an ACL can do that.
func (t *Tree) Unreadable(rel string) *Tree {
	t.tb.Helper()
	t.tb.Skip("testutil: a mode cannot make a file unreadable on Windows")
	return t
}
