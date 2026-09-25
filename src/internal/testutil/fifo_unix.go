//go:build unix

package testutil

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// Fifo creates a named pipe. It exists so that tests have a file type the
// archiver does not yet support, which is what keeps the "refuse what you
// cannot store" behaviour honest.
func (t *Tree) Fifo(rel string, mode uint32) *Tree {
	t.tb.Helper()

	p := t.Path(rel)
	if err := mkdirAllFor(p); err != nil {
		t.tb.Fatalf("testutil: mkdir for %s: %v", rel, err)
	}
	if err := unix.Mkfifo(p, mode); err != nil {
		t.tb.Fatalf("testutil: mkfifo %s: %v", rel, err)
	}
	return t
}

func mkdirAllFor(p string) error {
	return os.MkdirAll(filepath.Dir(p), 0o755)
}

// Socket creates a socket node.
//
// Linux lets a normal user make one with mknod, without binding it. macOS and
// the BSDs need root for that, so there the socket is bound as a listener
// would bind it. A bound socket's path must fit sun_path (104 bytes on macOS),
// and a CI runner's temporary directory is longer than that. So the bind uses
// the short relative name, from inside the directory, and the working
// directory goes back at once. No test in this project runs in parallel,
// which Chdir needs.
func (t *Tree) Socket(rel string) *Tree {
	t.tb.Helper()

	p := t.Path(rel)
	if err := mkdirAllFor(p); err != nil {
		t.tb.Fatalf("testutil: mkdir for %s: %v", rel, err)
	}
	if err := unix.Mknod(p, unix.S_IFSOCK|0o644, 0); err == nil {
		return t
	}
	if err := bindSocket(t.tb, p); err != nil {
		t.tb.Skipf("testutil: cannot create a socket node here: %v", err)
	}
	return t
}

// bindSocket makes a socket node at p by binding it, from inside its
// directory, so that the name given to bind is short whatever the path.
func bindSocket(tb testing.TB, p string) error {
	tb.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	tb.Chdir(filepath.Dir(p))
	defer tb.Chdir(cwd)

	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Base(p), Net: "unix"})
	if err != nil {
		return err
	}
	l.SetUnlinkOnClose(false) // keep the node: it is the fixture
	return l.Close()
}

// Unreadable creates a file its owner cannot read, which is how a test gets a
// member that fails during create. It is meaningless for root, who can read
// anything, so it skips there.
func (t *Tree) Unreadable(rel string) *Tree {
	t.tb.Helper()
	if unix.Geteuid() == 0 {
		t.tb.Skip("testutil: root can read any file, so nothing is unreadable")
	}
	t.File(rel, 0o000, []byte("secret"))
	return t
}
