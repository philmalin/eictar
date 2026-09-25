//go:build unix

package testutil

import (
	"os"
	"path/filepath"

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

// Socket creates a socket node without binding it, which Linux permits for an
// unprivileged user. A bound socket needs a path under the 108-byte limit of
// sun_path, which a test's temporary directory can exceed.
func (t *Tree) Socket(rel string) *Tree {
	t.tb.Helper()

	p := t.Path(rel)
	if err := mkdirAllFor(p); err != nil {
		t.tb.Fatalf("testutil: mkdir for %s: %v", rel, err)
	}
	if err := unix.Mknod(p, unix.S_IFSOCK|0o644, 0); err != nil {
		t.tb.Skipf("testutil: cannot create a socket node here: %v", err)
	}
	return t
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
