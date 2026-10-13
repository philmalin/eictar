//go:build linux || darwin

package meta

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestReadXattrsLogic: what readXattrs makes of the answers of the system.
func TestReadXattrsLogic(t *testing.T) {
	list := func(names string, err error) func([]byte) (int, error) {
		return func(buf []byte) (int, error) {
			if err != nil {
				return 0, err
			}
			if buf == nil {
				return len(names), nil
			}
			return copy(buf, names), nil
		}
	}
	values := map[string]any{"a": "1", "gone": errNoAttr, "bad": unix.EIO}
	get := func(name string, buf []byte) (int, error) {
		switch v := values[name].(type) {
		case error:
			return 0, v
		case string:
			if buf == nil {
				return len(v), nil
			}
			return copy(buf, v), nil
		}
		return 0, errNoAttr
	}
	got, err := readXattrs("p", list("a\x00gone\x00", nil), get)
	if err != nil || len(got) != 1 || !bytes.Equal(got["a"], []byte("1")) {
		t.Errorf("a name removed after the list: %q, %v", got, err)
	}
	if got, err := readXattrs("p", list("", unix.EOPNOTSUPP), get); got != nil || err != nil {
		t.Errorf("no extended attributes here: %q, %v", got, err)
	}
	if _, err := readXattrs("p", list("", unix.EIO), get); !errors.Is(err, unix.EIO) || !strings.Contains(err.Error(), "listing") {
		t.Errorf("a fault of the list: %v", err)
	}
	if _, err := readXattrs("p", list("a\x00bad\x00", nil), get); !errors.Is(err, unix.EIO) || !strings.Contains(err.Error(), "reading extended attribute bad") {
		t.Errorf("a fault of a read: %v", err)
	}
}

// TestRefused: the errors that mean "not this name, here".
func TestRefused(t *testing.T) {
	for _, err := range []error{unix.ENOTSUP, unix.EOPNOTSUPP, unix.EPERM, unix.EACCES, unix.EINVAL} {
		if !refused(err) {
			t.Errorf("%v: want refused", err)
		}
	}
	if refused(unix.EIO) {
		t.Error("EIO: want a fault, not a refusal")
	}
}

// userXattrs gives a file with a user attribute, or skips where the file
// system has none.
func userXattrs(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := unix.Setxattr(p, "user.t", []byte("v"), 0); err != nil {
		t.Skipf("no user attributes here: %v", err)
	}
	return p
}

// TestReadXattrsFollow: with follow, the attributes are those of the target
// of a link, and without it, those of the link.
func TestReadXattrsFollow(t *testing.T) {
	p := userXattrs(t)
	link := filepath.Join(filepath.Dir(p), "l")
	if err := os.Symlink("f", link); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadXattrs(link, true); err != nil || string(got["user.t"]) != "v" {
		t.Errorf("follow: %q, %v; want the attribute of the target", got, err)
	}
	if got, err := ReadXattrs(link, false); err != nil || got["user.t"] != nil {
		t.Errorf("no follow: %q, %v; want none of the target", got, err)
	}
}

// TestSetXattrErrors: a fault is itself, and a name that the file system
// does not take is ErrRefused.
func TestSetXattrErrors(t *testing.T) {
	f, err := os.Open(userXattrs(t))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := SetXattr(f, "user.big", make([]byte, 1<<20)); err == nil || errors.Is(err, ErrRefused) {
		t.Errorf("a value too large: %v, want the error of the system", err)
	}
	if err := SetXattr(f, "com.example.no-namespace-on-linux", []byte("v")); err != nil && !errors.Is(err, ErrRefused) {
		t.Errorf("a name the system does not take: %v, want ErrRefused", err)
	}
}
