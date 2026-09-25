package meta

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestModeRoundTrip(t *testing.T) {
	for _, m := range []fs.FileMode{
		0o644, 0o755, 0o000, 0o777,
		0o755 | fs.ModeSetuid,
		0o2755&0o777 | fs.ModeSetgid,
		0o1777&0o777 | fs.ModeSticky,
		0o777 | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky,
	} {
		bits := UnixMode(m)
		if got := FileMode(bits, true); got != m {
			t.Errorf("%v -> %#o -> %v", m, bits, got)
		}
	}
	if got := UnixMode(0o755 | fs.ModeSetuid); got != 0o4755 {
		t.Errorf("setuid 0755 = %#o, want 04755", got)
	}
}

// TestSpecialBitsNeedAsking: extraction restores setuid, setgid and sticky
// only when asked (-p). A setuid bit from an archive is not trusted by default.
func TestSpecialBitsNeedAsking(t *testing.T) {
	if got := FileMode(0o4755, false); got != 0o755 {
		t.Errorf("FileMode(04755, false) = %v, want 0755 with no setuid", got)
	}
}

func TestClassifyXattr(t *testing.T) {
	for name, want := range map[string]XattrClass{
		"user.comment":             XattrUser,
		"system.posix_acl_access":  XattrACL,
		"system.posix_acl_default": XattrACL,
		"security.selinux":         XattrPrivileged,
		"trusted.overlay.opaque":   XattrPrivileged,
		"system.nfs4_acl":          XattrPrivileged,
		"com.apple.quarantine":     XattrPlain, // macOS: no namespaces
		"user.":                    XattrPlain, // no name after the namespace
		"usercomment":              XattrPlain,
	} {
		if got := ClassifyXattr(name); got != want {
			t.Errorf("ClassifyXattr(%q) = %v, want %v", name, got, want)
		}
	}
}

// requires skips a test on a platform without the feature it tests
// (doc/design.md 15.1).
func requires(t *testing.T, has bool, feature string) {
	t.Helper()
	if !has {
		t.Skipf("%s: %s is not supported on this platform", runtime.GOOS, feature)
	}
}

func TestStatReportsIdentity(t *testing.T) {
	requires(t, Supports.Metadata, "metadata")
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	if err := os.WriteFile(a, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(a, b); err != nil {
		t.Fatal(err)
	}
	fa, _ := os.Lstat(a)
	fb, _ := os.Lstat(b)
	ia, ib := Stat(fa), Stat(fb)
	if !ia.OK {
		t.Fatal("no system information on Linux")
	}
	if ia.Dev != ib.Dev || ia.Ino != ib.Ino {
		t.Error("two names for one inode report different identities")
	}
	if ia.Nlink != 2 {
		t.Errorf("Nlink = %d, want 2", ia.Nlink)
	}
	if ia.UID != uint32(os.Getuid()) {
		t.Errorf("UID = %d, want %d", ia.UID, os.Getuid())
	}
}

func TestXattrRoundTrip(t *testing.T) {
	requires(t, Supports.Xattrs, "extended attributes")
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]byte{
		"user.comment": []byte("hello"),
		"user.binary":  {0x00, 0xff, 0x00},
		"user.empty":   {},
	}
	for name, value := range want {
		if err := SetXattr(f, name, value); err != nil {
			f.Close()
			if isUnsupportedErr(err) {
				t.Skipf("this filesystem does not support user xattrs: %v", err)
			}
			t.Fatalf("SetXattr(%s): %v", name, err)
		}
	}
	f.Close()

	got, err := ReadXattrs(p, false)
	if err != nil {
		t.Fatalf("ReadXattrs: %v", err)
	}
	for name, value := range want {
		if !bytes.Equal(got[name], value) {
			t.Errorf("%s = %q, want %q", name, got[name], value)
		}
	}
}

func isUnsupportedErr(err error) bool {
	return err != nil && bytesContains(err.Error(), "not supported")
}

func bytesContains(s, sub string) bool { return bytes.Contains([]byte(s), []byte(sub)) }

func TestDataSegmentsFindsHoles(t *testing.T) {
	requires(t, Supports.Holes, "hole detection")
	p := filepath.Join(t.TempDir(), "sparse")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	const size = 64 << 20
	if _, err := f.WriteAt(bytes.Repeat([]byte("A"), 4096), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(bytes.Repeat([]byte("B"), 4096), 32<<20); err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	f.Sync()

	fi, _ := f.Stat()
	info := Stat(fi)
	segs, sparse, err := DataSegments(f, fi.Size(), info.Blocks)
	if err != nil {
		t.Fatalf("DataSegments: %v", err)
	}
	if !sparse {
		t.Skip("this filesystem did not report the holes")
	}

	var data int64
	for _, s := range segs {
		data += s.Length
		if s.Offset < 0 || s.Offset+s.Length > size {
			t.Errorf("segment %+v is outside the file", s)
		}
	}
	if data >= size/2 {
		t.Errorf("%d bytes of data reported in a file that is almost all holes", data)
	}
	// The data that was written must be inside the reported segments.
	for _, off := range []int64{0, 32 << 20} {
		found := false
		for _, s := range segs {
			if off >= s.Offset && off < s.Offset+s.Length {
				found = true
			}
		}
		if !found {
			t.Errorf("the data written at %d is not in any segment: %+v", off, segs)
		}
	}
	// The offset is left at 0 for the reader that follows.
	if pos, _ := f.Seek(0, 1); pos != 0 {
		t.Errorf("file offset left at %d, want 0", pos)
	}
}

func TestDenseFileHasNoSegments(t *testing.T) {
	requires(t, Supports.Metadata, "metadata")
	p := filepath.Join(t.TempDir(), "dense")
	if err := os.WriteFile(p, bytes.Repeat([]byte("x"), 1<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	f, _ := os.Open(p)
	defer f.Close()
	fi, _ := f.Stat()
	if segs, sparse, err := DataSegments(f, fi.Size(), Stat(fi).Blocks); err != nil || sparse || segs != nil {
		t.Errorf("a dense file came back sparse=%v segs=%v err=%v", sparse, segs, err)
	}
}

// TestAtCallsRefuseEscapes: the *at wrappers resolve names against a
// directory os.Root vouched for, so anything but one plain component is an
// escape attempt.
func TestAtCallsRefuseEscapes(t *testing.T) {
	requires(t, Supports.Metadata, "metadata")
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()

	for _, name := range []string{"", ".", "..", "../x", "a/b", "/etc/x", "a\x00b"} {
		if err := Mkfifo(dir, name, 0o600); err == nil {
			t.Errorf("Mkfifo accepted %q", name)
		}
		if err := SetLinkTimes(dir, name, 0, 0); err == nil {
			t.Errorf("SetLinkTimes accepted %q", name)
		}
		if err := Mknod(dir, name, true, 0o600, 1, 3); err == nil {
			t.Errorf("Mknod accepted %q", name)
		}
		if err := Lchown(dir, name, 0, 0); err == nil {
			t.Errorf("Lchown accepted %q", name)
		}
	}
}

func TestMkfifo(t *testing.T) {
	requires(t, Supports.Fifos, "named pipes")
	d := t.TempDir()
	dir, _ := os.Open(d)
	defer dir.Close()
	if err := Mkfifo(dir, "pipe", 0o640); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}
	fi, err := os.Lstat(filepath.Join(d, "pipe"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&fs.ModeNamedPipe == 0 {
		t.Errorf("mode = %v, want a named pipe", fi.Mode())
	}
}

// TestSetLinkTimesDoesNotTouchTheTarget is the M2 hazard: os.Chtimes follows
// a link and retimes the file it points at.
func TestSetLinkTimesDoesNotTouchTheTarget(t *testing.T) {
	requires(t, Supports.Metadata, "link times")
	d := t.TempDir()
	target := filepath.Join(d, "target")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	targetTime := time.Unix(1_000_000_000, 0)
	os.Chtimes(target, targetTime, targetTime)
	if err := os.Symlink("target", filepath.Join(d, "link")); err != nil {
		t.Fatal(err)
	}

	dir, _ := os.Open(d)
	defer dir.Close()
	linkTime := time.Unix(1_500_000_000, 0)
	if err := SetLinkTimes(dir, "link", linkTime.UnixNano(), linkTime.UnixNano()); err != nil {
		t.Fatalf("SetLinkTimes: %v", err)
	}

	li, _ := os.Lstat(filepath.Join(d, "link"))
	if !li.ModTime().Equal(linkTime) {
		t.Errorf("link mtime = %v, want %v", li.ModTime(), linkTime)
	}
	ti, _ := os.Stat(target)
	if !ti.ModTime().Equal(targetTime) {
		t.Errorf("the target was retimed to %v", ti.ModTime())
	}
}

func TestNamesResolveTheCurrentUser(t *testing.T) {
	n := NewNames()
	uid := uint32(os.Getuid())
	name := n.UserName(uid)
	if name == "" {
		t.Skip("the current user has no name on this system")
	}
	if got := n.ResolveUser(name, 99999); got != uid {
		t.Errorf("ResolveUser(%q) = %d, want %d", name, got, uid)
	}
	// A name that does not exist here falls back to the recorded id.
	if got := n.ResolveUser("no-such-user-eictar-test", 4242); got != 4242 {
		t.Errorf("an unknown name resolved to %d, want the recorded 4242", got)
	}
	// And an empty name means "use the number".
	if got := n.ResolveUser("", 777); got != 777 {
		t.Errorf("an empty name resolved to %d, want 777", got)
	}
}
