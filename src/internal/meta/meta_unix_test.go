//go:build linux || darwin || freebsd || netbsd || openbsd

package meta

import (
	"errors"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestMayFollow is the rule of fs.protected_symlinks (doc/Security_Audit.md,
// finding 4), for users that a test cannot be.
func TestMayFollow(t *testing.T) {
	sticky := fs.ModeDir | fs.ModeSticky | 0o777
	for _, tc := range []struct {
		name                 string
		dirMode              fs.FileMode
		linkUID, dirUID, uid uint32
		want                 bool
	}{
		{"/tmp, a link of another user", sticky, 1001, 0, 1000, false},
		{"/tmp, a link of root, for a user", sticky, 0, 0, 1000, true}, // the directory's owner
		{"/tmp, one's own link", sticky, 1000, 0, 1000, true},
		{"a private directory", fs.ModeDir | 0o755, 1001, 1001, 1000, true},
		{"world-writable, not sticky", fs.ModeDir | 0o777, 1001, 0, 1000, true},
		{"sticky, not world-writable", fs.ModeDir | fs.ModeSticky | 0o755, 1001, 0, 1000, true},
	} {
		if got := mayFollow(tc.dirMode, tc.linkUID, tc.dirUID, tc.uid); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestMayFollowOnTheDisk: a link in a directory that is not sticky may be
// followed. A link whose directory does not stat may not.
func TestMayFollowOnTheDisk(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "l")
	if err := os.Symlink("target", link); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if !MayFollow(link, fi) {
		t.Error("a link in a private directory: want true")
	}
	if MayFollow(filepath.Join(dir, "missing", "l"), fi) {
		t.Error("a link whose directory does not stat: want false")
	}
}

// TestOpenNoFollowRefusesALink: the open does not follow a link.
func TestOpenNoFollowRefusesALink(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "target"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target", filepath.Join(dir, "l")); err != nil {
		t.Fatal(err)
	}
	if f, err := OpenNoFollow(filepath.Join(dir, "l")); err == nil {
		f.Close()
		t.Error("a link opened")
	}
	f, err := OpenNoFollow(filepath.Join(dir, "target"))
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
}

// TestGrowRead: the size first, then the content, again when it grew.
func TestGrowRead(t *testing.T) {
	answers := func(as ...any) func([]byte) (int, error) {
		return func(buf []byte) (int, error) {
			a := as[0]
			as = as[1:]
			if err, ok := a.(error); ok {
				return 0, err
			}
			s := a.(string)
			if buf == nil {
				return len(s), nil
			}
			if len(buf) < len(s) {
				return 0, unix.ERANGE
			}
			return copy(buf, s), nil
		}
	}
	for _, tc := range []struct {
		name string
		call func([]byte) (int, error)
		want string
		err  error
	}{
		{"one read", answers("abc", "abc"), "abc", nil},
		{"empty", answers(""), "", nil},
		{"grew", answers("ab", "abcd", "abcd", "abcd"), "abcd", nil},
		{"the size fails", answers(unix.EIO), "", unix.EIO},
		{"the read fails", answers("ab", unix.EIO), "", unix.EIO},
	} {
		got, err := growRead(tc.call)
		if string(got) != tc.want || !errors.Is(err, tc.err) || (tc.err == nil && err != nil) {
			t.Errorf("%s: %q, %v; want %q, %v", tc.name, got, err, tc.want, tc.err)
		}
		if tc.want == "" && got != nil {
			t.Errorf("%s: %q, want nil", tc.name, got)
		}
	}
	always := func(buf []byte) (int, error) {
		if buf == nil {
			return 1, nil
		}
		return 0, unix.ERANGE
	}
	if _, err := growRead(always); err == nil || !strings.Contains(err.Error(), "kept changing size") {
		t.Errorf("always grows: %v", err)
	}
}

// TestMknodAsRoot: the type, the permissions and the numbers of a device.
func TestMknodAsRoot(t *testing.T) {
	if !IsRoot() {
		t.Skip("needs root")
	}
	d := t.TempDir()
	dir, err := os.Open(d)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	defer unix.Umask(unix.Umask(0))
	type device struct {
		name string
		char bool
		mode fs.FileMode
	}
	devices := []device{{"c", true, fs.ModeDevice | fs.ModeCharDevice}}
	if runtime.GOOS != "freebsd" { // FreeBSD has no block devices
		devices = append(devices, device{"b", false, fs.ModeDevice})
	}
	for _, tc := range devices {
		if err := Mknod(dir, tc.name, tc.char, uint32(unix.S_IFIFO)|0o640, 1, 3); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Lstat(filepath.Join(d, tc.name))
		if err != nil {
			t.Fatal(err)
		}
		info := Stat(fi)
		if fi.Mode().Type() != tc.mode || fi.Mode().Perm() != 0o640 || info.Major != 1 || info.Minor != 3 {
			t.Errorf("%s: %v, %d:%d; want %v and 0640, 1:3", tc.name, fi.Mode(), info.Major, info.Minor, tc.mode)
		}
	}
}

// TestNamesOfTheSystem: the names of the current user and group, and the
// ids of the names of uid 0 and gid 0, from the system's own database. The
// test before this one skips when UserName gives "", which a fault gives
// too.
func TestNamesOfTheSystem(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skipf("no current user: %v", err)
	}
	g, err := user.LookupGroupId(me.Gid)
	if err != nil {
		t.Skipf("no name for the group %s: %v", me.Gid, err)
	}
	n := NewNames()
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	if got := n.UserName(uid); got != me.Username {
		t.Errorf("UserName(%d) = %q, want %q", uid, got, me.Username)
	}
	if got := n.GroupName(gid); got != g.Name {
		t.Errorf("GroupName(%d) = %q, want %q", gid, got, g.Name)
	}
	if got := n.ResolveGroup(g.Name, 99999); got != gid {
		t.Errorf("ResolveGroup(%q) = %d, want %d", g.Name, got, gid)
	}
	if got := n.ResolveGroup("no-such-group-eictar-test", 4242); got != 4242 {
		t.Errorf("an unknown group resolved to %d, want the recorded 4242", got)
	}
	if got := n.ResolveGroup("", 777); got != 777 {
		t.Errorf("an empty group resolved to %d, want 777", got)
	}

	// Id 0 is an id like the others, not "no id".
	if root, err := user.LookupId("0"); err == nil {
		if got := n.ResolveUser(root.Username, 99); got != 0 {
			t.Errorf("ResolveUser(%q) = %d, want 0", root.Username, got)
		}
	}
	if wheel, err := user.LookupGroupId("0"); err == nil {
		if got := n.ResolveGroup(wheel.Name, 99); got != 0 {
			t.Errorf("ResolveGroup(%q) = %d, want 0", wheel.Name, got)
		}
	}
}

// TestNamesCache: a name or an id that was looked up once comes from the
// cache, so a long run asks the system once for each.
func TestNamesCache(t *testing.T) {
	n := NewNames()
	n.users[4242], n.groups[4242] = "cached-user", "cached-group"
	n.uids["cached-user"], n.gids["cached-group"] = 7, 8
	if got := n.UserName(4242); got != "cached-user" {
		t.Errorf("UserName: %q", got)
	}
	if got := n.GroupName(4242); got != "cached-group" {
		t.Errorf("GroupName: %q", got)
	}
	if got := n.ResolveUser("cached-user", 1); got != 7 {
		t.Errorf("ResolveUser: %d", got)
	}
	if got := n.ResolveGroup("cached-group", 1); got != 8 {
		t.Errorf("ResolveGroup: %d", got)
	}
}

// TestIsRoot: the effective uid is 0.
func TestIsRoot(t *testing.T) {
	if IsRoot() != (os.Geteuid() == 0) {
		t.Errorf("IsRoot() = %v with the effective uid %d", IsRoot(), os.Geteuid())
	}
}
