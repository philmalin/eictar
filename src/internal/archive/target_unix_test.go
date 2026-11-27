//go:build !windows

package archive

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/philmalin/eictar/src/internal/meta"
)

// refuseLinksIn makes the rule of fs.protected_symlinks refuse each link in
// dir, as for links that another user planted there. Only root can make a
// link of another user, so the tests replace the rule.
func refuseLinksIn(t *testing.T, dir string) {
	saved := mayFollowLink
	t.Cleanup(func() { mayFollowLink = saved })
	mayFollowLink = func(link string, fi fs.FileInfo) bool {
		return filepath.Dir(link) != dir && saved(link, fi)
	}
}

// realDir is dir with its links resolved: the temporary directory of the
// tests can be under a link (/var on macOS).
func realDir(t *testing.T, dir string) string {
	t.Helper()
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	return real
}

// TestResolveArchive: the resolution of -f gives what the kernel finds, and
// a missing name is allowed only at the end.
func TestResolveArchive(t *testing.T) {
	root := realDir(t, t.TempDir())
	t.Chdir(root)
	for _, d := range []string{"d/e", "f"} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	mkfile(t, root, "d/e/a.ect")
	for link, to := range map[string]string{
		"rel":       "d/e/a.ect",
		"d/up":      "../f",
		"abs":       filepath.Join(root, "d", "e"),
		"chain":     "rel",
		"dangling":  "f/new.ect",
		"loop1":     "loop2",
		"loop2":     "loop1",
		"d/e/self":  ".",
		"d/e/selfs": "self/self/self",
	} {
		if err := os.Symlink(to, link); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct{ in, want string }{
		{"d/e/a.ect", "d/e/a.ect"},
		{"./d//e/./a.ect", "d/e/a.ect"},
		{"rel", "d/e/a.ect"},
		{"chain", "d/e/a.ect"},
		{"abs/a.ect", filepath.Join(root, "d/e/a.ect")},
		{"d/up/x.ect", "f/x.ect"}, // a link to .. resolves against its own directory
		{"d/e/../e/a.ect", "d/e/a.ect"},
		{"d/e/selfs/a.ect", "d/e/a.ect"},
		{"dangling", "f/new.ect"}, // the target of a link of one's own is made
		{"new.ect", "new.ect"},
		{"..", ".."},
		{"d/../..", ".."},
		{"d/../../..", "../.."},
		{".", "."},
		{"", "."},
		{"/", "/"},
		{"/..", "/"},
		{filepath.Join(root, "d"), filepath.Join(root, "d")},
	} {
		got, err := resolveArchive(c.in)
		if err != nil || got != c.want {
			t.Errorf("resolveArchive(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
	for _, c := range []struct {
		in   string
		want error
	}{
		{"loop1", syscall.ELOOP},
		{"missing/a.ect", fs.ErrNotExist},
		{"missing/../a.ect", fs.ErrNotExist}, // not cleaned by its text
		{"d/e/a.ect/x", syscall.ENOTDIR},
	} {
		got, err := resolveArchive(c.in)
		if !errors.Is(err, c.want) || !strings.HasPrefix(err.Error(), "resolving "+c.in+": ") {
			t.Errorf("resolveArchive(%q) = %q, %v; want %v", c.in, got, err, c.want)
		}
	}
}

// TestResolveArchiveFollowsAtMost40Links: as the kernel, the resolution
// follows 40 links, and refuses a path of 41.
func TestResolveArchiveFollowsAtMost40Links(t *testing.T) {
	t.Chdir(t.TempDir())
	mkfile(t, ".", "l0")
	for i := 1; i <= 41; i++ {
		if err := os.Symlink("l"+itoa(i-1), "l"+itoa(i)); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := resolveArchive("l40"); err != nil || got != "l0" {
		t.Errorf("40 links: %q, %v", got, err)
	}
	if _, err := resolveArchive("l41"); !errors.Is(err, syscall.ELOOP) {
		t.Errorf("41 links: %v, want %v", err, syscall.ELOOP)
	}
}

func itoa(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return itoa(i/10) + string(rune('0'+i%10))
}

// TestResolveArchiveErrors: a link that cannot be read is an error.
func TestResolveArchiveErrors(t *testing.T) {
	if meta.IsRoot() {
		t.Skip("root reads a directory with no permissions")
	}
	dir := t.TempDir()
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	os.Chmod(locked, 0)
	t.Cleanup(func() { os.Chmod(locked, 0o700) })
	p := filepath.Join(locked, "a.ect")
	if _, err := resolveArchive(p); !errors.Is(err, fs.ErrPermission) {
		t.Errorf("resolveArchive in a directory with no permissions: %v", err)
	}
}

// TestCreateChecksALinkInsideALinkTarget: root's own link
// ~/backups/latest.ect -> /tmp/latest.ect, and a link /tmp/latest.ect ->
// /etc/shadow that another user planted. The rule applies to each link that
// the resolution follows, also the one in the target of root's link, so the
// create is refused and the victim stays (doc/Security_Audit_Pass_2.eml,
// finding 16).
func TestCreateChecksALinkInsideALinkTarget(t *testing.T) {
	own, shared := realDir(t, t.TempDir()), realDir(t, t.TempDir())
	victim := filepath.Join(t.TempDir(), "shadow")
	if err := os.WriteFile(victim, []byte("the victim"), 0o600); err != nil {
		t.Fatal(err)
	}
	planted := filepath.Join(shared, "latest.ect")
	os.Symlink(victim, planted)
	link := filepath.Join(own, "latest.ect")
	os.Symlink(planted, link)
	refuseLinksIn(t, shared)

	w, err := Create(link, Options{})
	if err == nil {
		w.Close()
	}
	if !errors.Is(err, ErrUnsafeLink) || !strings.HasPrefix(err.Error(), planted+":") {
		t.Errorf("Create = %v, want %v for %s", err, ErrUnsafeLink, planted)
	}
	if b, _ := os.ReadFile(victim); string(b) != "the victim" {
		t.Errorf("the victim was replaced: %q", b)
	}
}

// TestCompactChecksALinkInsideALinkTarget: the same for compact, the change
// of passphrase and --encrypt-archive, which rename over the archive.
func TestCompactChecksALinkInsideALinkTarget(t *testing.T) {
	archive := mkArchive(t, mutTree(t), false, "t")
	before, _ := os.ReadFile(archive)
	own, shared := realDir(t, t.TempDir()), realDir(t, t.TempDir())
	planted := filepath.Join(shared, "latest.ect")
	os.Symlink(archive, planted)
	link := filepath.Join(own, "latest.ect")
	os.Symlink(planted, link)
	refuseLinksIn(t, shared)

	_, err := CompactArchive(CompactConfig{Archive: link})
	if !errors.Is(err, ErrUnsafeLink) {
		t.Errorf("CompactArchive = %v, want %v", err, ErrUnsafeLink)
	}
	if after, _ := os.ReadFile(archive); string(after) != string(before) {
		t.Error("the archive behind the planted link changed")
	}
}

// TestCreateRaceWithAPlantedLink: another user makes and removes the link
// /tmp/backup.ect -> /etc/passwd in a loop, while root creates
// /tmp/backup.ect. A link that appears after a check and before the
// resolution was followed with no check, and the rename replaced its target
// (doc/Security_Audit_Pass_2.eml, finding 15). With one pass for the check
// and the resolution, no try replaces the victim.
func TestCreateRaceWithAPlantedLink(t *testing.T) {
	shared := realDir(t, t.TempDir())
	victim := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(victim, []byte("the victim"), 0o600); err != nil {
		t.Fatal(err)
	}
	refuseLinksIn(t, shared)
	path := filepath.Join(shared, "backup.ect")

	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			os.Symlink(victim, path)
			os.Remove(path)
		}
	}()
	end := time.Now().Add(2 * time.Second)
	tries := 0
	for ; tries < 2000 && time.Now().Before(end); tries++ {
		if w, err := Create(path, Options{}); err == nil {
			w.Close()
		}
		if b, _ := os.ReadFile(victim); string(b) != "the victim" {
			break
		}
	}
	close(stop)
	<-done
	if b, _ := os.ReadFile(victim); string(b) != "the victim" {
		t.Errorf("the victim was replaced after %d tries", tries+1)
	}
}

// TestCreateDoesNotTakeTheModeOfAnotherUsersFile: a 0666 file of another
// user at -f does not make the new archive 0666. Its mode only limits the
// mode of a new file (doc/Security_Audit_Pass_2.eml, finding 17).
func TestCreateDoesNotTakeTheModeOfAnotherUsersFile(t *testing.T) {
	umask := fs.FileMode(meta.Umask())
	if umask&0o066 == 0 {
		t.Skipf("the umask %03o removes nothing from a 0666 file", umask)
	}
	saved := effectiveUID
	t.Cleanup(func() { effectiveUID = saved })

	for _, c := range []struct {
		name  string
		uid   int
		old   fs.FileMode
		wantM fs.FileMode
	}{
		{"another user's 0666 file", os.Geteuid() + 1, 0o666, 0o666 &^ umask},
		{"another user's 0600 file", os.Geteuid() + 1, 0o600, 0o600 &^ umask},
		{"one's own 0666 file", os.Geteuid(), 0o666, 0o666},
	} {
		effectiveUID = func() int { return c.uid }
		path := filepath.Join(t.TempDir(), "a.ect")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		os.Chmod(path, c.old)
		w, err := Create(path, Options{})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != c.wantM {
			t.Errorf("%s: mode %03o, want %03o", c.name, got, c.wantM)
		}
	}
}

// TestCreateStatOfTheDirectoryFails: the mode of the file of another user
// needs the owner of its directory. When the directory cannot be read, the
// create stops.
func TestCreateStatOfTheDirectoryFails(t *testing.T) {
	saved := effectiveUID
	t.Cleanup(func() { effectiveUID = saved })
	effectiveUID = func() int { return os.Geteuid() + 1 }

	path := filepath.Join(t.TempDir(), "a.ect")
	mkfile(t, filepath.Dir(path), "a.ect")
	fi, _ := os.Stat(path)
	if _, err := inheritedMode(filepath.Join(t.TempDir(), "missing", "a.ect"), fi); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("inheritedMode with no directory: %v", err)
	}
}

// TestCreateThroughALinkToNothing: through a link of one's own to a file
// that does not exist yet, create makes that file, and the link stays, as
// open(2) with O_CREAT does.
func TestCreateThroughALinkToNothing(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "new.ect")
	link := filepath.Join(dir, "latest.ect")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	w, err := Create(link, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&fs.ModeSymlink == 0 {
		t.Errorf("the link: %v, %v", fi, err)
	}
	if fi, err := os.Lstat(target); err != nil || !fi.Mode().IsRegular() {
		t.Errorf("the target: %v, %v", fi, err)
	}
}

// TestResolveArchiveOfALinkRemovedBeforeItsRead: a link that Lstat found
// and that is gone when the pass reads it is an error, not a path.
func TestResolveArchiveOfALinkRemovedBeforeItsRead(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "latest.ect")
	if err := os.Symlink("a.ect", link); err != nil {
		t.Fatal(err)
	}
	saved := readLink
	t.Cleanup(func() { readLink = saved })
	readLink = func(name string) (string, error) {
		os.Remove(name)
		return saved(name)
	}
	if got, err := resolveArchive(link); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("resolveArchive = %q, %v; want %v", got, err, fs.ErrNotExist)
	}
}

// afterOpenFS runs after once the first OpenArchive returns.
type afterOpenFS struct {
	fileSystem
	after func()
}

func (a *afterOpenFS) OpenArchive(path string, flag int) (archiveFile, error) {
	f, err := a.fileSystem.OpenArchive(path, flag)
	if after := a.after; after != nil {
		a.after = nil
		after()
	}
	return f, err
}

// TestCreateOfAnotherUsersFileInADirectoryItCannotStat: the rule for the
// file of another user needs the owner and the mode of its directory. When
// the directory cannot be read after the open, the create stops, and the old
// file stays.
func TestCreateOfAnotherUsersFileInADirectoryItCannotStat(t *testing.T) {
	if meta.IsRoot() {
		t.Skip("root reads a directory with no permissions")
	}
	savedUID, savedFS := effectiveUID, fsys
	t.Cleanup(func() { effectiveUID, fsys = savedUID, savedFS })
	effectiveUID = func() int { return os.Geteuid() + 1 }

	grand := t.TempDir()
	dir := filepath.Join(grand, "d")
	mkfile(t, dir, "a.ect")
	t.Cleanup(func() { os.Chmod(grand, 0o700) })
	fsys = &afterOpenFS{fileSystem: savedFS, after: func() { os.Chmod(grand, 0) }}

	w, err := Create(filepath.Join(dir, "a.ect"), Options{})
	if err == nil {
		w.Abort()
	}
	if !errors.Is(err, fs.ErrPermission) {
		t.Errorf("Create = %v, want %v", err, fs.ErrPermission)
	}
}
