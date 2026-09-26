package archive

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/philmalin/eictar/src/internal/format"
	"github.com/philmalin/eictar/src/internal/meta"
	"github.com/philmalin/eictar/src/internal/testutil"
)

// Regression tests of doc/Security_Audit.md, one for each finding.

// Finding 1: privileged attributes - security.capability gives a program
// privilege - are restored only as root and only with -p. ACLs need root or
// -p.
func TestXattrPolicy(t *testing.T) {
	none, p := RestoreOptions{}, RestoreOptions{Permissions: true}
	for _, tc := range []struct {
		name  string
		class meta.XattrClass
		o     RestoreOptions
		root  bool
		want  int
	}{
		{"privileged, root, no -p", meta.XattrPrivileged, none, true, xattrWithhold},
		{"privileged, root, -p", meta.XattrPrivileged, p, true, xattrRestore},
		{"privileged, user, -p", meta.XattrPrivileged, p, false, xattrSkip},
		{"privileged, root, -p, --no-xattrs", meta.XattrPrivileged, RestoreOptions{Permissions: true, NoXattrs: true}, true, xattrSkip},
		{"ACL, user, no -p", meta.XattrACL, none, false, xattrWithhold},
		{"ACL, user, -p", meta.XattrACL, p, false, xattrRestore},
		{"ACL, root", meta.XattrACL, none, true, xattrRestore},
		{"ACL, --no-acls", meta.XattrACL, RestoreOptions{Permissions: true, NoACLs: true}, true, xattrSkip},
		{"user attribute", meta.XattrUser, none, false, xattrRestore},
		{"user attribute, --no-xattrs", meta.XattrUser, RestoreOptions{NoXattrs: true}, false, xattrSkip},
	} {
		if got := xattrPolicy(tc.class, tc.o, tc.root); got != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, got, tc.want)
		}
	}
	if meta.ClassifyXattr("security.capability") != meta.XattrPrivileged {
		t.Error("security.capability is not privileged")
	}
}

// Finding 2: a member "." would apply its mode - and its owner, under
// --preserve-owner as root - to the destination itself.
func TestExtractDoesNotChangeTheDestination(t *testing.T) {
	path := filepath.Join(t.TempDir(), "crafted.ect")
	w, err := Create(path, Options{Codec: "none"})
	if err != nil {
		t.Fatal(err)
	}
	w.index.Members = append(w.index.Members, format.Member{
		ID: 1, Generation: 1, Path: ".", Type: format.TypeDir, Mode: 0o777, Codec: format.NoCodec, MTimeNanos: 1,
	})
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "dest")
	if err := os.Mkdir(dest, 0o750); err != nil {
		t.Fatal(err)
	}
	rep := &recordingReporter{}
	if _, err := Extract(ExtractConfig{Archive: path, Destination: dest, Reporter: rep}); err != nil {
		t.Fatal(err)
	}
	if got := mustStat(t, dest).Mode().Perm(); got != 0o750 {
		t.Errorf("the destination became %o; want it unchanged at 750", got)
	}
	if len(rep.warnings) != 1 || !strings.Contains(rep.warnings[0], "root of its tree") {
		t.Errorf("warnings %q", rep.warnings)
	}
}

// Finding 3: a regular file that becomes a symbolic link, or another file,
// after the walk is not archived.
func TestOpenWalkedRefusesASwap(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	secret := filepath.Join(dir, "secret")
	os.WriteFile(file, []byte("mine"), 0o644)
	os.WriteFile(secret, []byte("not mine"), 0o600)
	walked := func() entry {
		fi, err := os.Lstat(file)
		if err != nil {
			t.Fatal(err)
		}
		return entry{Src: file, Info: fi}
	}

	e := walked()
	f, err := openWalked(e)
	if err != nil {
		t.Fatalf("the file as walked: %v", err)
	}
	f.Close()

	os.Remove(file)
	os.Symlink(secret, file)
	if f, err := openWalked(e); err == nil {
		f.Close()
		t.Error("a symbolic link put there after the walk was followed")
	}

	os.Remove(file)
	os.WriteFile(file, []byte("another"), 0o644)
	if _, err := openWalked(e); !errors.Is(err, errChangedDuringWalk) {
		t.Errorf("another file at the path: %v, want errChangedDuringWalk", err)
	}
}

// Finding 3, end to end: a create does not store the target of a link that
// took the place of a file.
func TestCreateSkipsAFileThatBecameALink(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Text("f", 0o644, "mine")
	secret := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(secret, []byte("the secret"), 0o600)
	fi, _ := os.Lstat(filepath.Join(tree.Root, "f"))
	os.Remove(filepath.Join(tree.Root, "f"))
	os.Symlink(secret, filepath.Join(tree.Root, "f"))
	c := &capturer{}
	err := c.submitFile(format.Member{}, entry{Src: filepath.Join(tree.Root, "f"), Info: fi})
	if err == nil {
		t.Fatal("a link that replaced a walked file was archived")
	}
}

// Finding 4: -f through a link that another user planted in a sticky
// directory is refused, and a link of one's own is followed.
func TestCheckLinksFollowsOwnLinks(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0o1777) // sticky and world-writable, as /tmp
	target := filepath.Join(t.TempDir(), "real.ect")
	link := filepath.Join(dir, "backup.ect")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := checkLinks(link); err != nil {
		t.Errorf("a link of one's own: %v", err)
	}
	if err := checkLinks(filepath.Join(dir, "none.ect")); err != nil {
		t.Errorf("a path that does not exist: %v", err)
	}
}

// Finding 5: without -p, a mode that the archive gives is less the umask.
func TestExtractAppliesTheUmask(t *testing.T) {
	if meta.IsRoot() {
		t.Skip("root keeps the recorded modes, as tar does")
	}
	umask := meta.Umask()
	if umask&0o022 == 0 {
		t.Skipf("the umask %03o does not remove write for others", umask)
	}
	tree := testutil.NewTree(t)
	tree.Dir("d", 0o777).Text("d/f", 0o666, "x")
	archive := createWith(t, tree, false, false, "d")

	for _, p := range []bool{false, true} {
		dest := t.TempDir()
		if _, err := Extract(ExtractConfig{Archive: archive, Destination: dest,
			Restore: RestoreOptions{Permissions: p}}); err != nil {
			t.Fatal(err)
		}
		f, d := mustStat(t, filepath.Join(dest, "d/f")).Mode().Perm(), mustStat(t, filepath.Join(dest, "d")).Mode().Perm()
		wantF, wantD := os.FileMode(0o666), os.FileMode(0o777)
		if !p {
			wantF, wantD = wantF&^os.FileMode(umask), wantD&^os.FileMode(umask)
		}
		if f != wantF || d != wantD {
			t.Errorf("-p=%v: file %o and directory %o, want %o and %o", p, f, d, wantF, wantD)
		}
	}
}
