package archive

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/philmalin/eictar/src/internal/format"
	"github.com/philmalin/eictar/src/internal/fsutil"
	"github.com/philmalin/eictar/src/internal/meta"
	"github.com/philmalin/eictar/src/internal/testutil"
)

// Tests of --diff (diff.go) for what its other tests do not reach.

// diffKinds gives each difference as path:kind.
func diffKinds(res DiffResult) []string {
	var out []string
	for _, d := range res.Differences {
		out = append(out, d.Path+":"+d.Kind)
	}
	return out
}

// TestDiffRefuses: no archive, and a member whose path is not in stored
// form, are errors before anything is compared.
func TestDiffRefuses(t *testing.T) {
	tree := mutTree(t)
	if _, err := DiffArchive(DiffConfig{Archive: filepath.Join(t.TempDir(), "none.ect"), BaseDir: tree.Root}); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("no archive: %v", err)
	}
	path := copyArchive(t, mkArchive(t, tree, false, "t"))
	forgeIndex(t, path, nil, func(ix *format.Index) { ix.Members[1].Path = "t/./a.txt" })
	if _, err := DiffArchive(DiffConfig{Archive: path, BaseDir: tree.Root}); !errors.Is(err, fsutil.ErrUnsafePath) {
		t.Errorf("a path not in stored form: %v, want %v", err, fsutil.ErrUnsafePath)
	}
}

// TestDiffSkipsTheRoot: a member ".", which another writer can store, is not
// compared, as extraction does not apply it.
func TestDiffSkipsTheRoot(t *testing.T) {
	tree := mutTree(t)
	path := copyArchive(t, mkArchive(t, tree, false, "t"))
	forgeIndex(t, path, nil, func(ix *format.Index) {
		for i := range ix.Members {
			if ix.Members[i].Path == "t/sub" {
				ix.Members[i].Path = "."
			}
		}
	})
	res, err := DiffArchive(DiffConfig{Archive: path, BaseDir: tree.Root})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range res.Differences {
		if d.Path == "." {
			t.Errorf("the root was compared: %+v", d)
		}
	}
}

// TestDiffCountsAndOrder: the meter gets the content of the members, and
// advances by all of it, compared or not. The reporter gets each member
// compared. A path with several differences gives them in their order:
// mode before time.
func TestDiffCountsAndOrder(t *testing.T) {
	tree := mutTree(t)
	tree.Text("t/big.txt", 0o644, strings.Repeat("several chunks of text. ", 2000))
	archive := mkArchive(t, tree, false, "t")
	tree.Text("t/b.txt", 0o644, "bravo, longer") // a size that differs: no content check
	// Read-only: on Windows, a mode sets only that.
	if err := os.Chmod(tree.Path("t/a.txt"), 0o444); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(tree.Path("t/a.txt"), 0o644) }) // Windows does not remove a read-only file
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(tree.Path("t/a.txt"), future, future); err != nil {
		t.Fatal(err)
	}
	p := &progressRecorder{}
	rep := &memberRecorder{}
	res, err := DiffArchive(DiffConfig{Archive: archive, BaseDir: tree.Root, Reporter: membersAndMeter{rep, p}})
	if err != nil {
		t.Fatal(err)
	}
	want := int64(len("alpha") + len("bravo") + len("charlie") + 48000)
	if p.total != want || p.advanced != want {
		t.Errorf("meter: total %d, advanced %d; want %d each", p.total, p.advanced, want)
	}
	if len(rep.members) != res.Compared || res.Compared != 6 {
		t.Errorf("%d members reported, %d compared; want 6", len(rep.members), res.Compared)
	}
	var kinds []string
	for _, d := range res.Differences {
		if d.Path == "t/a.txt" {
			kinds = append(kinds, d.Kind)
		}
	}
	if !slices.Equal(kinds, []string{DiffMode, DiffMTime}) {
		t.Errorf("t/a.txt: %v, want mode before time", kinds)
	}
}

// TestDiffInTheCurrentDirectory: no -C is the working directory.
func TestDiffInTheCurrentDirectory(t *testing.T) {
	tree := mutTree(t)
	archive := mkArchive(t, tree, false, "t")
	t.Chdir(tree.Root)
	res, err := DiffArchive(DiffConfig{Archive: archive})
	if err != nil || len(res.Differences) != 0 || res.Compared == 0 {
		t.Errorf("%v, %v, %d compared", diffKinds(res), err, res.Compared)
	}
}

// TestDiffWarnsWithKeepGoing: with --keep-going, a path that fails is a
// warning and a failure, and the run goes on.
func TestDiffWarnsWithKeepGoing(t *testing.T) {
	tree := mutTree(t)
	archive := mkArchive(t, tree, false, "t")
	rep := &recordingReporter{}
	var res DiffResult
	err := withSrc(&faultFS{failOp: "read"}, &openSet{}, func() error {
		var err error
		res, err = DiffArchive(DiffConfig{Archive: archive, BaseDir: tree.Root, KeepGoing: true, Reporter: rep, Workers: 1})
		return err
	})
	if err != nil || res.Failed != 1 || len(rep.warnings) != 1 {
		t.Errorf("%v, %d failed, warnings %q; want 1 of each", err, res.Failed, rep.warnings)
	}
}

// TestDiffRefusesARootThroughALink: a member under a link that leads out of
// the base is refused, and the error names the link.
func TestDiffRefusesARootThroughALink(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Text("top/sub/x", 0o644, "x")
	// Stored by its own path, with no member for top: the walk starts at
	// top/sub/x, below the link.
	archive := mkArchive(t, tree, false, "top/sub/x")
	outside := testutil.NewTree(t)
	outside.Text("sub/x", 0o644, "x")
	if err := os.RemoveAll(tree.Path("top")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside.Root, tree.Path("top")); err != nil {
		t.Skipf("no symbolic links: %v", err)
	}
	_, err := DiffArchive(DiffConfig{Archive: archive, BaseDir: tree.Root})
	if !errors.Is(err, fsutil.ErrUnsafePath) || !strings.Contains(err.Error(), `link "top"`) {
		t.Errorf("DiffArchive = %v, want %v naming the link top", err, fsutil.ErrUnsafePath)
	}
}

// TestDiffTypeChange: a file in the archive and a directory on disk is a
// difference of type, and nothing else, and no failure.
func TestDiffTypeChange(t *testing.T) {
	tree := mutTree(t)
	archive := mkArchive(t, tree, false, "t")
	os.Remove(tree.Path("t/a.txt"))
	tree.Dir("t/a.txt", 0o755)
	res, err := DiffArchive(DiffConfig{Archive: archive, BaseDir: tree.Root})
	var got []string
	for _, k := range diffKinds(res) {
		if strings.HasPrefix(k, "t/a.txt:") {
			got = append(got, k)
		}
	}
	if err != nil || res.Failed != 0 || !slices.Equal(got, []string{"t/a.txt:type"}) {
		t.Errorf("%v, %v, %d failed; want only a difference of type for t/a.txt", diffKinds(res), err, res.Failed)
	}
}

// TestDiffClosesEachFile: a file whose size differs is opened for its
// attributes, not read, and still closed.
func TestDiffClosesEachFile(t *testing.T) {
	tree := mutTree(t)
	archive := mkArchive(t, tree, false, "t")
	tree.Text("t/b.txt", 0o644, "bravo, longer")
	var open openSet
	if err := withSrc(&faultFS{}, &open, func() error {
		_, err := DiffArchive(DiffConfig{Archive: archive, BaseDir: tree.Root})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, what := range open.m {
		t.Errorf("%s stays open", what)
	}
}

// TestDiffHardlinkToATombstone: a live hardlink whose target is a
// tombstone is not checked against the path of the target: what is there
// now is another file.
func TestDiffHardlinkToATombstone(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the walk finds no identity of a file on Windows")
	}
	tree := testutil.NewTree(t)
	tree.Text("d/a", 0o644, "the content")
	tree.Hardlink("d/b", "d/a")
	archive := mkArchive(t, tree, false, "d")
	if _, err := DeleteMembers(DeleteConfig{Archive: archive, Patterns: []string{"d/a"}}); err != nil {
		t.Fatal(err)
	}
	// Two files now, as an extraction leaves them: b with the content, and
	// a new a.
	os.Remove(tree.Path("d/b"))
	tree.Text("d/b", 0o644, "the content")
	os.Remove(tree.Path("d/a"))
	tree.Text("d/a", 0o644, "another file")
	res, err := DiffArchive(DiffConfig{Archive: archive, BaseDir: tree.Root, Patterns: []string{"d/b"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range res.Differences {
		if d.Kind == DiffHardlink {
			t.Errorf("a hardlink difference for a target that is gone: %+v", d)
		}
	}
}

// TestDiffDevice: a device with other numbers is a difference.
func TestDiffDevice(t *testing.T) {
	if fi, err := os.Lstat("/dev/null"); err != nil || fi.Mode()&fs.ModeCharDevice == 0 {
		t.Skip("no /dev/null")
	}
	path := filepath.Join(t.TempDir(), "x.ect")
	if _, err := CreateArchive(CreateConfig{Archive: path, Paths: []string{"null"}, BaseDir: "/dev"}); err != nil {
		t.Fatal(err)
	}
	if res, err := DiffArchive(DiffConfig{Archive: path, BaseDir: "/dev"}); err != nil || len(res.Differences) != 0 {
		t.Fatalf("the same device: %v, %v", diffKinds(res), err)
	}
	forgeIndex(t, path, nil, func(ix *format.Index) { ix.Members[0].RDev[1]++ })
	res, err := DiffArchive(DiffConfig{Archive: path, BaseDir: "/dev"})
	if err != nil || !slices.Equal(diffKinds(res), []string{"null:device"}) {
		t.Errorf("other numbers: %v, %v; want a difference of device", diffKinds(res), err)
	}
}

// TestDiffOwner: another owner is a difference, unless --no-owner.
func TestDiffOwner(t *testing.T) {
	tree := mutTree(t)
	path := copyArchive(t, mkArchive(t, tree, false, "t"))
	var info meta.Info
	if info = meta.Stat(mustStat(t, tree.Path("t/a.txt"))); !info.OK {
		t.Skip("this platform records no owner")
	}
	for _, change := range []func(m *format.Member){
		func(m *format.Member) { m.UID = format.OwnerID(info.UID + 1) },
		func(m *format.Member) { m.GID = format.OwnerID(info.GID + 1) },
	} {
		p := copyArchive(t, path)
		forgeIndex(t, p, nil, func(ix *format.Index) {
			for i := range ix.Members {
				if ix.Members[i].Path == "t/a.txt" {
					change(&ix.Members[i])
				}
			}
		})
		res, err := DiffArchive(DiffConfig{Archive: p, BaseDir: tree.Root})
		if err != nil || !slices.Equal(diffKinds(res), []string{"t/a.txt:owner"}) {
			t.Errorf("another owner: %v, %v", diffKinds(res), err)
		}
		res, err = DiffArchive(DiffConfig{Archive: p, BaseDir: tree.Root, Metadata: MetadataOptions{NoOwner: true}})
		if err != nil || len(res.Differences) != 0 {
			t.Errorf("another owner, --no-owner: %v, %v", diffKinds(res), err)
		}
	}
}

// TestDiffXattrsAndACLs: extended attributes and ACLs that differ are two
// differences, each with its names.
func TestDiffXattrsAndACLs(t *testing.T) {
	tree := mutTree(t)
	path := copyArchive(t, mkArchive(t, tree, false, "t"))
	forgeIndex(t, path, nil, func(ix *format.Index) {
		for i := range ix.Members {
			if ix.Members[i].Path == "t/a.txt" {
				ix.Members[i].Xattrs = map[string][]byte{"user.a": []byte("1"), "system.posix_acl_access": []byte("1")}
			}
		}
	})
	disk := map[string][]byte{"user.a": []byte("2"), "system.posix_acl_access": []byte("2")}
	ff, fp := readXattrsFile, readXattrsPath
	t.Cleanup(func() { readXattrsFile, readXattrsPath = ff, fp })
	readXattrsFile = func(f *os.File, _ string) (map[string][]byte, error) {
		if strings.HasSuffix(f.Name(), "a.txt") {
			return disk, nil
		}
		return nil, nil
	}
	readXattrsPath = func(string, bool) (map[string][]byte, error) { return nil, nil }
	res, err := DiffArchive(DiffConfig{Archive: path, BaseDir: tree.Root})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, d := range res.Differences {
		got = append(got, fmt.Sprintf("%s:%s:%v", d.Path, d.Kind, d.Names))
	}
	if want := []string{"t/a.txt:xattrs:[user.a]", "t/a.txt:acls:[system.posix_acl_access]"}; !slices.Equal(got, want) {
		t.Errorf("%v, want %v", got, want)
	}
}

// TestDiffOfAFileThatDoesNotOpen: a file that the user cannot read is a
// failure, with the differences found so far, even when its size already
// differs.
func TestDiffOfAFileThatDoesNotOpen(t *testing.T) {
	if runtime.GOOS == "windows" || meta.IsRoot() {
		t.Skip("needs a file that the user cannot read")
	}
	tree := mutTree(t)
	archive := mkArchive(t, tree, false, "t")
	tree.Text("t/b.txt", 0o644, "bravo, longer")
	if err := os.Chmod(tree.Path("t/b.txt"), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(tree.Path("t/b.txt"), 0o644) })
	_, err := DiffArchive(DiffConfig{Archive: archive, BaseDir: tree.Root})
	if !errors.Is(err, fs.ErrPermission) {
		t.Errorf("DiffArchive = %v, want %v", err, fs.ErrPermission)
	}
}

// membersAndMeter is a Reporter that records the members and has a meter.
type membersAndMeter struct {
	*memberRecorder
	p *progressRecorder
}

func (r membersAndMeter) Total(n int64)   { r.p.Total(n) }
func (r membersAndMeter) Advance(n int64) { r.p.Advance(n) }

// TestDiffStripAndExclude: with --strip-components, a pattern names a stored
// path. "t/a.txt" is not a stored path of top/t/a.txt, but it is the path on
// disk: the walk must not take it to leave the file out.
func TestDiffStripAndExclude(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Text("top/t/a.txt", 0o644, "alpha")
	tree.Text("top/t/b.txt", 0o644, "bravo")
	archive := mkArchive(t, tree, false, "top")
	res, err := DiffArchive(DiffConfig{Archive: archive, BaseDir: tree.Path("top"), StripComponents: 1, Exclude: []string{"t/a.txt"}})
	if err != nil || len(res.Differences) != 0 {
		t.Errorf("%v, %v; want no difference", diffKinds(res), err)
	}
}

// TestDiffXattrsOfADirectory: the extended attributes of a directory are
// compared, as those of a file are.
func TestDiffXattrsOfADirectory(t *testing.T) {
	tree := mutTree(t)
	path := copyArchive(t, mkArchive(t, tree, false, "t"))
	forgeIndex(t, path, nil, func(ix *format.Index) {
		for i := range ix.Members {
			if ix.Members[i].Path == "t/sub" {
				ix.Members[i].Xattrs = map[string][]byte{"user.a": []byte("1")}
			}
		}
	})
	ff, fp := readXattrsFile, readXattrsPath
	t.Cleanup(func() { readXattrsFile, readXattrsPath = ff, fp })
	readXattrsFile = func(*os.File, string) (map[string][]byte, error) { return nil, nil }
	readXattrsPath = func(string, bool) (map[string][]byte, error) { return nil, nil }
	res, err := DiffArchive(DiffConfig{Archive: path, BaseDir: tree.Root})
	if err != nil || !slices.Equal(diffKinds(res), []string{"t/sub:xattrs"}) {
		t.Errorf("%v, %v; want the attribute of t/sub", diffKinds(res), err)
	}
}

// TestDiffOfAFileThatDoesNotOpenWithOptions: a file that does not open is a
// failure when its attributes are compared, even when only its ACLs are.
// When nothing of it is read, neither content nor attributes, it is not:
// its size is the difference.
func TestDiffOfAFileThatDoesNotOpenWithOptions(t *testing.T) {
	if runtime.GOOS == "windows" || meta.IsRoot() {
		t.Skip("needs a file that the user cannot read")
	}
	tree := mutTree(t)
	archive := mkArchive(t, tree, false, "t")
	tree.Text("t/b.txt", 0o644, "bravo, longer")
	if err := os.Chmod(tree.Path("t/b.txt"), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(tree.Path("t/b.txt"), 0o644) })
	if _, err := DiffArchive(DiffConfig{Archive: archive, BaseDir: tree.Root, Metadata: MetadataOptions{NoXattrs: true}}); !errors.Is(err, fs.ErrPermission) {
		t.Errorf("ACLs compared: %v, want %v", err, fs.ErrPermission)
	}
	res, err := DiffArchive(DiffConfig{Archive: archive, BaseDir: tree.Root, Metadata: MetadataOptions{NoXattrs: true, NoACLs: true}})
	var got []string
	for _, k := range diffKinds(res) {
		if strings.HasPrefix(k, "t/b.txt:") {
			got = append(got, k)
		}
	}
	if err != nil || !slices.Contains(got, "t/b.txt:size") {
		t.Errorf("nothing read: %v, %v; want the size, and no failure", got, err)
	}
}

// TestDiffSamePathKeepsIndexOrder: two live members with one path come only
// from a forged index. With --strip-components, they are taken in index
// order, as extraction takes them, so the run compares the same member each
// time: the later one, whose content stays on disk after an extraction.
func TestDiffSamePathKeepsIndexOrder(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Text("top/t/a.txt", 0o644, "alpha")
	tree.Text("top/t/b.txt", 0o644, "bravo")
	path := copyArchive(t, mkArchive(t, tree, false, "top"))
	forgeIndex(t, path, nil, func(ix *format.Index) {
		for i := range ix.Members {
			if ix.Members[i].Path == "top/t/b.txt" {
				ix.Members[i].Path = "top/t/a.txt"
			}
		}
	})
	dest := t.TempDir()
	if _, err := Extract(ExtractConfig{Archive: path, Destination: dest, StripComponents: 1, Workers: 1}); err != nil {
		t.Fatal(err)
	}
	res, err := DiffArchive(DiffConfig{Archive: path, BaseDir: dest, StripComponents: 1})
	if err != nil || len(res.Differences) != 0 {
		t.Errorf("%v, %v; want no difference with the extraction", diffKinds(res), err)
	}
}

// TestDiffXattrsOfADirectoryThatDoesNotOpen: a directory that the walk
// cannot open is a failure, and with --keep-going its attributes are still
// compared, read by its path.
func TestDiffXattrsOfADirectoryThatDoesNotOpen(t *testing.T) {
	if runtime.GOOS == "windows" || meta.IsRoot() {
		t.Skip("needs a directory that the user cannot open")
	}
	tree := mutTree(t)
	path := copyArchive(t, mkArchive(t, tree, false, "t"))
	forgeIndex(t, path, nil, func(ix *format.Index) {
		for i := range ix.Members {
			if ix.Members[i].Path == "t/sub" {
				ix.Members[i].Xattrs = map[string][]byte{"user.a": []byte("1")}
			}
		}
	})
	if err := os.Chmod(tree.Path("t/sub"), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(tree.Path("t/sub"), 0o755) })
	ff, fp := readXattrsFile, readXattrsPath
	t.Cleanup(func() { readXattrsFile, readXattrsPath = ff, fp })
	readXattrsFile = func(*os.File, string) (map[string][]byte, error) { return nil, nil }
	readXattrsPath = func(string, bool) (map[string][]byte, error) { return nil, nil }
	res, err := DiffArchive(DiffConfig{Archive: path, BaseDir: tree.Root, KeepGoing: true})
	if err != nil || res.Failed != 1 || !slices.Contains(diffKinds(res), "t/sub:xattrs") {
		t.Errorf("%v, %v, %d failed; want the attribute of t/sub, and one failure", diffKinds(res), err, res.Failed)
	}
}
