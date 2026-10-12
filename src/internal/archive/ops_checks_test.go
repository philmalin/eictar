package archive

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/philmalin/eictar/src/internal/crypt"
	"github.com/philmalin/eictar/src/internal/format"
	"github.com/philmalin/eictar/src/internal/meta"
)

// Tests of ops.go that the tests of the operations do not reach: the
// helpers that the listing of the command line uses, and the rules for
// memory and keys.

// TestListingHelpers: each helper of a Listing, with no listing, with a
// member that the listing does not have, and with one that it has.
func TestListingHelpers(t *testing.T) {
	var none *Listing
	m := &format.Member{Codec: 0, Data: 5, HardlinkTo: 5}
	if _, ok := none.Codec(m); ok {
		t.Error("Codec with no listing: want false")
	}
	if p, dead := none.SameAs(m); p != "member 5" || dead {
		t.Errorf("SameAs with no listing: %q, %v", p, dead)
	}
	if n := none.NotStored(m); n != 0 {
		t.Errorf("NotStored with no listing: %d", n)
	}
	if p := none.HardlinkTarget(m); p != "member 5" {
		t.Errorf("HardlinkTarget with no listing: %q", p)
	}

	l := &Listing{
		Codecs: []format.CodecSpec{{Name: "zstd"}},
		byID: map[uint64]*format.Member{
			// No member has the id 0: it means "no member". It is here to
			// show that NotStored does not look it up.
			0: {Path: "zero", Length: 99},
		},
	}
	for _, tc := range []struct {
		codec int
		want  string
	}{{-1, "none"}, {0, "zstd"}, {1, "none"}} {
		if c, ok := l.Codec(&format.Member{Codec: tc.codec}); !ok || c.Name != tc.want {
			t.Errorf("Codec %d: %q, %v; want %q", tc.codec, c.Name, ok, tc.want)
		}
	}
	if p, dead := l.SameAs(m); p != "member 5" || dead {
		t.Errorf("SameAs of a missing member: %q, %v", p, dead)
	}
	if n := l.NotStored(m); n != 0 {
		t.Errorf("NotStored of a missing member: %d", n)
	}
	if n := l.NotStored(&format.Member{}); n != 0 {
		t.Errorf("NotStored of a member that shares nothing: %d", n)
	}
	if p := l.HardlinkTarget(m); p != "member 5" {
		t.Errorf("HardlinkTarget of a missing member: %q", p)
	}

	l.byID[5] = &format.Member{Path: "owner", Length: 42, Dead: true}
	if p, dead := l.SameAs(m); p != "owner" || !dead {
		t.Errorf("SameAs: %q, %v; want owner, deleted", p, dead)
	}
	if n := l.NotStored(m); n != 42 {
		t.Errorf("NotStored: %d, want 42", n)
	}
	if p := l.HardlinkTarget(m); p != "owner" {
		t.Errorf("HardlinkTarget: %q, want owner", p)
	}
}

// TestListArchiveCountsTombstones: Tombstoned counts the deleted members,
// which the listing does not show.
func TestListArchiveCountsTombstones(t *testing.T) {
	path := copyArchive(t, mkArchive(t, mutTree(t), false, "t"))
	if _, err := DeleteMembers(DeleteConfig{Archive: path, Patterns: []string{"t/a.txt"}}); err != nil {
		t.Fatal(err)
	}
	l, err := ListArchive(ListConfig{Archive: path})
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, m := range l.Members {
		paths = append(paths, m.Path)
	}
	if l.Tombstoned != 1 || strings.Join(paths, " ") != "t t/b.txt t/sub t/sub/c.txt" {
		t.Errorf("%d tombstones, members %v", l.Tombstoned, paths)
	}
}

// TestDescribeMode: the name of each type that cannot be stored.
func TestDescribeMode(t *testing.T) {
	for mode, want := range map[os.FileMode]string{
		os.ModeSymlink:                    "a symbolic link",
		os.ModeDevice:                     "a device node",
		os.ModeDevice | os.ModeCharDevice: "a device node",
		os.ModeNamedPipe:                  "a named pipe",
		os.ModeSocket:                     "a socket",
		os.ModeIrregular:                  "an unsupported file type",
		0:                                 "an unsupported file type",
	} {
		if got := describeMode(mode | 0o644); got != want {
			t.Errorf("%v: %q, want %q", mode, got, want)
		}
	}
}

// TestWalkGuardWarnsOnce: the archive, new or old, is left out, with one
// warning for them both. A stripped name has one warning too.
func TestWalkGuardWarnsOnce(t *testing.T) {
	dir := t.TempDir()
	info := func(name string) os.FileInfo {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
		return mustStat(t, p)
	}
	out, old, other := info("out"), info("old"), info("other")
	rep := &recordingReporter{}
	g := &walkGuard{rep: rep, isOutput: func(fi os.FileInfo) bool { return os.SameFile(fi, out) }, old: old}
	for _, tc := range []struct {
		e    entry
		skip bool
	}{
		{entry{Src: "out", Info: out}, true},
		{entry{Src: "old", Info: old}, true},
		{entry{Src: "out", Info: out}, true},
		{entry{Src: "other", Info: other}, false},
		{entry{Src: "/a", Info: other, Stripped: true}, false},
		{entry{Src: "/b", Info: other, Stripped: true}, false},
	} {
		if got := g.skip(tc.e); got != tc.skip {
			t.Errorf("%s: skip %v, want %v", tc.e.Src, got, tc.skip)
		}
	}
	want := []string{
		"out is the archive being written; not archiving it",
		"removing leading '/', '..' or drive from member names",
	}
	if strings.Join(rep.warnings, "\n") != strings.Join(want, "\n") {
		t.Errorf("warnings %q, want %q", rep.warnings, want)
	}

	// With no reporter, the guard still leaves the archive out.
	g = &walkGuard{isOutput: func(fi os.FileInfo) bool { return os.SameFile(fi, out) }}
	if !g.skip(entry{Src: "out", Info: out}) || g.skip(entry{Src: "/a", Info: other, Stripped: true}) {
		t.Error("with no reporter: want the archive left out, and the other entry kept")
	}
}

// TestCreateCountsPayloadBytes: Bytes counts the content of the members
// that have one: not a directory, and not the target of a link.
func TestCreateCountsPayloadBytes(t *testing.T) {
	tree := mutTree(t)
	if runtime.GOOS != "windows" {
		if err := os.Symlink("a-long-target-name", tree.Path("t/link")); err != nil {
			t.Fatal(err)
		}
	}
	stats, err := CreateArchive(CreateConfig{Archive: filepath.Join(t.TempDir(), "a.ect"), Paths: []string{"t"}, BaseDir: tree.Root})
	if err != nil {
		t.Fatal(err)
	}
	if want := uint64(len("alpha") + len("bravo") + len("charlie")); stats.Bytes != want {
		t.Errorf("Bytes %d, want %d", stats.Bytes, want)
	}
}

// TestKeepGoingWithNoReporter: with --keep-going, a file and a directory
// that cannot be read are counted, and the run goes on. A reporter has a
// warning for each, and with no reporter the run goes on too.
func TestKeepGoingWithNoReporter(t *testing.T) {
	if runtime.GOOS == "windows" || meta.IsRoot() {
		t.Skip("needs a file that the user cannot read")
	}
	tree := mutTree(t)
	for _, p := range []string{"t/a.txt", "t/sub"} {
		if err := os.Chmod(tree.Path(p), 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(tree.Path(p), 0o755) })
	}
	for _, rep := range []*recordingReporter{nil, {}} {
		cfg := CreateConfig{Archive: filepath.Join(t.TempDir(), "a.ect"), Paths: []string{"t"}, BaseDir: tree.Root, KeepGoing: true}
		if rep != nil {
			cfg.Reporter = rep
		}
		stats, err := CreateArchive(cfg)
		if err != nil || stats.Failed != 2 {
			t.Errorf("%v, %d failed; want two failures and no error", err, stats.Failed)
		}
		if rep != nil && len(rep.warnings) != 2 {
			t.Errorf("warnings %q, want one for each failure", rep.warnings)
		}
	}
}

// TestEncryptionSetup: an empty passphrase is refused, and no archive is
// made. Parameters left out are the defaults, and they are checked against
// the memory of the machine, as given ones are.
func TestEncryptionSetup(t *testing.T) {
	tree := mutTree(t)
	path := filepath.Join(t.TempDir(), "a.ect")
	_, err := CreateArchive(CreateConfig{Archive: path, Paths: []string{"t"}, BaseDir: tree.Root, Encryption: &EncryptionConfig{}})
	if err == nil || !strings.Contains(err.Error(), "empty passphrase") {
		t.Errorf("empty passphrase: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("empty passphrase: the archive is there (%v)", err)
	}

	saved := kdfMemory
	t.Cleanup(func() { kdfMemory = saved })
	kdfMemory = func() int64 { return 64 << 20 }
	var opts Options
	err = (&EncryptionConfig{Passphrase: []byte("x")}).apply(&opts)
	want := "needs 256 MiB, more than half this machine's 64 MiB"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("default parameters: %v, want %q", err, want)
	}
	if err := (&EncryptionConfig{Passphrase: []byte("x"), Params: crypt.KDFParams{Time: 1, Memory: 8 << 10}}).apply(&opts); err == nil || !strings.Contains(err.Error(), "threads") {
		t.Errorf("parameters that are not valid: %v", err)
	}
	if opts.Keys != nil {
		t.Error("a refused setup gave keys")
	}
}

// TestCheckAffordableAtHalf: half of the RAM is affordable, and more is not.
func TestCheckAffordableAtHalf(t *testing.T) {
	p := crypt.KDFParams{Time: 1, Memory: 64 << 10, Threads: 1} // 64 MiB
	if err := checkAffordableOn(p, 128<<20); err != nil {
		t.Errorf("half the RAM: %v", err)
	}
	if err := checkAffordableOn(p, 128<<20-1); err == nil {
		t.Error("more than half the RAM: no error")
	}
}

// TestBudgetFor: the limit when it is given. Otherwise four chunks for each
// worker, or a quarter of the RAM when that is less.
func TestBudgetFor(t *testing.T) {
	const chunk = 1 << 20
	for _, tc := range []struct {
		name  string
		limit int64
		ram   int64
		want  int64
	}{
		{"limit", 5 << 20, 1 << 30, 5 << 20},
		{"RAM not known", 0, 0, 32 << 20},
		{"much RAM", 0, 1 << 30, 32 << 20},
		{"RAM at four times the workers", 0, 128 << 20, 32 << 20},
		{"little RAM", 0, 64 << 20, 16 << 20},
	} {
		if got := budgetForOn(tc.limit, 8, chunk, tc.ram); got != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, got, tc.want)
		}
	}
}
