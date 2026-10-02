package archive

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/philmalin/eictar/src/internal/format"
	"github.com/philmalin/eictar/src/internal/fsutil"
	"github.com/philmalin/eictar/src/internal/meta"
	"github.com/philmalin/eictar/src/internal/testutil"
)

// metadataTree builds a tree with every kind of metadata M5 records.
func metadataTree(t *testing.T) *testutil.Tree {
	t.Helper()
	tree := testutil.NewTree(t)
	tree.Dir("tree", 0o755).
		Dir("tree/private", 0o750).
		Text("tree/plain.txt", 0o644, "plain content").
		Text("tree/attrs.txt", 0o640, "has attributes").
		Text("tree/tool", 0o755, "#!/bin/sh\necho hi\n").
		Chmod("tree/tool", 0o755|os.ModeSetuid).
		Dir("tree/shared", 0o777).
		Chmod("tree/shared", 0o777|os.ModeSticky).
		Text("tree/private/first", 0o600, "linked content").
		Hardlink("tree/second-name", "tree/private/first").
		Fifo("tree/pipe", 0o640).
		Symlink("tree/link", "plain.txt").
		Text("tree/with space.txt", 0o644, "spaces").
		Text("tree/new\nline.txt", 0o644, "newline").
		Text("tree/-leading-dash", 0o644, "dash").
		Text("tree/"+strings.Repeat("n", 200), 0o644, "long name")

	// What a platform does not support is left out of the tree, so that the
	// round trip tests the rest there (doc/design.md 15.1).
	names := []string{"tree/plain.txt", "tree/attrs.txt", "tree/tool",
		"tree/private/first", "tree/pipe", "tree/disk.img", "tree/with space.txt",
		"tree/new\nline.txt", "tree/-leading-dash", "tree/" + strings.Repeat("n", 200)}
	if tree.AcceptsNonUTF8() {
		tree.Text("tree/caf\xe9.txt", 0o644, "latin-1")
		names = append(names, "tree/caf\xe9.txt")
	}
	if meta.Supports.Xattrs {
		tree.Xattr("tree/attrs.txt", "user.comment", []byte("hello")).
			Xattr("tree/attrs.txt", "user.binary", []byte{0x00, 0xff, 0x7f})
	}

	const size = 64 << 20
	tree.Sparse("tree/disk.img", 0o644, size,
		testutil.Segment{Offset: 0, Data: bytes.Repeat([]byte("H"), 8192)},
		testutil.Segment{Offset: 32 << 20, Data: bytes.Repeat([]byte("M"), 8192)},
		testutil.Segment{Offset: size - 4096, Data: bytes.Repeat([]byte("T"), 4096)})

	stamp := time.Unix(1_600_000_000, 0)
	for _, p := range names {
		tree.SetTimes(p, stamp, stamp)
	}
	tree.SetLinkTimes("tree/link", stamp, stamp.Add(time.Hour))
	for _, d := range []string{"tree/private", "tree/shared", "tree"} {
		tree.SetTimes(d, stamp, stamp)
	}
	return tree
}

func createAndExtract(t *testing.T, tree *testutil.Tree, restore RestoreOptions, enc *EncryptionConfig) string {
	t.Helper()
	archivePath := filepath.Join(t.TempDir(), "meta.ect")
	if _, err := CreateArchive(CreateConfig{
		Archive: archivePath, Paths: []string{"tree"}, BaseDir: tree.Root,
		Options: Options{Codec: "zstd", ChunkSize: 4096}, Encryption: enc,
	}); err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}

	var ask PassphraseFunc
	if enc != nil {
		ask = passphrase(string(enc.Passphrase))
	}
	dest := t.TempDir()
	if _, err := Extract(ExtractConfig{
		Archive: archivePath, Destination: dest, Restore: restore, Passphrase: ask,
	}); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	return dest
}

// TestMetadataRoundTrip is the M5 property: everything recorded comes back.
func TestMetadataRoundTrip(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		name := "plaintext"
		var enc *EncryptionConfig
		if encrypted {
			name = "encrypted"
			enc = &EncryptionConfig{Passphrase: []byte("pw"), Params: testKDF, EncryptIndex: true}
		}
		t.Run(name, func(t *testing.T) {
			tree := metadataTree(t)
			if !meta.Supports.Fifos {
				// The platform cannot create a pipe safely, so extraction
				// skips it with a notice (TestPipeSkippedWhereUnsafe).
				if err := os.Remove(tree.Path("tree/pipe")); err != nil {
					t.Fatal(err)
				}
			}
			dest := createAndExtract(t, tree, RestoreOptions{Permissions: true}, enc)

			testutil.CompareTrees(t, tree.Path("tree"), filepath.Join(dest, "tree"),
				testutil.CompareOptions{
					Mode: true, Special: true, MTime: true, Hardlinks: true,
					Xattrs: meta.Supports.Xattrs,
					Holes:  meta.Supports.Holes && tree.Holes("tree/disk.img"),
				})
		})
	}
}

// TestSpecialBitsNeedAskingFor: a setuid bit in an archive is not trusted by
// default. Without -p it is dropped.
func TestSpecialBitsNeedAskingFor(t *testing.T) {
	tree := metadataTree(t)
	dest := createAndExtract(t, tree, RestoreOptions{}, nil)

	for _, p := range []string{"tree/tool", "tree/shared"} {
		fi, err := os.Stat(filepath.Join(dest, p))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			t.Errorf("%s: special bits %v restored without -p", p, fi.Mode())
		}
	}
}

// TestHolesSurviveAndCostNothing: a 64 MiB file with 20 KiB of data stores
// only what the filesystem reports as data, and extracts with its holes.
//
// How much that is depends on the filesystem. ext4 reports data in 4 KiB
// blocks, so the blob is about 20 KiB. ZFS reports it in whole records, 128 KiB
// by default and up to 1 MiB, so each of the three regions costs a record:
// 384 KiB on the FreeBSD CI runner. The bound allows three 1 MiB records and
// still fails at once for a file stored dense.
func TestHolesSurviveAndCostNothing(t *testing.T) {
	if !meta.Supports.Holes {
		t.Skipf("%s stores files with holes dense (doc/design.md 15.1)", runtime.GOOS)
	}
	tree := metadataTree(t)
	if !tree.Holes("tree/disk.img") {
		t.Skip("this filesystem does not make holes")
	}

	archivePath := filepath.Join(t.TempDir(), "a.ect")
	if _, err := CreateArchive(CreateConfig{
		Archive: archivePath, Paths: []string{"tree/disk.img"}, BaseDir: tree.Root,
		Options: Options{Codec: "none", ChunkSize: 4096},
	}); err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}

	r, err := Open(archivePath, nil)
	if err != nil {
		t.Fatal(err)
	}
	m := r.Members()[0]
	r.Close()
	if len(m.Sparse) == 0 {
		t.Fatal("the sparse file was stored dense")
	}
	if m.Size != 64<<20 {
		t.Errorf("logical size = %d, want %d", m.Size, 64<<20)
	}
	const bound = 64 << 20 / 16 // 4 MiB
	if m.Length > bound {
		t.Errorf("the blob is %d bytes; a sparse file must store only its data", m.Length)
	}

	fi, _ := os.Stat(archivePath)
	if fi.Size() > bound+1<<20 {
		t.Errorf("the archive is %d bytes for 20 KiB of data", fi.Size())
	}
}

// TestSparseToStdoutFillsHoles: -O gets the file as a reader sees it.
func TestSparseToStdoutFillsHoles(t *testing.T) {
	tree := metadataTree(t)
	archivePath := filepath.Join(t.TempDir(), "a.ect")
	if _, err := CreateArchive(CreateConfig{
		Archive: archivePath, Paths: []string{"tree/disk.img"}, BaseDir: tree.Root,
		Options: Options{Codec: "zstd", ChunkSize: 4096},
	}); err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}

	var out bytes.Buffer
	if _, err := Extract(ExtractConfig{Archive: archivePath, ToStdout: &out}); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	want, err := os.ReadFile(tree.Path("tree/disk.img"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), want) {
		t.Errorf("stdout content differs: %d bytes, want %d", out.Len(), len(want))
	}
}

// TestHardlinkWithoutItsTarget: asking for one name of a file produces the
// file, even when its content was recorded under another name.
func TestHardlinkWithoutItsTarget(t *testing.T) {
	tree := metadataTree(t)
	archivePath := filepath.Join(t.TempDir(), "a.ect")
	if _, err := CreateArchive(CreateConfig{
		Archive: archivePath, Paths: []string{"tree"}, BaseDir: tree.Root,
		Options: Options{Codec: "zstd"},
	}); err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}

	// Which name is the hardlink depends on walk order; ask for whichever it is.
	r, err := Open(archivePath, nil)
	if err != nil {
		t.Fatal(err)
	}
	var link string
	for _, m := range r.Members() {
		if m.Type == format.TypeHardlink {
			link = m.Path
		}
	}
	r.Close()
	if link == "" {
		t.Fatal("no hardlink member was recorded")
	}

	dest := t.TempDir()
	if _, err := Extract(ExtractConfig{Archive: archivePath, Destination: dest, Patterns: []string{link}}); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, link))
	if err != nil {
		t.Fatalf("the link was not extracted: %v", err)
	}
	if string(got) != "linked content" {
		t.Errorf("content = %q, want the target's", got)
	}
}

// TestHardlinksShareOneBlob: the second name stores no content.
func TestHardlinksShareOneBlob(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Text("a", 0o644, strings.Repeat("x", 100000)).Hardlink("b", "a").Hardlink("c", "a")

	archivePath := filepath.Join(t.TempDir(), "a.ect")
	if _, err := CreateArchive(CreateConfig{
		Archive: archivePath, Paths: []string{"a", "b", "c"}, BaseDir: tree.Root,
		Options: Options{Codec: "none"},
	}); err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}

	r, err := Open(archivePath, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	var regs, links int
	for _, m := range r.Members() {
		switch m.Type {
		case format.TypeReg:
			regs++
		case format.TypeHardlink:
			links++
		}
	}
	if regs != 1 || links != 2 {
		t.Errorf("recorded %d files and %d links, want 1 and 2", regs, links)
	}
}

func TestOwnerIsRecorded(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Text("a", 0o644, "x")

	for _, noOwner := range []bool{false, true} {
		archivePath := filepath.Join(t.TempDir(), "a.ect")
		if _, err := CreateArchive(CreateConfig{
			Archive: archivePath, Paths: []string{"a"}, BaseDir: tree.Root,
			Options: Options{Codec: "none"}, Metadata: MetadataOptions{NoOwner: noOwner},
		}); err != nil {
			t.Fatalf("CreateArchive: %v", err)
		}
		r, err := Open(archivePath, nil)
		if err != nil {
			t.Fatal(err)
		}
		m := r.Members()[0]
		r.Close()

		if noOwner {
			if m.UID != nil || m.GID != nil || m.Uname != "" {
				t.Errorf("--no-owner recorded uid=%v gid=%v uname=%q", m.UID, m.GID, m.Uname)
			}
			continue
		}
		if m.UID == nil || *m.UID != uint32(os.Getuid()) {
			t.Errorf("uid = %v, want %d", m.UID, os.Getuid())
		}
	}
}

func TestXattrOptions(t *testing.T) {
	tree := metadataTree(t)
	archivePath := filepath.Join(t.TempDir(), "a.ect")
	if _, err := CreateArchive(CreateConfig{
		Archive: archivePath, Paths: []string{"tree/attrs.txt"}, BaseDir: tree.Root,
		Options: Options{Codec: "none"}, Metadata: MetadataOptions{NoXattrs: true},
	}); err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}
	r, _ := Open(archivePath, nil)
	m := r.Members()[0]
	r.Close()
	if len(m.Xattrs) != 0 {
		t.Errorf("--no-xattrs recorded %v", m.Xattrs)
	}

	// And on extract: recorded, but not applied.
	archivePath = filepath.Join(t.TempDir(), "b.ect")
	if _, err := CreateArchive(CreateConfig{
		Archive: archivePath, Paths: []string{"tree/attrs.txt"}, BaseDir: tree.Root,
		Options: Options{Codec: "none"},
	}); err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}
	dest := t.TempDir()
	if _, err := Extract(ExtractConfig{Archive: archivePath, Destination: dest,
		Restore: RestoreOptions{NoXattrs: true}}); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	got, _ := meta.ReadXattrs(filepath.Join(dest, "tree/attrs.txt"), false)
	if len(got) != 0 {
		t.Errorf("--no-xattrs on extract applied %v", got)
	}
}

// TestPrivilegedXattrsNeedRoot: security.* and trusted.* are not applied as
// an ordinary user, and their absence is not an error.
func TestPrivilegedXattrsNeedRoot(t *testing.T) {
	if meta.IsRoot() {
		t.Skip("needs an ordinary user; this run is root")
	}
	archivePath, _ := craftArchive(t, "none", []byte("content"), func(m *format.Member) {
		m.Xattrs = map[string][]byte{
			"user.ok":          []byte("yes"),
			"security.selinux": []byte("system_u:object_r:etc_t:s0"),
			"trusted.secret":   []byte("x"),
		}
	})
	dest := t.TempDir()
	if _, err := Extract(ExtractConfig{Archive: archivePath, Destination: dest}); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	got, _ := meta.ReadXattrs(filepath.Join(dest, "member.bin"), false)
	if string(got["user.ok"]) != "yes" {
		t.Errorf("user.ok = %q, want yes", got["user.ok"])
	}
	for _, name := range []string{"security.selinux", "trusted.secret"} {
		if _, ok := got[name]; ok {
			t.Errorf("%s was applied as an ordinary user", name)
		}
	}
}

func TestExcludePrunes(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Dir("tree/cache", 0o755).
		Text("tree/cache/big.bin", 0o644, "cached").
		Text("tree/keep.txt", 0o644, "keep").
		Text("tree/secret.key", 0o600, "secret").
		Text("tree/sub/other.key", 0o600, "also secret")

	archivePath := filepath.Join(t.TempDir(), "a.ect")
	if _, err := CreateArchive(CreateConfig{
		Archive: archivePath, Paths: []string{"tree"}, BaseDir: tree.Root,
		Options: Options{Codec: "none"}, Exclude: []string{"tree/cache", "*.key"},
	}); err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}

	members, err := List(ListConfig{Archive: archivePath})
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, m := range members {
		paths = append(paths, m.Path)
	}
	got := strings.Join(paths, ",")
	if got != "tree,tree/keep.txt,tree/sub" {
		t.Errorf("archived %q, want tree,tree/keep.txt,tree/sub", got)
	}
}

// TestOneFileSystemStopsAtAMountPoint uses a walker whose root device is set
// to something else, which is what a mount point looks like from above.
func TestOneFileSystemStopsAtAMountPoint(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Dir("mnt", 0o755).Text("mnt/inside.txt", 0o644, "on another filesystem")

	var seen []string
	wk := newWalker(walkOptions{baseDir: tree.Root, oneFileSystem: true}, func(e entry) error {
		seen = append(seen, e.Stored)
		return nil
	})
	wk.rootDev = ^uint64(0) // a device nothing in the tree is on
	if err := wk.walk(tree.Path("mnt"), "mnt", true); err != nil {
		t.Fatal(err)
	}
	if strings.Join(seen, ",") != "mnt" {
		t.Errorf("walked %v; a mount point is recorded but not entered", seen)
	}
}

// TestDeviceNodesNeedAsking: a device node in an archive is skipped with a
// notice unless --preserve-devices was given.
func TestDeviceNodesNeedAsking(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "dev.ect")
	w, err := Create(archivePath, Options{Codec: "none"})
	if err != nil {
		t.Fatal(err)
	}
	dev := format.Member{ID: 1, Generation: 1, Path: "null", Type: format.TypeCharDev,
		Mode: 0o666, RDev: []uint32{1, 3}, Codec: format.NoCodec}
	if err := w.AppendMember(&dev, nil); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	dest := t.TempDir()
	rep := &recordingReporter{}
	stats, err := Extract(ExtractConfig{Archive: archivePath, Destination: dest, Reporter: rep})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if stats.Skipped != 1 {
		t.Errorf("stats = %+v, want the device skipped", stats)
	}
	if _, err := os.Lstat(filepath.Join(dest, "null")); err == nil {
		t.Error("a device node was created without --preserve-devices")
	}
	if !strings.Contains(strings.Join(rep.warnings, "\n"), "--preserve-devices") {
		t.Errorf("warnings = %q, want them to name the option", rep.warnings)
	}

	if !meta.IsRoot() {
		return
	}
	dest = t.TempDir()
	if _, err := Extract(ExtractConfig{Archive: archivePath, Destination: dest,
		Restore: RestoreOptions{Devices: true}}); err != nil {
		t.Fatalf("Extract as root: %v", err)
	}
	fi, err := os.Lstat(filepath.Join(dest, "null"))
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		t.Errorf("as root with --preserve-devices, got %v, %v", fi, err)
	}
}

// TestFifoCannotEscapeThroughALink: a pipe is created with an *at call, and
// the directory it is created in comes from os.Root, so a planted link
// cannot steer it outside.
func TestFifoCannotEscapeThroughALink(t *testing.T) {
	outside := t.TempDir()
	archivePath := filepath.Join(t.TempDir(), "evil.ect")
	w, err := Create(archivePath, Options{Codec: "none"})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []format.Member{
		{ID: 1, Generation: 1, Path: "evil", Type: format.TypeSymlink, Mode: 0o777,
			LinkTarget: outside, Codec: format.NoCodec},
		{ID: 2, Generation: 1, Path: "evil/pipe", Type: format.TypeFIFO, Mode: 0o600,
			Codec: format.NoCodec},
	} {
		m := m
		if err := w.AppendMember(&m, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = Extract(ExtractConfig{Archive: archivePath, Destination: t.TempDir()})
	if !errors.Is(err, fsutil.ErrUnsafePath) {
		t.Errorf("error = %v, want ErrUnsafePath", err)
	}
	if _, err := os.Lstat(filepath.Join(outside, "pipe")); err == nil {
		t.Fatal("a pipe was created outside the destination")
	}
}

// TestOwnershipRestoredAsRoot only runs as root, where chown works.
func TestOwnershipRestoredAsRoot(t *testing.T) {
	if !meta.IsRoot() {
		t.Skip("restoring ownership needs root")
	}
	tree := testutil.NewTree(t)
	tree.Text("a", 0o644, "x")
	if err := os.Chown(tree.Path("a"), 12345, 12345); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(t.TempDir(), "a.ect")
	if _, err := CreateArchive(CreateConfig{Archive: archivePath, Paths: []string{"a"},
		BaseDir: tree.Root, Options: Options{Codec: "none"}}); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	if _, err := Extract(ExtractConfig{Archive: archivePath, Destination: dest,
		Restore: RestoreOptions{Owner: true}}); err != nil {
		t.Fatal(err)
	}
	testutil.CompareTrees(t, tree.Root, dest, testutil.CompareOptions{Owner: true})
}

var _ = io.Discard
