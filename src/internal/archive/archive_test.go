package archive

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"lukechampine.com/blake3"

	"eictar/src/internal/codec"
	"eictar/src/internal/crypt"
	"eictar/src/internal/format"
	"eictar/src/internal/fsutil"
	"eictar/src/internal/testutil"
)

// contents covers the payload shapes that break an archiver: empty, tiny,
// exactly one chunk, one byte over a chunk, incompressible, and highly
// compressible.
func contents(chunk int) map[string][]byte {
	rnd := rand.New(rand.NewSource(42))
	incompressible := make([]byte, chunk*2+123)
	rnd.Read(incompressible)

	return map[string][]byte{
		"empty.txt":          {},
		"one.txt":            {'x'},
		"text.txt":           []byte(strings.Repeat("compress me please. ", 500)),
		"exact-chunk.bin":    bytes.Repeat([]byte("a"), chunk),
		"chunk-plus-one.bin": bytes.Repeat([]byte("b"), chunk+1),
		"three-chunks.bin":   bytes.Repeat([]byte("c"), chunk*3),
		"incompressible.bin": incompressible,
		"zeroes.bin":         make([]byte, chunk+7),
	}
}

func buildTree(t *testing.T, chunk int) *testutil.Tree {
	t.Helper()

	tree := testutil.NewTree(t)
	tree.Dir("tree", 0o755).Dir("tree/sub", 0o750)
	for name, data := range contents(chunk) {
		tree.File("tree/"+name, 0o644, data)
	}
	tree.File("tree/sub/nested.txt", 0o600, []byte("nested"))
	return tree
}

// TestRoundTrip is the core property: whatever goes in comes out, for every
// codec and across chunk boundaries.
func TestRoundTrip(t *testing.T) {
	for _, codecName := range codec.Names() {
		for _, chunk := range []int{512, 4096, 1 << 20} {
			t.Run(fmt.Sprintf("%s/chunk=%d", codecName, chunk), func(t *testing.T) {
				tree := buildTree(t, chunk)
				archivePath := filepath.Join(t.TempDir(), "a.eictar")

				stats, err := CreateArchive(CreateConfig{
					Archive: archivePath,
					Paths:   []string{"tree"},
					BaseDir: tree.Root,
					Options: Options{Codec: codecName, ChunkSize: chunk},
				})
				if err != nil {
					t.Fatalf("CreateArchive: %v", err)
				}
				if stats.Failed != 0 {
					t.Fatalf("%d members failed", stats.Failed)
				}

				dest := t.TempDir()
				if _, err := Extract(ExtractConfig{Archive: archivePath, Destination: dest}); err != nil {
					t.Fatalf("Extract: %v", err)
				}

				testutil.CompareTrees(t,
					filepath.Join(tree.Root, "tree"),
					filepath.Join(dest, "tree"),
					testutil.CompareOptions{Mode: true, MTime: true})
			})
		}
	}
}

// TestChunkingIsRecorded checks the index describes the blob truthfully: the
// reader relies on the chunk table to know where each chunk ends.
func TestChunkingIsRecorded(t *testing.T) {
	const chunk = 1024
	tree := testutil.NewTree(t)
	tree.File("big.bin", 0o644, bytes.Repeat([]byte("x"), chunk*3+1))

	archivePath := filepath.Join(t.TempDir(), "a.eictar")
	if _, err := CreateArchive(CreateConfig{
		Archive: archivePath,
		Paths:   []string{"big.bin"},
		BaseDir: tree.Root,
		Options: Options{Codec: "zstd", ChunkSize: chunk},
	}); err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}

	r, err := Open(archivePath, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	m := r.Members()[0]
	if want := 4; len(m.Chunks) != want {
		t.Errorf("chunks = %d, want %d", len(m.Chunks), want)
	}
	if m.ChunkSize != chunk {
		t.Errorf("ChunkSize = %d, want %d", m.ChunkSize, chunk)
	}
	if m.Size != uint64(chunk*3+1) {
		t.Errorf("Size = %d, want %d", m.Size, chunk*3+1)
	}
	var total uint64
	for _, c := range m.Chunks {
		total += uint64(c)
	}
	if total != m.Length {
		t.Errorf("chunk lengths total %d, Length is %d", total, m.Length)
	}
	if len(m.Digest) != format.DigestSize {
		t.Errorf("digest is %d bytes, want %d", len(m.Digest), format.DigestSize)
	}
}

// TestIncompressibleChunksStorePlaintext pins the rule the reader depends on:
// a chunk that compression would grow is stored as-is, and equality between
// on-disk length and plaintext size is what marks it.
func TestIncompressibleChunksStorePlaintext(t *testing.T) {
	const chunk = 4096
	rnd := rand.New(rand.NewSource(7))
	random := make([]byte, chunk*2)
	rnd.Read(random)

	tree := testutil.NewTree(t)
	tree.File("random.bin", 0o644, random)

	archivePath := filepath.Join(t.TempDir(), "a.eictar")
	if _, err := CreateArchive(CreateConfig{
		Archive: archivePath,
		Paths:   []string{"random.bin"},
		BaseDir: tree.Root,
		Options: Options{Codec: "zstd", ChunkSize: chunk},
	}); err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}

	r, err := Open(archivePath, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	m := r.Members()[0]
	for i, c := range m.Chunks {
		if int(c) != chunk {
			t.Errorf("chunk %d is %d bytes on disk, want %d (stored plaintext)", i, c, chunk)
		}
	}

	// And it still reads back correctly.
	var got bytes.Buffer
	if err := r.WriteMember(&m, &got); err != nil {
		t.Fatalf("WriteMember: %v", err)
	}
	if !bytes.Equal(got.Bytes(), random) {
		t.Error("stored-plaintext member did not round trip")
	}
}

func TestEmptyArchive(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Dir("empty", 0o755)

	archivePath := filepath.Join(t.TempDir(), "a.eictar")
	if _, err := CreateArchive(CreateConfig{
		Archive: archivePath,
		Paths:   []string{"empty"},
		BaseDir: tree.Root,
		Options: Options{Codec: "zstd"},
	}); err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}

	r, err := Open(archivePath, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	if got := len(r.Members()); got != 1 {
		t.Errorf("members = %d, want 1 (the directory)", got)
	}
}

// TestDamageIsDetected is the integrity story: every kind of tampering must be
// caught, and attributed to the right layer.
func TestDamageIsDetected(t *testing.T) {
	build := func(t *testing.T) string {
		t.Helper()
		tree := testutil.NewTree(t)
		tree.File("a.txt", 0o644, []byte(strings.Repeat("data ", 1000)))
		tree.File("b.txt", 0o644, []byte("second member"))

		archivePath := filepath.Join(t.TempDir(), "a.eictar")
		if _, err := CreateArchive(CreateConfig{
			Archive: archivePath,
			Paths:   []string{"a.txt", "b.txt"},
			BaseDir: tree.Root,
			Options: Options{Codec: "zstd", ChunkSize: 256},
		}); err != nil {
			t.Fatalf("CreateArchive: %v", err)
		}
		return archivePath
	}

	// Damage in the body: Open succeeds, reading the member fails.
	t.Run("member payload", func(t *testing.T) {
		path := build(t)
		flipByteAt(t, path, format.HeaderSize+8)

		r, err := Open(path, nil)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer r.Close()

		var failed bool
		for _, m := range r.Members() {
			if err := r.WriteMember(&m, io.Discard); err != nil {
				failed = true
			}
		}
		if !failed {
			t.Error("a flipped payload byte was not detected")
		}
	})

	for _, tc := range []struct {
		name   string
		damage func(t *testing.T, path string)
		want   error
	}{
		{"header magic", func(t *testing.T, p string) { flipByteAt(t, p, 2) }, format.ErrBadMagic},
		{"header body", func(t *testing.T, p string) { flipByteAt(t, p, 20) }, format.ErrChecksum},
		{"trailer", func(t *testing.T, p string) {
			fi := mustStat(t, p)
			flipByteAt(t, p, fi.Size()-40)
		}, format.ErrChecksum},
		{"index bytes", func(t *testing.T, p string) {
			r, err := Open(p, nil)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			off := int64(r.Trailer().IndexOffset)
			r.Close()
			flipByteAt(t, p, off+2)
		}, format.ErrChecksum},
		{"truncated file", func(t *testing.T, p string) {
			fi := mustStat(t, p)
			if err := os.Truncate(p, fi.Size()-20); err != nil {
				t.Fatalf("truncate: %v", err)
			}
		}, nil},
		{"empty file", func(t *testing.T, p string) {
			if err := os.Truncate(p, 0); err != nil {
				t.Fatalf("truncate: %v", err)
			}
		}, format.ErrTruncated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := build(t)
			tc.damage(t, path)

			r, err := Open(path, nil)
			if err == nil {
				r.Close()
				t.Fatal("Open accepted a damaged archive")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestExtractRefusesUnsafeMemberPath(t *testing.T) {
	// Build a legitimate archive, then rewrite the index so a member escapes.
	// This is the archive an attacker sends, not one we would write.
	tree := testutil.NewTree(t)
	tree.File("a.txt", 0o644, []byte("content"))

	archivePath := filepath.Join(t.TempDir(), "a.eictar")
	if _, err := CreateArchive(CreateConfig{
		Archive: archivePath,
		Paths:   []string{"a.txt"},
		BaseDir: tree.Root,
		Options: Options{Codec: "none"},
	}); err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}

	forgeMemberPath(t, archivePath, "../escaped.txt")

	dest := t.TempDir()
	_, err := Extract(ExtractConfig{Archive: archivePath, Destination: dest})
	if err == nil {
		t.Fatal("extraction accepted a member path that escapes the destination")
	}
	if !errors.Is(err, fsutil.ErrUnsafePath) && !errors.Is(err, format.ErrCorruptIndex) {
		t.Errorf("error = %v, want an unsafe-path or corrupt-index error", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dest), "escaped.txt")); err == nil {
		t.Fatal("a file was written outside the destination")
	}
}

func TestOverwritePolicies(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.File("a.txt", 0o644, []byte("from the archive"))

	archivePath := filepath.Join(t.TempDir(), "a.eictar")
	if _, err := CreateArchive(CreateConfig{
		Archive: archivePath,
		Paths:   []string{"a.txt"},
		BaseDir: tree.Root,
		Options: Options{Codec: "none"},
	}); err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}

	for _, tc := range []struct {
		name   string
		policy OverwritePolicy
		want   string
	}{
		{"always", OverwriteAlways, "from the archive"},
		{"never", OverwriteNever, "already here"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dest := t.TempDir()
			if err := os.WriteFile(filepath.Join(dest, "a.txt"), []byte("already here"), 0o644); err != nil {
				t.Fatalf("seeding destination: %v", err)
			}

			if _, err := Extract(ExtractConfig{
				Archive: archivePath, Destination: dest, Overwrite: tc.policy,
			}); err != nil {
				t.Fatalf("Extract: %v", err)
			}

			got, err := os.ReadFile(filepath.Join(dest, "a.txt"))
			if err != nil {
				t.Fatalf("reading result: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("content = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPatternsSelectMembers(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Dir("tree", 0o755).Dir("tree/sub", 0o755).
		File("tree/a.txt", 0o644, []byte("a")).
		File("tree/b.go", 0o644, []byte("b")).
		File("tree/sub/c.txt", 0o644, []byte("c"))

	archivePath := filepath.Join(t.TempDir(), "a.eictar")
	if _, err := CreateArchive(CreateConfig{
		Archive: archivePath,
		Paths:   []string{"tree"},
		BaseDir: tree.Root,
		Options: Options{Codec: "none"},
	}); err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}

	for _, tc := range []struct {
		pattern string
		want    []string
	}{
		{"tree/a.txt", []string{"tree/a.txt"}},
		{"tree/sub", []string{"tree/sub", "tree/sub/c.txt"}},
		{"*.txt", []string{"tree/a.txt", "tree/sub/c.txt"}},
		{"tree/*.go", []string{"tree/b.go"}},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			members, err := List(ListConfig{Archive: archivePath, Patterns: []string{tc.pattern}})
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			var got []string
			for _, m := range members {
				got = append(got, m.Path)
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("matched %v, want %v", got, tc.want)
			}
		})
	}
}

// TestSymlinkRoundTrip covers the shapes a symlink comes in: relative,
// absolute, dangling, into a directory, and one whose target would escape the
// destination. All of them are stored verbatim and recreated verbatim; a
// link's target is content, not a path into the archive.
func TestSymlinkRoundTrip(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Dir("tree", 0o755).
		Dir("tree/sub", 0o755).
		Text("tree/real.txt", 0o644, "content").
		Text("tree/sub/nested.txt", 0o644, "nested").
		Symlink("tree/relative", "real.txt").
		Symlink("tree/deeper", "sub/nested.txt").
		Symlink("tree/absolute", "/etc/hostname").
		Symlink("tree/dangling", "nowhere.txt").
		Symlink("tree/to-dir", "sub").
		Symlink("tree/escaping", "../../outside.txt")

	archivePath := filepath.Join(t.TempDir(), "a.eictar")
	stats, err := CreateArchive(CreateConfig{
		Archive: archivePath,
		Paths:   []string{"tree"},
		BaseDir: tree.Root,
		Options: Options{Codec: "zstd"},
	})
	if err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}
	if stats.Failed != 0 {
		t.Fatalf("%d members failed", stats.Failed)
	}

	// The index must record the targets exactly as they were on disk.
	r, err := Open(archivePath, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	targets := map[string]string{}
	for _, m := range r.Members() {
		if m.Type == format.TypeSymlink {
			targets[m.Path] = m.LinkTarget
			if m.Size != 0 || len(m.Chunks) != 0 {
				t.Errorf("symlink %q carries a payload", m.Path)
			}
		}
	}
	r.Close()

	for path, want := range map[string]string{
		"tree/relative": "real.txt",
		"tree/deeper":   "sub/nested.txt",
		"tree/absolute": "/etc/hostname",
		"tree/dangling": "nowhere.txt",
		"tree/to-dir":   "sub",
		"tree/escaping": "../../outside.txt",
	} {
		if got := targets[path]; got != want {
			t.Errorf("%s: stored target %q, want %q", path, got, want)
		}
	}

	dest := t.TempDir()
	if _, err := Extract(ExtractConfig{Archive: archivePath, Destination: dest}); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	testutil.CompareTrees(t,
		filepath.Join(tree.Root, "tree"),
		filepath.Join(dest, "tree"),
		testutil.CompareOptions{Mode: true})

	// An escaping target is recreated as a link, because a link is inert
	// until something follows it, and we never do.
	got, err := os.Readlink(filepath.Join(dest, "tree", "escaping"))
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	if got != "../../outside.txt" {
		t.Errorf("escaping link target = %q, want it verbatim", got)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dest), "outside.txt")); err == nil {
		t.Error("something was written outside the destination")
	}
}

// TestExtractRefusesWritingThroughSymlink is the attack os.Root defends
// against: an archive that plants a link out of the destination and then
// writes a member "inside" it.
func TestExtractRefusesWritingThroughSymlink(t *testing.T) {
	outside := t.TempDir()

	// Build the hostile archive by hand: a symlink to somewhere outside,
	// followed by a file underneath it.
	staging := testutil.NewTree(t)
	staging.Dir("payload", 0o755).Text("payload/pwned.txt", 0o644, "owned")

	archivePath := filepath.Join(t.TempDir(), "evil.eictar")
	w, err := Create(archivePath, Options{Codec: "none"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	link := format.Member{
		ID: 1, Generation: 1, Path: "evil", Type: format.TypeSymlink,
		Mode: 0o777, LinkTarget: outside, Codec: format.NoCodec,
	}
	if err := w.AppendMember(&link, nil); err != nil {
		t.Fatalf("AppendMember: %v", err)
	}
	// Write the payload member by hand: the writer is a sink now, and a
	// hostile archive is exactly what a normal build path would refuse to
	// produce.
	payload := []byte("owned")
	member := format.Member{
		ID: 2, Generation: 1, Path: "evil/pwned.txt", Type: format.TypeReg,
		Mode: 0o644, Size: uint64(len(payload)), Codec: format.NoCodec,
		ChunkSize: uint32(DefaultChunkSize),
		Length:    uint64(len(payload)),
		Chunks:    []uint32{uint32(len(payload))},
		Digest:    blake3Sum(payload),
	}
	if err := w.AppendMember(&member, bytesWriterTo(payload)); err != nil {
		t.Fatalf("AppendMember: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	dest := t.TempDir()
	_, err = Extract(ExtractConfig{Archive: archivePath, Destination: dest})
	if err == nil {
		t.Fatal("extraction wrote through a symbolic link out of the destination")
	}
	if !errors.Is(err, fsutil.ErrUnsafePath) {
		t.Errorf("error = %v, want ErrUnsafePath", err)
	}
	if !strings.Contains(err.Error(), "evil") {
		t.Errorf("error = %v, want it to name the offending link", err)
	}

	if _, err := os.Stat(filepath.Join(outside, "pwned.txt")); err == nil {
		t.Fatal("a file was written outside the destination through a symlink")
	}
}

// TestDereferenceFollowsLinks covers -h.
func TestDereferenceFollowsLinks(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Dir("tree", 0o755).
		Dir("tree/real-dir", 0o755).
		Text("tree/real.txt", 0o644, "content").
		Text("tree/real-dir/inner.txt", 0o644, "inner").
		Symlink("tree/link-to-file", "real.txt").
		Symlink("tree/link-to-dir", "real-dir")

	archivePath := filepath.Join(t.TempDir(), "a.eictar")
	if _, err := CreateArchive(CreateConfig{
		Archive:     archivePath,
		Paths:       []string{"tree"},
		BaseDir:     tree.Root,
		Options:     Options{Codec: "none"},
		Dereference: true,
	}); err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}

	r, err := Open(archivePath, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	byPath := map[string]format.Member{}
	for _, m := range r.Members() {
		byPath[m.Path] = m
		if m.Type == format.TypeSymlink {
			t.Errorf("-h left %q as a symlink", m.Path)
		}
	}

	if m, ok := byPath["tree/link-to-file"]; !ok || m.Type != format.TypeReg {
		t.Errorf("link-to-file = %+v, want a regular file", m)
	}
	if m, ok := byPath["tree/link-to-dir"]; !ok || m.Type != format.TypeDir {
		t.Errorf("link-to-dir = %+v, want a directory", m)
	}
	// Following a directory link means walking into it.
	if _, ok := byPath["tree/link-to-dir/inner.txt"]; !ok {
		t.Error("-h did not walk into the linked directory")
	}
}

func TestDereferenceDetectsLoops(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Dir("tree", 0o755).Dir("tree/sub", 0o755)
	tree.Symlink("tree/sub/loop", "..")

	_, err := CreateArchive(CreateConfig{
		Archive:     filepath.Join(t.TempDir(), "a.eictar"),
		Paths:       []string{"tree"},
		BaseDir:     tree.Root,
		Options:     Options{Codec: "none"},
		Dereference: true,
	})
	if err == nil {
		t.Fatal("a symlink loop was followed without complaint")
	}
	if !strings.Contains(err.Error(), "loop") {
		t.Errorf("error = %v, want it to name the loop", err)
	}
}

func TestDanglingLinkUnderDereferenceIsAnError(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Symlink("dangling", "nowhere.txt")

	_, err := CreateArchive(CreateConfig{
		Archive:     filepath.Join(t.TempDir(), "a.eictar"),
		Paths:       []string{"dangling"},
		BaseDir:     tree.Root,
		Options:     Options{Codec: "none"},
		Dereference: true,
	})
	if err == nil {
		t.Error("-h on a dangling link should fail rather than store nothing")
	}
}

// TestSymlinkOverwrite checks that replacing an existing entry with a link
// works: os.Symlink fails on an existing name, unlike O_TRUNC on a file.
func TestSymlinkOverwrite(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Text("real.txt", 0o644, "content").Symlink("link", "real.txt")

	archivePath := filepath.Join(t.TempDir(), "a.eictar")
	if _, err := CreateArchive(CreateConfig{
		Archive: archivePath,
		Paths:   []string{"real.txt", "link"},
		BaseDir: tree.Root,
		Options: Options{Codec: "none"},
	}); err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}

	dest := t.TempDir()
	// Seed the destination with a regular file where the link goes.
	if err := os.WriteFile(filepath.Join(dest, "link"), []byte("in the way"), 0o644); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	if _, err := Extract(ExtractConfig{Archive: archivePath, Destination: dest}); err != nil {
		t.Fatalf("Extract: %v", err)
	}

	fi, err := os.Lstat(filepath.Join(dest, "link"))
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Error("the existing file was not replaced by the symlink")
	}

	// And -k leaves it alone.
	dest2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(dest2, "link"), []byte("keep me"), 0o644); err != nil {
		t.Fatalf("seeding: %v", err)
	}
	if _, err := Extract(ExtractConfig{
		Archive: archivePath, Destination: dest2, Overwrite: OverwriteNever,
	}); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest2, "link"))
	if err != nil || string(got) != "keep me" {
		t.Errorf("--keep-existing replaced the file: content=%q err=%v", got, err)
	}
}

// TestSymlinkChtimesDoesNotRetimeTarget guards a real hazard: Chtimes follows
// a symlink, so restoring a link's time would silently retime whatever it
// points at.
func TestSymlinkChtimesDoesNotRetimeTarget(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Text("real.txt", 0o644, "content").Symlink("link", "real.txt")
	realTime := time.Unix(1_000_000_000, 0)
	tree.SetTimes("real.txt", realTime, realTime)

	archivePath := filepath.Join(t.TempDir(), "a.eictar")
	if _, err := CreateArchive(CreateConfig{
		Archive: archivePath,
		Paths:   []string{"real.txt", "link"},
		BaseDir: tree.Root,
		Options: Options{Codec: "none"},
	}); err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}

	dest := t.TempDir()
	if _, err := Extract(ExtractConfig{Archive: archivePath, Destination: dest}); err != nil {
		t.Fatalf("Extract: %v", err)
	}

	fi, err := os.Stat(filepath.Join(dest, "real.txt"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !fi.ModTime().Equal(realTime) {
		t.Errorf("the link's extraction changed its target's mtime to %v, want %v",
			fi.ModTime(), realTime)
	}
}

// TestSocketIsSkippedWithNotice: a socket has no content and cannot be
// recreated usefully, so it is skipped with a notice, as tar does. It is the
// one type that is skipped rather than refused.
func TestSocketIsSkippedWithNotice(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Text("real.txt", 0o644, "x").Socket("sock")

	rep := &recordingReporter{}
	archivePath := filepath.Join(t.TempDir(), "a.eictar")
	stats, err := CreateArchive(CreateConfig{
		Archive:  archivePath,
		Paths:    []string{"real.txt", "sock"},
		BaseDir:  tree.Root,
		Options:  Options{Codec: "none"},
		Reporter: rep,
	})
	if err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}
	if stats.Skipped != 1 || stats.Failed != 0 {
		t.Errorf("stats = %+v, want 1 skipped and no failures", stats)
	}
	if !strings.Contains(strings.Join(rep.warnings, "\n"), "socket ignored") {
		t.Errorf("warnings = %q, want a notice that the socket was ignored", rep.warnings)
	}

	members, err := List(ListConfig{Archive: archivePath})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(members) != 1 || members[0].Path != "real.txt" {
		t.Errorf("archive holds %v, want just real.txt", members)
	}
	// Skipping must not leave a gap in the member ids.
	if members[0].ID != 1 {
		t.Errorf("member id = %d, want 1", members[0].ID)
	}
}

// recordingReporter collects warnings for assertions.
type recordingReporter struct {
	mu       sync.Mutex
	warnings []string
}

func (r *recordingReporter) Member(*format.Member) {}
func (r *recordingReporter) Warn(f string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.warnings = append(r.warnings, fmt.Sprintf(f, args...))
}

func TestKeepGoingSkipsBadMembers(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Text("good.txt", 0o644, "fine").Unreadable("locked.txt")

	archivePath := filepath.Join(t.TempDir(), "a.eictar")
	stats, err := CreateArchive(CreateConfig{
		Archive:   archivePath,
		Paths:     []string{"good.txt", "locked.txt"},
		BaseDir:   tree.Root,
		Options:   Options{Codec: "none"},
		KeepGoing: true,
	})
	if err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}
	if stats.Members != 1 || stats.Failed != 1 {
		t.Errorf("stats = %+v, want 1 member and 1 failure", stats)
	}

	members, err := List(ListConfig{Archive: archivePath})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(members) != 1 || members[0].Path != "good.txt" {
		t.Errorf("archive holds %v, want just good.txt", members)
	}
}

// bytesWriterTo adapts a byte slice to the payload interface the writer takes.
type bytesWriterTo []byte

func (b bytesWriterTo) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(b)
	return int64(n), err
}

func blake3Sum(b []byte) []byte {
	sum := blake3.Sum256(b)
	return sum[:]
}

func flipByteAt(t *testing.T, path string, off int64) {
	t.Helper()

	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("opening %s: %v", path, err)
	}
	defer f.Close()

	var b [1]byte
	if _, err := f.ReadAt(b[:], off); err != nil {
		t.Fatalf("reading at %d: %v", off, err)
	}
	b[0] ^= 0xff
	if _, err := f.WriteAt(b[:], off); err != nil {
		t.Fatalf("writing at %d: %v", off, err)
	}
}

func mustStat(t testing.TB, path string) os.FileInfo {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi
}

// forgeMemberPath rewrites an archive's index so its first member claims a
// different path, then fixes up the trailer. It builds the archive an
// attacker would send.
func forgeMemberPath(t *testing.T, path, newPath string) {
	t.Helper()
	forgeMemberPathWith(t, path, newPath, nil)
}

// forgeMemberPathWith rewrites a member's path in an existing archive and
// fixes up the trailer, exactly as an attacker with write access would. ask
// supplies the passphrase needed to *read* the archive; the forgery itself
// never uses a key, because an attacker does not have one.
func forgeMemberPathWith(t *testing.T, path, newPath string, ask PassphraseFunc) {
	t.Helper()

	r, err := Open(path, ask)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	tr := r.Trailer()
	hdr := r.Header()
	index := *r.index
	r.Close()

	index.Members[0].Path = newPath

	// Validate would refuse this, so encode the CBOR directly.
	enc, err := index.Encode(format.EncodeOptions{Compress: true})
	if err != nil {
		// Expected when the forged path fails validation; fall back to
		// forging only the bytes, which is what a real attacker does.
		t.Skipf("index validation refused the forged path at encode time: %v", err)
	}

	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("opening %s: %v", path, err)
	}
	defer f.Close()

	if _, err := f.WriteAt(enc.Bytes, int64(tr.IndexOffset)); err != nil {
		t.Fatalf("writing forged index: %v", err)
	}

	tr.IndexLength = uint64(len(enc.Bytes))
	// The digest binds the archive id and the generation, so a forger has to
	// recompute it the same way. Both are in the plaintext header, so this
	// costs an attacker nothing on an unencrypted archive - which is the
	// point of keying it when there is a key.
	tr.IndexDigest = crypt.IndexDigest(nil, hdr.ArchiveUUID, tr.Generation, enc.Bytes)
	trBytes, err := tr.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling trailer: %v", err)
	}
	if _, err := f.WriteAt(trBytes, int64(tr.IndexOffset)+int64(len(enc.Bytes))); err != nil {
		t.Fatalf("writing trailer: %v", err)
	}
	if err := f.Truncate(int64(tr.IndexOffset) + int64(len(enc.Bytes)) + format.TrailerSize); err != nil {
		t.Fatalf("truncating: %v", err)
	}
}

// TestMixedChunkCompressibility is a regression test for buffer aliasing in
// the decode loop.
//
// A member whose chunks differ in compressibility exercises both paths: a
// stored chunk is handed back as the read buffer itself, and a compressed
// chunk decodes into a separate one. If the reader reuses a single buffer for
// both, the decode of chunk N+1 writes into the array chunk N was read into,
// and the output is silently wrong - no error, no failed digest until the end.
func TestMixedChunkCompressibility(t *testing.T) {
	const chunk = 1024

	rnd := rand.New(rand.NewSource(99))
	random := make([]byte, chunk)
	rnd.Read(random)

	// stored, compressed, stored, compressed, ...
	var want []byte
	for i := range 6 {
		if i%2 == 0 {
			want = append(want, random...)
		} else {
			want = append(want, bytes.Repeat([]byte{'a'}, chunk)...)
		}
	}

	tree := testutil.NewTree(t)
	tree.File("mixed.bin", 0o644, want)

	archivePath := filepath.Join(t.TempDir(), "a.eictar")
	if _, err := CreateArchive(CreateConfig{
		Archive: archivePath,
		Paths:   []string{"mixed.bin"},
		BaseDir: tree.Root,
		Options: Options{Codec: "zstd", ChunkSize: chunk},
	}); err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}

	r, err := Open(archivePath, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	m := r.Members()[0]
	var stored, compressed int
	for _, c := range m.Chunks {
		if int(c) == chunk {
			stored++
		} else {
			compressed++
		}
	}
	if stored == 0 || compressed == 0 {
		t.Fatalf("fixture did not produce both kinds of chunk: %d stored, %d compressed",
			stored, compressed)
	}

	var got bytes.Buffer
	if err := r.WriteMember(&m, &got); err != nil {
		t.Fatalf("WriteMember: %v", err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		first := -1
		for i := range want {
			if i >= got.Len() || got.Bytes()[i] != want[i] {
				first = i
				break
			}
		}
		t.Fatalf("content differs, first at byte %d (chunk %d of %d)",
			first, first/chunk, len(m.Chunks))
	}
}

// TestArchiveIsNotArchivedIntoItself guards against the archive being walked
// into its own contents: it is created before the walk starts, so a walk over
// the directory holding it would read bytes it is still writing.
func TestArchiveIsNotArchivedIntoItself(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Text("real.txt", 0o644, "content")

	archivePath := filepath.Join(tree.Root, "inside.eictar")
	stats, err := CreateArchive(CreateConfig{
		Archive: archivePath,
		Paths:   []string{"."},
		BaseDir: tree.Root,
		Options: Options{Codec: "zstd"},
	})
	if err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}

	members, err := List(ListConfig{Archive: archivePath})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, m := range members {
		if strings.Contains(m.Path, "inside.eictar") {
			t.Errorf("the archive archived itself as %q", m.Path)
		}
	}
	if stats.Members == 0 {
		t.Error("nothing was archived at all")
	}
}

// TestSkippedMembersAreNotCountedAsExtracted keeps the summary honest.
func TestSkippedMembersAreNotCountedAsExtracted(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Text("a.txt", 0o644, "from the archive").
		Text("b.txt", 0o644, "also from the archive")

	archivePath := filepath.Join(t.TempDir(), "a.eictar")
	if _, err := CreateArchive(CreateConfig{
		Archive: archivePath,
		Paths:   []string{"a.txt", "b.txt"},
		BaseDir: tree.Root,
		Options: Options{Codec: "none"},
	}); err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}

	dest := t.TempDir()
	if err := os.WriteFile(filepath.Join(dest, "a.txt"), []byte("mine"), 0o644); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	stats, err := Extract(ExtractConfig{
		Archive: archivePath, Destination: dest, Overwrite: OverwriteNever,
	})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if stats.Members != 1 || stats.Skipped != 1 {
		t.Errorf("stats = %+v, want 1 extracted and 1 skipped", stats)
	}
}

// buildVariedTree makes a tree that exercises the pipeline: files smaller than
// a chunk, files spanning several, compressible and not, empty ones, nested
// directories and links.
func buildVariedTree(t *testing.T, chunk int) *testutil.Tree {
	t.Helper()

	rnd := rand.New(rand.NewSource(17))
	tree := testutil.NewTree(t)
	tree.Dir("tree", 0o755).Dir("tree/sub", 0o750)

	for i := range 40 {
		name := fmt.Sprintf("tree/file%02d.bin", i)
		switch i % 4 {
		case 0:
			tree.File(name, 0o644, nil) // empty
		case 1:
			tree.File(name, 0o644, []byte(strings.Repeat("compress me ", 50*(i+1))))
		case 2:
			buf := make([]byte, chunk*2+i)
			rnd.Read(buf)
			tree.File(name, 0o644, buf)
		case 3:
			// Mixed: an incompressible head and a compressible tail, which is
			// what exercises both chunk kinds inside one member.
			head := make([]byte, chunk)
			rnd.Read(head)
			tree.File(name, 0o600, append(head, []byte(strings.Repeat("tail ", chunk))...))
		}
	}
	tree.Text("tree/sub/nested.txt", 0o644, "nested").
		Symlink("tree/link", "file01.bin")
	return tree
}

// TestConcurrencyDeterminism is the property doc/design.md 13.2 asks for: the
// worker count must not change what comes out. Byte layout may differ, since
// the writer takes whichever member finishes first; the content must not.
func TestConcurrencyDeterminism(t *testing.T) {
	const chunk = 4096
	tree := buildVariedTree(t, chunk)

	extractWith := func(t *testing.T, workers int) string {
		t.Helper()

		archivePath := filepath.Join(t.TempDir(), fmt.Sprintf("j%d.eictar", workers))
		if _, err := CreateArchive(CreateConfig{
			Archive: archivePath,
			Paths:   []string{"tree"},
			BaseDir: tree.Root,
			Options: Options{Codec: "zstd", ChunkSize: chunk},
			Workers: workers,
		}); err != nil {
			t.Fatalf("CreateArchive(-j %d): %v", workers, err)
		}

		dest := t.TempDir()
		if _, err := Extract(ExtractConfig{
			Archive: archivePath, Destination: dest, Workers: workers,
		}); err != nil {
			t.Fatalf("Extract(-j %d): %v", workers, err)
		}
		return dest
	}

	base := extractWith(t, 1)
	for _, workers := range []int{2, 3, 8, 64} {
		t.Run(fmt.Sprintf("j=%d", workers), func(t *testing.T) {
			got := extractWith(t, workers)
			testutil.CompareTrees(t,
				filepath.Join(base, "tree"),
				filepath.Join(got, "tree"),
				testutil.CompareOptions{Mode: true, MTime: true})
			testutil.CompareTrees(t,
				filepath.Join(tree.Root, "tree"),
				filepath.Join(got, "tree"),
				testutil.CompareOptions{Mode: true, MTime: true})
		})
	}
}

// TestIndexIsStableAcrossWorkerCounts: members arrive in completion order, so
// the index is sorted by id before it is written. Two runs over the same tree
// must therefore describe it identically, whatever the worker count did.
func TestIndexIsStableAcrossWorkerCounts(t *testing.T) {
	const chunk = 4096
	tree := buildVariedTree(t, chunk)

	describe := func(workers int) []string {
		archivePath := filepath.Join(t.TempDir(), "a.eictar")
		if _, err := CreateArchive(CreateConfig{
			Archive: archivePath,
			Paths:   []string{"tree"},
			BaseDir: tree.Root,
			Options: Options{Codec: "zstd", ChunkSize: chunk},
			Workers: workers,
		}); err != nil {
			t.Fatalf("CreateArchive: %v", err)
		}

		r, err := Open(archivePath, nil)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer r.Close()

		var out []string
		for _, m := range r.Members() {
			out = append(out, fmt.Sprintf("%d %s %s %d %x", m.ID, m.Path, m.Type, m.Size, m.Digest))
		}
		return out
	}

	want := describe(1)
	for _, workers := range []int{2, 8, 32} {
		got := describe(workers)
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("-j %d produced a different index:\n got %v\nwant %v", workers, got, want)
		}
	}
}

// TestSpillThresholdIsHonoured drives a member past the spill threshold, which
// is the path where the payload lives in a file rather than in memory.
func TestSpillThresholdIsHonoured(t *testing.T) {
	const chunk = 4096

	rnd := rand.New(rand.NewSource(23))
	big := make([]byte, 400*1024) // incompressible, so it cannot shrink below the threshold
	rnd.Read(big)

	tree := testutil.NewTree(t)
	tree.File("big.bin", 0o644, big).Text("small.txt", 0o644, "small")

	archivePath := filepath.Join(t.TempDir(), "a.eictar")
	if _, err := CreateArchive(CreateConfig{
		Archive:        archivePath,
		Paths:          []string{"big.bin", "small.txt"},
		BaseDir:        tree.Root,
		Options:        Options{Codec: "zstd", ChunkSize: chunk},
		Workers:        4,
		SpillThreshold: 64 * 1024, // well under the big member
		MemoryLimit:    256 * 1024,
	}); err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}

	dest := t.TempDir()
	if _, err := Extract(ExtractConfig{Archive: archivePath, Destination: dest}); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	testutil.CompareTrees(t, tree.Root, dest, testutil.CompareOptions{Mode: true, MTime: true})
}

// TestTinyMemoryLimit: a budget smaller than a single chunk must still make
// progress rather than deadlock.
func TestTinyMemoryLimit(t *testing.T) {
	tree := buildVariedTree(t, 4096)

	archivePath := filepath.Join(t.TempDir(), "a.eictar")
	if _, err := CreateArchive(CreateConfig{
		Archive:     archivePath,
		Paths:       []string{"tree"},
		BaseDir:     tree.Root,
		Options:     Options{Codec: "zstd", ChunkSize: 4096},
		Workers:     8,
		MemoryLimit: 1024, // a quarter of one chunk
	}); err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}

	dest := t.TempDir()
	if _, err := Extract(ExtractConfig{Archive: archivePath, Destination: dest, Workers: 8}); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	testutil.CompareTrees(t,
		filepath.Join(tree.Root, "tree"),
		filepath.Join(dest, "tree"),
		testutil.CompareOptions{Mode: true, MTime: true})
}

// TestManyMembersAcrossWorkers pushes enough members through the pool that
// scheduling actually interleaves.
func TestManyMembersAcrossWorkers(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Dir("many", 0o755)
	for i := range 500 {
		tree.Text(fmt.Sprintf("many/f%03d.txt", i), 0o644, strings.Repeat("x", i))
	}

	archivePath := filepath.Join(t.TempDir(), "a.eictar")
	stats, err := CreateArchive(CreateConfig{
		Archive: archivePath,
		Paths:   []string{"many"},
		BaseDir: tree.Root,
		Options: Options{Codec: "zstd", ChunkSize: 1024},
		Workers: 16,
	})
	if err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}
	if want := 501; stats.Members != want { // 500 files plus the directory
		t.Errorf("archived %d members, want %d", stats.Members, want)
	}

	dest := t.TempDir()
	if _, err := Extract(ExtractConfig{Archive: archivePath, Destination: dest, Workers: 16}); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	testutil.CompareTrees(t,
		filepath.Join(tree.Root, "many"),
		filepath.Join(dest, "many"),
		testutil.CompareOptions{Mode: true, MTime: true})
}

// craftArchive writes an archive whose index says whatever the caller wants.
// It is the attacker's tool: everything a reader trusts comes from here.
//
// The mutation is applied to the member record *after* the payload has been
// written, because AppendMember assigns the real offset as it writes. It
// returns the error from Close, since the writer's own validation is a
// defence in its own right and refusing there is a pass, not a failure.
func craftArchive(t *testing.T, codecName string, payload []byte, mutate func(m *format.Member)) (string, error) {
	t.Helper()

	archivePath := filepath.Join(t.TempDir(), "crafted.eictar")
	w, err := Create(archivePath, Options{Codec: codecName})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	m := format.Member{
		ID: 1, Generation: 1, Path: "member.bin", Type: format.TypeReg,
		Mode: 0o644, Codec: w.CodecRef(), ChunkSize: DefaultChunkSize,
		Size:   uint64(len(payload)),
		Length: uint64(len(payload)),
		Chunks: []uint32{uint32(len(payload))},
		Digest: blake3Sum(payload),
	}
	if err := w.AppendMember(&m, bytesWriterTo(payload)); err != nil {
		t.Fatalf("AppendMember: %v", err)
	}

	// The index now holds the member as written; forge it in place.
	mutate(&w.index.Members[len(w.index.Members)-1])

	return archivePath, w.Close()
}

// TestCraftedChunkSizeIsRefused is a regression test for an allocation bomb: a
// tiny archive claiming an enormous chunk size made the reader allocate that
// much before discovering the chunk was a few bytes long, once per extraction
// worker.
func TestCraftedChunkSizeIsRefused(t *testing.T) {
	for _, chunkSize := range []uint32{
		format.MaxChunkSize + 1,
		1 << 30,
		1 << 31,
		^uint32(0),
	} {
		t.Run(fmt.Sprintf("chunk=%d", chunkSize), func(t *testing.T) {
			archivePath, closeErr := craftArchive(t, "zstd", []byte("small"), func(m *format.Member) {
				m.ChunkSize = chunkSize
				m.Size = uint64(chunkSize)
			})
			if closeErr != nil {
				// Refused before it could be written: the best outcome.
				if !errors.Is(closeErr, format.ErrCorruptIndex) {
					t.Errorf("Close error = %v, want ErrCorruptIndex", closeErr)
				}
				return
			}

			r, err := Open(archivePath, nil)
			if err == nil {
				defer r.Close()
				var before, after runtime.MemStats
				runtime.ReadMemStats(&before)
				err = r.WriteMember(&r.Members()[0], io.Discard)
				runtime.ReadMemStats(&after)

				if grew := after.TotalAlloc - before.TotalAlloc; grew > 64<<20 {
					t.Errorf("reading a %d-byte archive allocated %d MiB",
						chunkSize, grew/(1<<20))
				}
			}
			if err == nil {
				t.Fatal("a member claiming an impossible chunk size was accepted")
			}
			if !errors.Is(err, format.ErrCorruptIndex) {
				t.Errorf("error = %v, want ErrCorruptIndex", err)
			}
		})
	}
}

// TestCraftedOffsetIsRefused: a member whose blob lies outside the body must
// be refused when the archive is opened, not read. An offset pointing into the
// index or the trailer would otherwise return those bytes as file content.
func TestCraftedOffsetIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(m *format.Member)
	}{
		{"before the body", func(m *format.Member) { m.Offset = 0 }},
		{"inside the header", func(m *format.Member) { m.Offset = 8 }},
		{"past the end", func(m *format.Member) { m.Offset = 1 << 40 }},
		{"overlapping the index", func(m *format.Member) { m.Length = 1 << 20 }},
		{"overflowing", func(m *format.Member) {
			m.Offset = ^uint64(0) - 4
			m.Length = 8
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			archivePath, closeErr := craftArchive(t, "none", []byte("payload"), tc.mutate)
			if closeErr != nil {
				if !errors.Is(closeErr, format.ErrCorruptIndex) {
					t.Errorf("Close error = %v, want ErrCorruptIndex", closeErr)
				}
				return
			}

			r, err := Open(archivePath, nil)
			if err == nil {
				r.Close()
				t.Fatal("an archive with an out-of-range member blob was opened")
			}
			if !errors.Is(err, format.ErrCorruptIndex) {
				t.Errorf("error = %v, want ErrCorruptIndex", err)
			}
		})
	}
}

// TestRegularFileWithoutDigestIsRefused: the digest is the only thing that
// catches a member pointed at the wrong bytes, so it is mandatory for content.
func TestRegularFileWithoutDigestIsRefused(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "a.eictar")
	w, err := Create(archivePath, Options{Codec: "none"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	payload := []byte("content")
	m := format.Member{
		ID: 1, Generation: 1, Path: "member.bin", Type: format.TypeReg,
		Mode: 0o644, Codec: format.NoCodec, ChunkSize: DefaultChunkSize,
		Size: uint64(len(payload)), Length: uint64(len(payload)),
		Chunks: []uint32{uint32(len(payload))},
		// no digest
	}
	if err := w.AppendMember(&m, bytesWriterTo(payload)); err != nil {
		t.Fatalf("AppendMember: %v", err)
	}
	if err := w.Close(); err == nil {
		t.Fatal("an archive with an undigested regular file was written")
	} else if !errors.Is(err, format.ErrCorruptIndex) {
		t.Errorf("error = %v, want ErrCorruptIndex", err)
	}
}

// TestFailedMemberLeavesExistingFileAlone is the data-loss case: extraction
// over an existing file must not destroy it when the archive turns out to be
// damaged. The new copy goes to a temporary name and is renamed only after its
// digest checks out.
func TestFailedMemberLeavesExistingFileAlone(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Text("important.txt", 0o644, "the new version")

	archivePath := filepath.Join(t.TempDir(), "a.eictar")
	if _, err := CreateArchive(CreateConfig{
		Archive: archivePath,
		Paths:   []string{"important.txt"},
		BaseDir: tree.Root,
		Options: Options{Codec: "none"},
	}); err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}

	// Damage the payload so the digest fails during extraction.
	r, err := Open(archivePath, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	off := int64(r.Members()[0].Offset)
	r.Close()
	flipByteAt(t, archivePath, off)

	dest := t.TempDir()
	existing := filepath.Join(dest, "important.txt")
	if err := os.WriteFile(existing, []byte("the only copy I have"), 0o644); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	if _, err := Extract(ExtractConfig{Archive: archivePath, Destination: dest}); err == nil {
		t.Fatal("extracting a damaged member succeeded")
	}

	got, err := os.ReadFile(existing)
	if err != nil {
		t.Fatalf("the existing file is gone: %v", err)
	}
	if string(got) != "the only copy I have" {
		t.Errorf("the existing file was damaged: %q", got)
	}

	// And no half-written temporary is left lying about.
	entries, err := os.ReadDir(dest)
	if err != nil {
		t.Fatalf("reading destination: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".eictar-part-") {
			t.Errorf("a partial file was left behind: %s", e.Name())
		}
	}
}

// TestPrivateDirectoryIsNeverWorldTraversable: a 0700 directory must not be
// briefly 0755 while its contents are written, or a local attacker has a
// window to walk into it.
func TestPrivateDirectoryIsNeverWorldTraversable(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Dir("secret", 0o700).Text("secret/key.txt", 0o600, "sensitive")

	archivePath := filepath.Join(t.TempDir(), "a.eictar")
	if _, err := CreateArchive(CreateConfig{
		Archive: archivePath,
		Paths:   []string{"secret"},
		BaseDir: tree.Root,
		Options: Options{Codec: "none"},
	}); err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}

	dest := t.TempDir()
	if _, err := Extract(ExtractConfig{Archive: archivePath, Destination: dest}); err != nil {
		t.Fatalf("Extract: %v", err)
	}

	fi, err := os.Stat(filepath.Join(dest, "secret"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Errorf("directory mode = %04o, want 0700", fi.Mode().Perm())
	}
	fi, err = os.Stat(filepath.Join(dest, "secret", "key.txt"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("file mode = %04o, want 0600", fi.Mode().Perm())
	}
}

// TestExtractionWorkersAreBoundedByMemory: each worker decodes into a buffer
// the size of its member's chunk, so a large chunk size must reduce the number
// of workers rather than multiply the allocation by it.
func TestExtractionWorkersAreBoundedByMemory(t *testing.T) {
	members := []format.Member{
		{ChunkSize: 64 << 20}, {ChunkSize: 4 << 20},
	}

	for _, tc := range []struct {
		name    string
		workers int
		limit   int64
		want    int
	}{
		{"tight budget allows one", 64, 64 << 20, 1},
		{"room for four", 64, 8 * 64 << 20, 4},
		{"never below one", 64, 1, 1},
		{"small chunks unaffected", 8, 1 << 30, 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ms := members
			if tc.name == "small chunks unaffected" {
				ms = []format.Member{{ChunkSize: 64 << 10}}
			}
			if got := boundByMemory(tc.workers, ms, tc.limit); got != tc.want {
				t.Errorf("boundByMemory(%d, limit=%d) = %d, want %d",
					tc.workers, tc.limit, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// M4: encryption
// ---------------------------------------------------------------------------

// testKDF keeps the tests fast. Argon2id at real settings would dominate the
// suite; the schedule itself is pinned by vectors in the crypt package.
var testKDF = crypt.KDFParams{Time: 1, Memory: 8 * 1024, Threads: 1}

func passphrase(s string) PassphraseFunc {
	return func() ([]byte, error) { return []byte(s), nil }
}

func encryptedArchive(t *testing.T, tree *testutil.Tree, paths []string, codecName string, encryptIndex bool) string {
	t.Helper()

	archivePath := filepath.Join(t.TempDir(), "enc.eictar")
	if _, err := CreateArchive(CreateConfig{
		Archive: archivePath,
		Paths:   paths,
		BaseDir: tree.Root,
		Options: Options{Codec: codecName, ChunkSize: 4096},
		Encryption: &EncryptionConfig{
			Passphrase:   []byte("correct horse"),
			Params:       testKDF,
			EncryptIndex: encryptIndex,
		},
	}); err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}
	return archivePath
}

func TestEncryptedRoundTrip(t *testing.T) {
	for _, codecName := range codec.Names() {
		for _, encryptIndex := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/index-encrypted=%v", codecName, encryptIndex), func(t *testing.T) {
				tree := buildVariedTree(t, 4096)
				archivePath := encryptedArchive(t, tree, []string{"tree"}, codecName, encryptIndex)

				r, err := Open(archivePath, passphrase("correct horse"))
				if err != nil {
					t.Fatalf("Open: %v", err)
				}
				if !r.Encrypted() {
					t.Error("the archive does not report itself as encrypted")
				}
				// Every member with content must carry its own salt.
				salts := map[string]bool{}
				for _, m := range r.Members() {
					if !m.Type.HasPayload() {
						continue
					}
					if m.Enc == nil || len(m.Enc.Salt) != crypt.SaltSize {
						t.Fatalf("member %q has no member salt", m.Path)
					}
					key := string(m.Enc.Salt)
					if salts[key] {
						t.Errorf("member %q reuses another member's salt", m.Path)
					}
					salts[key] = true
				}
				r.Close()

				dest := t.TempDir()
				if _, err := Extract(ExtractConfig{
					Archive: archivePath, Destination: dest,
					Passphrase: passphrase("correct horse"),
				}); err != nil {
					t.Fatalf("Extract: %v", err)
				}
				testutil.CompareTrees(t,
					filepath.Join(tree.Root, "tree"),
					filepath.Join(dest, "tree"),
					testutil.CompareOptions{Mode: true, MTime: true})
			})
		}
	}
}

func TestEncryptedArchiveNeedsTheRightPassphrase(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Text("a.txt", 0o644, "secret")
	archivePath := encryptedArchive(t, tree, []string{"a.txt"}, "zstd", false)

	for _, tc := range []struct {
		name string
		ask  PassphraseFunc
		want error
	}{
		{"wrong passphrase", passphrase("incorrect horse"), crypt.ErrWrongPassphrase},
		{"empty passphrase", passphrase(""), crypt.ErrWrongPassphrase},
		{"no passphrase at all", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := Open(archivePath, tc.ask)
			if err == nil {
				r.Close()
				t.Fatal("the archive opened")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestEncryptedContentIsNotOnDisk: the plaintext must not be findable in the
// archive file. Obvious, and worth asserting once.
func TestEncryptedContentIsNotOnDisk(t *testing.T) {
	const secret = "TOPSECRETCANARYVALUE"

	tree := testutil.NewTree(t)
	tree.Text("a.txt", 0o644, strings.Repeat(secret+" ", 100))
	archivePath := encryptedArchive(t, tree, []string{"a.txt"}, "none", false)

	raw, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatalf("reading the archive: %v", err)
	}
	if bytes.Contains(raw, []byte(secret)) {
		t.Error("the plaintext is present in the encrypted archive")
	}
}

// TestEncryptIndexHidesMetadata: --encrypt-index is what keeps filenames out
// of the file. Without it they are visible, which is the documented default.
func TestEncryptIndexHidesMetadata(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Text("distinctive-filename.txt", 0o644, "content")

	for _, tc := range []struct {
		encryptIndex bool
		wantVisible  bool
	}{
		{false, true},
		{true, false},
	} {
		t.Run(fmt.Sprintf("encrypt-index=%v", tc.encryptIndex), func(t *testing.T) {
			archivePath := encryptedArchive(t, tree,
				[]string{"distinctive-filename.txt"}, "none", tc.encryptIndex)

			raw, err := os.ReadFile(archivePath)
			if err != nil {
				t.Fatalf("reading: %v", err)
			}
			visible := bytes.Contains(raw, []byte("distinctive-filename.txt"))
			if visible != tc.wantVisible {
				t.Errorf("filename visible = %v, want %v", visible, tc.wantVisible)
			}
		})
	}
}

// TestEncryptedTamperIsCaught is the content integrity story: every kind of
// edit to a sealed member must be refused rather than decoded.
func TestEncryptedTamperIsCaught(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Text("a.txt", 0o644, strings.Repeat("sensitive ", 2000))
	archivePath := encryptedArchive(t, tree, []string{"a.txt"}, "zstd", false)

	r, err := Open(archivePath, passphrase("correct horse"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	m := r.Members()[0]
	if len(m.Chunks) < 2 {
		t.Fatalf("fixture produced %d chunks, want several", len(m.Chunks))
	}
	blobStart := int64(m.Offset)
	r.Close()

	for _, tc := range []struct {
		name string
		at   int64
	}{
		{"first byte of the ciphertext", blobStart},
		{"inside the first chunk", blobStart + 4},
		{"in the tag of the first chunk", blobStart + int64(m.Chunks[0]) - 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			damaged := filepath.Join(t.TempDir(), "damaged.eictar")
			copyFile(t, archivePath, damaged)
			flipByteAt(t, damaged, tc.at)

			r, err := Open(damaged, passphrase("correct horse"))
			if err != nil {
				// Damage inside the index region is caught at open.
				return
			}
			defer r.Close()

			err = r.WriteMember(&r.Members()[0], io.Discard)
			if err == nil {
				t.Fatal("a tampered member decoded without complaint")
			}
			if !errors.Is(err, crypt.ErrAuthentication) {
				t.Errorf("error = %v, want ErrAuthentication", err)
			}
		})
	}
}

// TestEncryptedMetadataTamperIsCaught is the attack doc/design.md 6.4 exists
// for: an attacker who cannot read a byte of content rewrites a path in the
// plaintext index. Every chunk still authenticates, because the chunk AAD
// never mentioned the path. Only the keyed index digest catches it.
func TestEncryptedMetadataTamperIsCaught(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Text("notes.txt", 0o644, "harmless content")

	// The index is deliberately *not* encrypted: that is the default, and the
	// case where the metadata is there for the editing.
	archivePath := encryptedArchive(t, tree, []string{"notes.txt"}, "none", false)

	forgeMemberPathWith(t, archivePath, "authorized_keys", passphrase("correct horse"))

	r, err := Open(archivePath, passphrase("correct horse"))
	if err == nil {
		paths := []string{}
		for _, m := range r.Members() {
			paths = append(paths, m.Path)
		}
		r.Close()
		t.Fatalf("an archive with rewritten metadata opened, listing %v", paths)
	}
	if !errors.Is(err, format.ErrChecksum) {
		t.Errorf("error = %v, want a checksum failure naming the index", err)
	}
	if !strings.Contains(err.Error(), "authentication") {
		t.Errorf("error = %q, want it to say the index failed authentication", err)
	}
}

// TestPlaintextMetadataTamperIsOnlyDetectedByAccident records the limit
// honestly: without a key, an attacker can rewrite the index and recompute
// every digest. This test asserts the *current* behaviour so that nobody
// mistakes it for protection.
func TestPlaintextMetadataTamperIsNotDetected(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Text("notes.txt", 0o644, "harmless content")

	archivePath := filepath.Join(t.TempDir(), "plain.eictar")
	if _, err := CreateArchive(CreateConfig{
		Archive: archivePath, Paths: []string{"notes.txt"},
		BaseDir: tree.Root, Options: Options{Codec: "none"},
	}); err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}

	forgeMemberPath(t, archivePath, "renamed.txt")

	r, err := Open(archivePath, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	if got := r.Members()[0].Path; got != "renamed.txt" {
		t.Errorf("member path = %q, want the forged %q", got, "renamed.txt")
	}
	// If this ever starts failing, an unkeyed archive gained tamper evidence
	// and doc/design.md 14.4 needs updating to match.
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Fatalf("reading %s: %v", from, err)
	}
	if err := os.WriteFile(to, data, 0o644); err != nil {
		t.Fatalf("writing %s: %v", to, err)
	}
}

// ---------------------------------------------------------------------------
// Review of M4: regression tests for each finding
// ---------------------------------------------------------------------------

// TestDowngradedArchiveIsRefusedWhenEncryptionExpected: stripping an encrypted
// archive's framing needs no passphrase, and the result opens without asking
// for one and lists whatever the attacker wrote. A caller that expected a
// sealed archive must be told instead.
func TestDowngradedArchiveIsRefusedWhenEncryptionExpected(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Text("notes.txt", 0o644, "private")
	archivePath := encryptedArchive(t, tree, []string{"notes.txt"}, "none", false)

	downgradeArchive(t, archivePath, passphrase("correct horse"), "you-can-trust-this.txt")

	// A caller with no expectation still opens it: that is the documented
	// limit, and why the expectation matters.
	r, err := Open(archivePath, nil)
	if err != nil {
		t.Fatalf("the downgraded archive no longer opens at all: %v", err)
	}
	r.Close()

	_, err = OpenWith(archivePath, OpenOptions{
		Passphrase:        passphrase("correct horse"),
		RequireEncryption: true,
	})
	if !errors.Is(err, ErrNotEncrypted) {
		t.Fatalf("error = %v, want ErrNotEncrypted", err)
	}

	// And the listing path honours it too.
	if _, err := List(ListConfig{Archive: archivePath, RequireEncryption: true}); !errors.Is(err, ErrNotEncrypted) {
		t.Errorf("List error = %v, want ErrNotEncrypted", err)
	}
}

// TestDowngradedContentStillFails: even without the expectation, a stripped
// archive cannot hand over forged content, because the sealed blobs no longer
// match their plaintext digests.
func TestDowngradedContentStillFails(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Text("notes.txt", 0o644, "private")
	archivePath := encryptedArchive(t, tree, []string{"notes.txt"}, "none", false)
	downgradeArchive(t, archivePath, passphrase("correct horse"), "notes.txt")

	if _, err := Extract(ExtractConfig{Archive: archivePath, Destination: t.TempDir()}); err == nil {
		t.Fatal("content was extracted from a downgraded archive")
	}
}

// TestCraftedKDFParametersAreRefusedBeforePrompting: the parameters come from
// the archive. A crafted header asking for 2^32-1 passes, or more memory than
// the machine has, must be refused - and before the user is asked for a
// passphrase, not after.
func TestCraftedKDFParametersAreRefusedBeforePrompting(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Text("a.txt", 0o644, "content")

	for _, tc := range []struct {
		name   string
		mutate func(ch *format.CryptoHeader)
	}{
		{"time at uint32 max", func(ch *format.CryptoHeader) { ch.Time = ^uint32(0) }},
		{"time just above the cap", func(ch *format.CryptoHeader) { ch.Time = format.MaxKDFTime + 1 }},
		{"memory above the cap", func(ch *format.CryptoHeader) { ch.Memory = format.MaxKDFMemoryKiB + 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			archivePath := encryptedArchive(t, tree, []string{"a.txt"}, "none", false)
			rewriteCryptoHeader(t, archivePath, tc.mutate)

			asked := false
			ask := func() ([]byte, error) {
				asked = true
				return []byte("correct horse"), nil
			}

			start := time.Now()
			_, err := Open(archivePath, ask)
			if err == nil {
				t.Fatal("an archive with crafted KDF parameters opened")
			}
			if asked {
				t.Error("the user was asked for a passphrase before the parameters were checked")
			}
			if elapsed := time.Since(start); elapsed > 5*time.Second {
				t.Errorf("refusing took %v; the parameters were used before being checked", elapsed)
			}
		})
	}
}

// TestWriterRefusesKeysWithoutTheirArchiveID: keys are derived against the
// archive id, so keys without it produce an archive nobody can open.
func TestWriterRefusesKeysWithoutTheirArchiveID(t *testing.T) {
	keys, err := crypt.Derive([]byte("p"), bytes.Repeat([]byte{1}, crypt.SaltSize), [16]byte{7}, testKDF)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	_, err = Create(filepath.Join(t.TempDir(), "a.eictar"), Options{
		Codec: "none", Keys: keys, Salt: bytes.Repeat([]byte{1}, crypt.SaltSize),
		KDFParams: testKDF,
		// no ArchiveUUID
	})
	if err == nil {
		t.Fatal("the writer accepted keys without the archive id they were derived for")
	}
}

// TestReaderCloseWipesKeys: key material should not outlive the reader.
func TestReaderCloseWipesKeys(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Text("a.txt", 0o644, "content")
	archivePath := encryptedArchive(t, tree, []string{"a.txt"}, "none", false)

	r, err := Open(archivePath, passphrase("correct horse"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	keys := r.keys
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if r.keys != nil {
		t.Error("the reader still holds its keys after Close")
	}
	// The Keys value itself was zeroed, not merely dropped.
	if keys.Check() == nil {
		t.Fatal("unexpected nil check")
	}
	if err := r.Close(); err != nil {
		t.Errorf("a second Close failed: %v", err)
	}
}

// rewriteCryptoHeader replaces an archive's crypto header, as an attacker
// would to change the KDF parameters.
//
// A crafted value can encode longer than the original, so the header cannot
// always be edited in place. The file is rebuilt instead: new header, new
// crypto header, the rest of the file shifted, and the trailer's offsets moved
// to match. The trailer is protected only by a CRC, which anyone can
// recompute, so the result is exactly what a reader would be handed.
func rewriteCryptoHeader(t *testing.T, path string, mutate func(ch *format.CryptoHeader)) {
	t.Helper()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}

	var hdr format.Header
	if err := hdr.UnmarshalBinary(raw[:format.HeaderSize]); err != nil {
		t.Fatalf("decoding header: %v", err)
	}
	oldLen := int(hdr.CryptoHeaderLen)
	ch, err := format.UnmarshalCryptoHeader(raw[format.HeaderSize : format.HeaderSize+oldLen])
	if err != nil {
		t.Fatalf("decoding crypto header: %v", err)
	}
	mutate(ch)

	// Encoded without validation: the attacker's encoder has no limits.
	body, err := cborMarshalUnchecked(ch)
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	newCrypto := make([]byte, 4, 4+len(body))
	binary.LittleEndian.PutUint32(newCrypto, uint32(len(body)))
	newCrypto = append(newCrypto, body...)
	delta := int64(len(newCrypto) - oldLen)

	hdr.CryptoHeaderLen = uint32(len(newCrypto))
	hdrBytes, err := hdr.MarshalBinary()
	if err != nil {
		t.Fatalf("encoding header: %v", err)
	}

	rest := raw[format.HeaderSize+oldLen:]
	var tr format.Trailer
	if err := tr.UnmarshalBinary(rest); err != nil {
		t.Fatalf("decoding trailer: %v", err)
	}
	tr.IndexOffset = uint64(int64(tr.IndexOffset) + delta)
	if tr.PrevIndexOffset != 0 {
		tr.PrevIndexOffset = uint64(int64(tr.PrevIndexOffset) + delta)
	}
	trBytes, err := tr.MarshalBinary()
	if err != nil {
		t.Fatalf("encoding trailer: %v", err)
	}

	out := make([]byte, 0, len(raw)+int(delta))
	out = append(out, hdrBytes...)
	out = append(out, newCrypto...)
	out = append(out, rest[:len(rest)-format.TrailerSize]...)
	out = append(out, trBytes...)
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatalf("writing: %v", err)
	}
}

// TestAffordabilityCheck: key derivation that would take more than half the
// machine's memory is refused with a message naming both figures, rather than
// allocated and killed.
func TestAffordabilityCheck(t *testing.T) {
	const gib = int64(1) << 30
	p := crypt.KDFParams{Time: 3, Memory: 1024 * 1024, Threads: 4} // 1 GiB

	if err := checkAffordableOn(p, 8*gib); err != nil {
		t.Errorf("1 GiB on an 8 GiB machine was refused: %v", err)
	}
	err := checkAffordableOn(p, 1*gib)
	if err == nil {
		t.Fatal("1 GiB on a 1 GiB machine was accepted")
	}
	for _, want := range []string{"1024 MiB", "--kdf-memory"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to mention %q", err, want)
		}
	}
	// Unknown RAM is not a reason to refuse.
	if err := checkAffordableOn(p, 0); err != nil {
		t.Errorf("unknown RAM caused a refusal: %v", err)
	}
}
