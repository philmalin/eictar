//go:build unix

package archive

import (
	"bytes"
	"errors"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/philmalin/eictar/src/internal/codec"
	"github.com/philmalin/eictar/src/internal/crypt"
	"github.com/philmalin/eictar/src/internal/format"
	"github.com/philmalin/eictar/src/internal/meta"
	"github.com/philmalin/eictar/src/internal/testutil"
)

// Tests of --encrypt-archive (doc/design.md 9.11). The fault and power-loss
// tests of fault_test.go and crash_test.go also run it (writeCases).

// encryptWith is the configuration of the tests: the new passphrase is
// "battery staple".
func encryptWith(workers int) *EncryptArchiveConfig {
	return &EncryptArchiveConfig{Passphrase: passphrase("battery staple"), Params: testKDF, EncryptIndex: true, Workers: workers}
}

var newPassphrase = OpenOptions{Passphrase: passphrase("battery staple")}

// encryptTree has each member type, content that compresses and content
// that does not, a file with holes, two files with the same content, and
// files for a dictionary.
func encryptTree(t *testing.T) *testutil.Tree {
	t.Helper()
	tree := dictTree(t, "src", 20)
	noise := make([]byte, 10000)
	rng := rand.New(rand.NewPCG(1, 2))
	for i := range noise {
		noise[i] = byte(rng.Uint32())
	}
	tree.Dir("t", 0o755)
	tree.Text("t/a.txt", 0o644, strings.Repeat("several chunks of alpha. ", 800))
	tree.Text("t/same.txt", 0o644, strings.Repeat("several chunks of alpha. ", 800))
	tree.File("t/noise.bin", 0o644, noise)
	tree.Text("t/empty", 0o644, "")
	tree.Hardlink("t/hard", "t/a.txt")
	tree.Symlink("t/link", "a.txt")
	tree.Fifo("t/fifo", 0o644)
	tree.Sparse("t/holes", 0o644, 1<<20, testutil.Segment{Offset: 1 << 19, Data: []byte("data in the middle of holes")})
	return tree
}

// plainArchive makes a plaintext archive of encryptTree with a dictionary.
// Then it replaces t/a.txt: the old one becomes a tombstone that t/same.txt
// and t/hard still need, and t/b.txt goes, which leaves dead space.
func plainArchive(t *testing.T, tree *testutil.Tree) string {
	t.Helper()
	tree.Text("t/b.txt", 0o644, "bravo")
	path := filepath.Join(t.TempDir(), "p.ect")
	if _, err := CreateArchive(CreateConfig{Archive: path, Paths: []string{"src", "t"}, BaseDir: tree.Root, Workers: 2,
		Options: Options{Codec: "zstd", ChunkSize: 4096, Params: codec.Params{"train": "4K"}}}); err != nil {
		t.Fatal(err)
	}
	tree.Text("t/a.txt", 0o644, "alpha, changed")
	if _, err := appendTo(t, path, tree, false, nil, "t/a.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := DeleteMembers(DeleteConfig{Archive: path, Patterns: []string{"t/b.txt"}}); err != nil {
		t.Fatal(err)
	}
	return path
}

// oldBlobs gives the chunks and the dictionaries of a plaintext archive as
// they are on disk.
func oldBlobs(t *testing.T, path string) [][]byte {
	t.Helper()
	r, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	file := readAll(t, path)
	var blobs [][]byte
	for _, m := range r.AllMembers() {
		off := m.Offset
		for _, n := range m.Chunks {
			blobs = append(blobs, file[off:off+uint64(n)])
			off += uint64(n)
		}
	}
	for _, d := range r.index.Dicts {
		blobs = append(blobs, file[d.Offset:d.Offset+d.Length])
	}
	blobs = append(blobs, file[r.tr.IndexOffset:r.tr.IndexOffset+r.tr.IndexLength])
	return blobs
}

// TestEncryptArchive: the encrypted archive holds the same members, with
// the same metadata and content, and none of the bytes of the plaintext
// archive.
func TestEncryptArchive(t *testing.T) {
	tree := encryptTree(t)
	path := plainArchive(t, tree)
	before := membersByID(t, path, false)
	stateBefore, err := archiveState(path, []OpenOptions{{}})
	if err != nil {
		t.Fatal(err)
	}
	blobs := oldBlobs(t, path)
	old, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	oldHdr, oldTr, oldDicts := old.hdr, old.tr, old.index.Dicts
	old.Close()
	if len(oldDicts) == 0 {
		t.Fatal("the plaintext archive has no dictionary")
	}
	plainDest := t.TempDir()
	if _, err := Extract(ExtractConfig{Archive: path, Destination: plainDest}); err != nil {
		t.Fatal(err)
	}

	res, err := CompactArchive(CompactConfig{Archive: path, Encrypt: encryptWith(2)})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if res.Dropped != 1 || res.Sealed == 0 {
		t.Errorf("result %+v: want t/b.txt dropped, and members sealed", res)
	}

	if _, err := Open(path, nil); err == nil {
		t.Fatal("the encrypted archive opens with no passphrase")
	}
	r, err := OpenWith(path, newPassphrase)
	if err != nil {
		t.Fatalf("open with the new passphrase: %v", err)
	}
	if r.hdr.ArchiveUUID != oldHdr.ArchiveUUID || r.hdr.CreatedUnixNanos != oldHdr.CreatedUnixNanos {
		t.Error("the uuid or the creation time changed")
	}
	if !r.hdr.Encrypted() || !r.tr.IndexEncrypted() || r.tr.Generation != oldTr.Generation+1 {
		t.Errorf("header flags %x, trailer %+v: want encrypted, a sealed index, generation %d", r.hdr.Flags, r.tr, oldTr.Generation+1)
	}
	if got := (crypt.KDFParams{Time: r.crypto.Time, Memory: r.crypto.Memory, Threads: r.crypto.Threads}); got != testKDF {
		t.Errorf("KDF parameters %+v, want %+v", got, testKDF)
	}

	sealed, shares := 0, 0
	for _, m := range r.AllMembers() {
		o, ok := before[m.ID]
		if !ok {
			t.Errorf("%s: a new member id %d", m.Path, m.ID)
			continue
		}
		if m.Path != o.Path || m.Type != o.Type || m.Mode != o.Mode || m.Size != o.Size || m.MTimeNanos != o.MTimeNanos ||
			m.LinkTarget != o.LinkTarget || m.HardlinkTo != o.HardlinkTo || m.Data != o.Data || m.Dead != o.Dead ||
			m.Codec != o.Codec || m.ChunkSize != o.ChunkSize || len(m.Sparse) != len(o.Sparse) {
			t.Errorf("%s: the metadata changed:\n%+v\n%+v", m.Path, o, m)
		}
		if len(o.Digest) > 0 && (len(m.Digest) != format.DigestSize || bytes.Equal(m.Digest, o.Digest)) {
			t.Errorf("%s: digest %x, was %x: want a new keyed one", m.Path, m.Digest, o.Digest)
		}
		if m.Data != 0 {
			shares++
		}
		if len(o.Chunks) == 0 {
			if m.Enc != nil || m.Length != 0 {
				t.Errorf("%s: no blob before, enc %+v and length %d after", m.Path, m.Enc, m.Length)
			}
			continue
		}
		sealed++
		if m.Enc == nil || len(m.Chunks) != len(o.Chunks) {
			t.Errorf("%s: enc %+v, %d chunks (was %d)", m.Path, m.Enc, len(m.Chunks), len(o.Chunks))
			continue
		}
		for i := range m.Chunks {
			if m.Chunks[i] != o.Chunks[i]+16 {
				t.Errorf("%s: chunk %d is %d bytes, was %d: want the tag added", m.Path, i, m.Chunks[i], o.Chunks[i])
			}
		}
	}
	// Pass B keeps the order of the blobs in the file.
	byOld := r.AllMembers()
	sort.Slice(byOld, func(i, j int) bool { return before[byOld[i].ID].Offset < before[byOld[j].ID].Offset })
	var last uint64
	for _, m := range byOld {
		if m.Length == 0 {
			continue
		}
		if m.Offset < last {
			t.Errorf("%s: at %d, before the blob that was before it (%d)", m.Path, m.Offset, last)
		}
		last = m.Offset
	}
	if sealed != res.Sealed || shares == 0 {
		t.Errorf("%d members sealed, the result says %d; %d members share content", sealed, res.Sealed, shares)
	}
	if len(r.index.Dicts) != len(oldDicts) {
		t.Fatalf("%d dictionaries, was %d", len(r.index.Dicts), len(oldDicts))
	}
	for i, d := range r.index.Dicts {
		o := oldDicts[i]
		if d.ID != o.ID || d.Generation != o.Generation || d.Size != o.Size || d.Enc == nil ||
			bytes.Equal(d.Digest, o.Digest) || d.Length != o.Length+16 {
			t.Errorf("dictionary %+v, was %+v: want the same id, sealed, with a keyed digest", d, o)
		}
	}
	r.Close()

	if _, err := VerifyArchive(VerifyConfig{Archive: path, Open: newPassphrase}); err != nil {
		t.Errorf("verify: %v", err)
	}
	stateAfter, err := archiveState(path, []OpenOptions{newPassphrase})
	if err != nil {
		t.Fatal(err)
	}
	if stateAfter != stateBefore {
		t.Errorf("the state changed:\n%s\nwas\n%s", stateAfter, stateBefore)
	}
	dest := t.TempDir()
	if _, err := Extract(ExtractConfig{Archive: path, Destination: dest, Passphrase: newPassphrase.Passphrase}); err != nil {
		t.Fatal(err)
	}
	testutil.CompareTrees(t, plainDest, dest, testutil.CompareOptions{Mode: true, Holes: meta.Supports.Holes})

	file := readAll(t, path)
	for i, b := range blobs {
		if len(b) >= 16 && bytes.Contains(file, b) {
			t.Errorf("blob %d of the plaintext archive (%d bytes) is in the encrypted file", i, len(b))
		}
	}
	for _, p := range []string{"src/f000.go", "t/same.txt", "t/holes", "data in the middle"} {
		if bytes.Contains(file, []byte(p)) {
			t.Errorf("%q is in the encrypted file", p)
		}
	}
}

// TestEncryptArchiveWithoutEncryptIndex: the index is authenticated and not
// sealed, as for a create with -e and without --encrypt-index.
func TestEncryptArchiveWithoutEncryptIndex(t *testing.T) {
	path := mkArchive(t, mutTree(t), false, "t")
	ec := encryptWith(1)
	ec.EncryptIndex = false
	if _, err := CompactArchive(CompactConfig{Archive: path, Encrypt: ec}); err != nil {
		t.Fatal(err)
	}
	r, err := OpenWith(path, newPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if !r.hdr.Encrypted() || r.tr.IndexEncrypted() {
		t.Errorf("header flags %x, trailer flags %x: want encrypted, and the index not sealed", r.hdr.Flags, r.tr.Flags)
	}
}

// TestEncryptArchiveRefusesAnEncryptedArchive: an encrypted archive stops the
// run before any passphrase is asked, and nothing changes.
func TestEncryptArchiveRefusesAnEncryptedArchive(t *testing.T) {
	path := mkArchive(t, mutTree(t), true, "t")
	before := readAll(t, path)
	ec := &EncryptArchiveConfig{Passphrase: func() ([]byte, error) {
		t.Error("a passphrase was asked")
		return []byte("x"), nil
	}}
	if _, err := CompactArchive(CompactConfig{Archive: path, Encrypt: ec}); !errors.Is(err, ErrAlreadyEncrypted) {
		t.Errorf("err %v, want ErrAlreadyEncrypted", err)
	}
	if !bytes.Equal(before, readAll(t, path)) {
		t.Error("the archive changed")
	}
	if entries, _ := os.ReadDir(filepath.Dir(path)); len(entries) != 1 {
		t.Errorf("files beside the archive: %v", entries)
	}
}

// noPrompt is a passphrase that the run must not ask for.
func noPrompt(t *testing.T) PassphraseFunc {
	return func() ([]byte, error) {
		t.Error("the passphrase was asked")
		return []byte("x"), nil
	}
}

// errNoTerminal is the error of a prompt that cannot ask.
var errNoTerminal = errors.New("no terminal")

// TestEncryptArchiveRefusals: a passphrase or parameters that create refuses
// stop the run, and nothing changes.
func TestEncryptArchiveRefusals(t *testing.T) {
	path := mkArchive(t, mutTree(t), false, "t")
	before := readAll(t, path)
	for name, ec := range map[string]*EncryptArchiveConfig{
		"empty passphrase": {Passphrase: passphrase(""), Params: testKDF},
		// Parameters that cannot work stop the run before the prompt.
		"bad parameters":     {Passphrase: noPrompt(t), Params: crypt.KDFParams{Time: 1, Memory: 1, Threads: 1}},
		"unaffordable":       {Passphrase: noPrompt(t), Params: crypt.KDFParams{Time: 1, Memory: 1<<32 - 1, Threads: 1}},
		"passphrase refused": {Passphrase: func() ([]byte, error) { return nil, errNoTerminal }, Params: testKDF},
	} {
		_, err := CompactArchive(CompactConfig{Archive: path, Encrypt: ec})
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
		// The error of the prompt is the one that the user sees.
		if name == "passphrase refused" && !errors.Is(err, errNoTerminal) {
			t.Errorf("%s: %v, want the error of the prompt", name, err)
		}
		if !bytes.Equal(before, readAll(t, path)) {
			t.Errorf("%s: the archive changed", name)
		}
	}
	if entries, _ := os.ReadDir(filepath.Dir(path)); len(entries) != 1 {
		t.Errorf("files beside the archive: %v", entries)
	}
}

// TestEncryptArchiveDefaultParameters: no parameters give the defaults of
// create.
func TestEncryptArchiveDefaultParameters(t *testing.T) {
	if crypt.DefaultKDFParams.MemoryBytes() > totalMemory()/2 {
		t.Skip("this machine cannot afford the default parameters")
	}
	path := mkArchive(t, mutTree(t), false, "t")
	if _, err := CompactArchive(CompactConfig{Archive: path,
		Encrypt: &EncryptArchiveConfig{Passphrase: passphrase("battery staple")}}); err != nil {
		t.Fatal(err)
	}
	r, err := OpenWith(path, newPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if got := (crypt.KDFParams{Time: r.crypto.Time, Memory: r.crypto.Memory, Threads: r.crypto.Threads}); got != crypt.DefaultKDFParams {
		t.Errorf("KDF parameters %+v, want the defaults %+v", got, crypt.DefaultKDFParams)
	}
}

// TestEncryptArchiveOfADamagedArchive: a changed byte in a blob or in a
// dictionary is damage. The run stops, and the archive does not change: no
// damaged blob gets a seal with a valid tag.
func TestEncryptArchiveOfADamagedArchive(t *testing.T) {
	tree := encryptTree(t)
	for _, what := range []string{"member", "dictionary"} {
		t.Run(what, func(t *testing.T) {
			path := plainArchive(t, tree)
			r, err := Open(path, nil)
			if err != nil {
				t.Fatal(err)
			}
			// The second half of the blob is inverted. One flipped bit is not
			// enough: some bits of a zstd frame do not change what it decodes
			// to, and then the content is still correct and nothing is damaged.
			var from, to uint64
			if what == "dictionary" {
				d := r.index.Dicts[0]
				from, to = d.Offset+d.Length/2, d.Offset+d.Length
			} else {
				for _, m := range r.Members() {
					if m.Path == "src/f005.go" {
						from, to = m.Offset+m.Length/2, m.Offset+m.Length
					}
				}
			}
			r.Close()
			if from == 0 {
				t.Fatal("no blob to damage")
			}
			b := readAll(t, path)
			for i := from; i < to; i++ {
				b[i] ^= 0xff
			}
			if err := os.WriteFile(path, b, 0o644); err != nil {
				t.Fatal(err)
			}
			// The rule: --encrypt-archive refuses what --verify refuses.
			if _, err := VerifyArchive(VerifyConfig{Archive: path}); !IsDamage(err) {
				t.Fatalf("verify of the damaged archive: %v, want damage", err)
			}
			_, err = CompactArchive(CompactConfig{Archive: path, Encrypt: encryptWith(2)})
			if !IsDamage(err) {
				t.Errorf("err %v, want damage", err)
			}
			// Pass A stops the run at the damage. A later member that decodes
			// must not clear its error, so pass B never starts.
			if err != nil && strings.Contains(err.Error(), "changed after its check") {
				t.Errorf("err %v: pass B ran after the damage", err)
			}
			if !bytes.Equal(b, readAll(t, path)) {
				t.Error("the archive changed")
			}
			if entries, _ := os.ReadDir(filepath.Dir(path)); len(entries) != 1 {
				t.Errorf("files beside the archive: %v", entries)
			}
		})
	}
}

// TestEncryptArchiveSealsOnlyCheckedBytes: a blob that changes between the
// check of pass A and the seal of pass B stops the run.
func TestEncryptArchiveSealsOnlyCheckedBytes(t *testing.T) {
	path := mkArchive(t, encryptTree(t), false, "t")
	r, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	// t/noise.bin has content of its own. t/a.txt and t/same.txt share
	// one blob, and the order of the workers decides which one holds it.
	var at uint64
	for _, m := range r.Members() {
		if m.Path == "t/noise.bin" && m.Data == 0 && m.Length > 0 {
			at = m.Offset + m.Length/2
		}
	}
	r.Close()
	if at == 0 {
		t.Fatal("t/noise.bin has no blob")
	}
	testBetweenPasses = func() {
		f, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		b := make([]byte, 1)
		if _, err := f.ReadAt(b, int64(at)); err != nil {
			t.Fatal(err)
		}
		b[0] ^= 0x40
		if _, err := f.WriteAt(b, int64(at)); err != nil {
			t.Fatal(err)
		}
	}
	defer func() { testBetweenPasses = nil }()
	_, err = CompactArchive(CompactConfig{Archive: path, Encrypt: encryptWith(1)})
	if !errors.Is(err, format.ErrCorruptData) || !strings.Contains(err.Error(), "changed after its check") {
		t.Errorf("err %v, want the blob that changed after its check", err)
	}
	if _, err := Open(path, nil); err != nil {
		t.Errorf("the archive is no longer plaintext: %v", err)
	}
	if entries, _ := os.ReadDir(filepath.Dir(path)); len(entries) != 1 {
		t.Errorf("files beside the archive: %v", entries)
	}
}

// TestEncryptArchiveDoesNotDependOnWorkers: one worker and many give the same
// state.
func TestEncryptArchiveDoesNotDependOnWorkers(t *testing.T) {
	plain := readAll(t, plainArchive(t, encryptTree(t)))
	var states []string
	for _, workers := range []int{1, 8} {
		path := filepath.Join(t.TempDir(), "p.ect")
		if err := os.WriteFile(path, plain, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := CompactArchive(CompactConfig{Archive: path, Encrypt: encryptWith(workers)}); err != nil {
			t.Fatal(err)
		}
		s, err := archiveState(path, []OpenOptions{newPassphrase})
		if err != nil {
			t.Fatal(err)
		}
		states = append(states, s)
	}
	if states[0] != states[1] {
		t.Errorf("1 worker:\n%s\n8 workers:\n%s", states[0], states[1])
	}
}

// TestEncryptArchiveProgress: the meter gets a total, and advances by all of
// it: the decoded bytes of pass A and the blobs of pass B.
func TestEncryptArchiveProgress(t *testing.T) {
	path := plainArchive(t, encryptTree(t))
	p := &progressRecorder{}
	if _, err := CompactArchive(CompactConfig{Archive: path, Encrypt: encryptWith(2), Reporter: p}); err != nil {
		t.Fatal(err)
	}
	if p.total == 0 || p.advanced != p.total {
		t.Errorf("total %d, advanced %d", p.total, p.advanced)
	}
}

// TestEncryptArchiveOfACatalogThatShrinks: when no kept member uses the
// first codec of the catalog, the catalog shrinks, and the codec of each
// member gets a new position. The decode of pass A must use the positions of
// the archive that it reads. The stress tester found a gzip member decoded
// with the codec at its new position.
func TestEncryptArchiveOfACatalogThatShrinks(t *testing.T) {
	tree := mutTree(t)
	// Content that compresses: a stored chunk needs no decoder.
	bravo := strings.Repeat("bravo ", 2000)
	tree.Text("t/b.txt", 0o644, bravo)
	path := filepath.Join(t.TempDir(), "c.ect")
	if _, err := CreateArchive(CreateConfig{Archive: path, Paths: []string{"t/a.txt"}, BaseDir: tree.Root,
		Options: Options{Codec: "zstd"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := appendTo(t, path, tree, false, func(c *AppendConfig) { c.Options.Codec = "gzip" }, "t/b.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := DeleteMembers(DeleteConfig{Archive: path, Patterns: []string{"t/a.txt"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := CompactArchive(CompactConfig{Archive: path, Encrypt: encryptWith(1)}); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	r, err := OpenWith(path, newPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if len(r.index.Codecs) != 1 || r.index.Codecs[0].Name != "gzip" {
		t.Errorf("catalog %+v: want gzip alone", r.index.Codecs)
	}
	dest := t.TempDir()
	if _, err := Extract(ExtractConfig{Archive: path, Destination: dest, Passphrase: newPassphrase.Passphrase}); err != nil {
		t.Fatal(err)
	}
	if b := readAll(t, filepath.Join(dest, "t/b.txt")); string(b) != bravo {
		t.Errorf("t/b.txt is %d bytes, want %d", len(b), len(bravo))
	}
}
