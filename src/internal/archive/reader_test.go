package archive

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/philmalin/eictar/src/internal/format"
)

// Tests of the checks that the Reader makes on an archive, after the
// checks of the format package (doc/format.md 8.4).

// copyArchive copies the archive at src to a new temporary file.
func copyArchive(t *testing.T, src string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), filepath.Base(src))
	if err := os.WriteFile(path, readAll(t, src), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// rewriteTrailer changes the last trailer of the archive at path with mod,
// and writes it back with its checksum. The index digest does not change.
func rewriteTrailer(t *testing.T, path string, mod func(tr *format.Trailer, size int64) int64) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, format.TrailerSize)
	if _, err := f.ReadAt(raw, fi.Size()-format.TrailerSize); err != nil {
		t.Fatal(err)
	}
	var tr format.Trailer
	if err := tr.UnmarshalBinary(raw); err != nil {
		t.Fatal(err)
	}
	// mod gives the offset where the trailer goes.
	at := mod(&tr, fi.Size())
	if raw, err = tr.MarshalBinary(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(raw, at); err != nil {
		t.Fatal(err)
	}
}

func atTheEnd(tr *format.Trailer, size int64) int64 { return size - format.TrailerSize }

// TestLiveCountMustMatch: the trailer's count of live members must be the
// count in the index. The digest does not cover the trailer.
func TestLiveCountMustMatch(t *testing.T) {
	path := copyArchive(t, mkArchive(t, mutTree(t), false, "t"))
	rewriteTrailer(t, path, func(tr *format.Trailer, size int64) int64 {
		tr.LiveMembers++
		return atTheEnd(tr, size)
	})
	_, err := Open(path, nil)
	if !errors.Is(err, format.ErrCorruptIndex) || !strings.Contains(err.Error(), "live members") {
		t.Errorf("Open = %v, want %v for the live count", err, format.ErrCorruptIndex)
	}
}

// TestTrailerIsCheckedAgainstTheFile: an index offset before the body is
// refused as such, before the reader reads the header as an index.
func TestTrailerIsCheckedAgainstTheFile(t *testing.T) {
	path := copyArchive(t, mkArchive(t, mutTree(t), false, "t"))
	rewriteTrailer(t, path, func(tr *format.Trailer, size int64) int64 {
		tr.IndexOffset = 1
		return atTheEnd(tr, size)
	})
	_, err := Open(path, nil)
	if !errors.Is(err, format.ErrCorruptIndex) || !strings.Contains(err.Error(), "outside body") {
		t.Errorf("Open = %v, want %v for an index outside the body", err, format.ErrCorruptIndex)
	}
}

// TestIndexOverTheLimit: a sparse file can claim an index of more than
// MaxIndexSize. The reader refuses it before it allocates the memory.
func TestIndexOverTheLimit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a file of 1 GiB is not sparse on Windows unless it is marked so")
	}
	path := copyArchive(t, mkArchive(t, mutTree(t), false, "t"))
	r, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	body := r.hdr.BodyOffset()
	r.Close()
	rewriteTrailer(t, path, func(tr *format.Trailer, _ int64) int64 {
		tr.IndexOffset, tr.IndexLength = uint64(body), format.MaxIndexSize+1
		return body + format.MaxIndexSize + 1
	})
	_, err = Open(path, nil)
	if !errors.Is(err, format.ErrIndexTooLarge) {
		t.Errorf("Open = %v, want %v", err, format.ErrIndexTooLarge)
	}
}

// TestIndexThatDoesNotDecode: an index whose digest matches, but whose bytes
// are not an index, is damage, not a crash.
func TestIndexThatDoesNotDecode(t *testing.T) {
	path := copyArchive(t, mkArchive(t, mutTree(t), false, "t"))
	r, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	tr, hdr := r.Trailer(), r.Header()
	r.Close()
	writeForgedIndex(t, path, tr, hdr, []byte("not an index"))
	_, err = Open(path, nil)
	if !errors.Is(err, format.ErrCorruptIndex) {
		t.Errorf("Open = %v, want %v", err, format.ErrCorruptIndex)
	}
}

// TestUnaffordableKDFIsRefusedFirst: Argon2id parameters that need more than
// half the RAM are refused before the passphrase is asked for (doc/design.md
// A.3).
func TestUnaffordableKDFIsRefusedFirst(t *testing.T) {
	path := mkArchive(t, mutTree(t), true, "t")
	saved := kdfMemory
	t.Cleanup(func() { kdfMemory = saved })
	kdfMemory = func() int64 { return int64(testKDF.Memory) << 10 } // the KDF needs all of it
	asked := 0
	_, err := Open(path, func() ([]byte, error) { asked++; return []byte("correct horse"), nil })
	if err == nil || !strings.Contains(err.Error(), "deriving the key needs") || asked != 0 {
		t.Errorf("Open = %v, after %d questions; want the memory refused, and no question", err, asked)
	}
}

// TestPassphraseErrorIsReturned: when the passphrase cannot be read, that is
// the error, not a wrong passphrase.
func TestPassphraseErrorIsReturned(t *testing.T) {
	path := mkArchive(t, mutTree(t), true, "t")
	errNoTerminal := errors.New("no terminal")
	_, err := Open(path, func() ([]byte, error) { return nil, errNoTerminal })
	if !errors.Is(err, errNoTerminal) {
		t.Errorf("Open = %v, want %v", err, errNoTerminal)
	}
}

// TestSealedMemberInAPlainArchive: a member of a plain archive whose index
// gives it an enc is refused. Without a key, the reader cannot open it.
func TestSealedMemberInAPlainArchive(t *testing.T) {
	path := copyArchive(t, mkArchive(t, mutTree(t), false, "t"))
	first := -1
	forgeIndex(t, path, nil, func(ix *format.Index) {
		first = slices.IndexFunc(ix.Members, func(m format.Member) bool { return m.Length > 0 })
		ix.Members[first].Enc = &format.EncInfo{Salt: make([]byte, format.CryptoSaltSize)}
	})
	r, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	err = r.WriteMember(&r.index.Members[first], &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "is encrypted and no passphrase was supplied") {
		t.Errorf("WriteMember = %v, want the member refused", err)
	}
}

// TestUnsealedMemberInAnEncryptedArchive: in an encrypted archive, a member
// with chunks and no enc contradicts the header. An empty file has no blob,
// and so no enc (doc/format.md 8.3), and reads as empty.
func TestUnsealedMemberInAnEncryptedArchive(t *testing.T) {
	tree := mutTree(t)
	tree.Text("t/empty", 0o644, "")
	r, err := OpenWith(mkArchive(t, tree, true, "t"), openFor(true))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	var checked int
	for _, m := range r.index.Members {
		if !m.Type.HasPayload() || m.Data != 0 {
			continue
		}
		m.Enc = nil
		var out bytes.Buffer
		err := r.WriteMember(&m, &out)
		switch {
		case len(m.Chunks) == 0 && (err != nil || out.Len() != 0):
			t.Errorf("%s, empty: %v, %d bytes", m.Path, err, out.Len())
		case len(m.Chunks) > 0 && (!errors.Is(err, format.ErrCorruptIndex) || !strings.Contains(err.Error(), "unsealed")):
			t.Errorf("%s: %v, want %v for a member that is not sealed", m.Path, err, format.ErrCorruptIndex)
		}
		checked++
	}
	if checked < 2 {
		t.Fatalf("%d members checked", checked)
	}
}

// TestDamagedDictionary: a dictionary that fails its digest is reported as
// such, not as the failure of each member that uses it.
func TestDamagedDictionary(t *testing.T) {
	path := copyArchive(t, dictCreate(t, dictTree(t, "src", 150), false, trainParams, nil, "src"))
	r, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	d := r.index.Dicts[0]
	r.Close()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1)
	if _, err := f.ReadAt(b, int64(d.Offset)+10); err != nil {
		t.Fatal(err)
	}
	b[0] ^= 0xff
	if _, err := f.WriteAt(b, int64(d.Offset)+10); err != nil {
		t.Fatal(err)
	}
	f.Close()

	r, err = Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for _, m := range r.index.Members {
		if m.Codec < 0 || r.index.Codecs[m.Codec].Dict == 0 || m.Length == 0 {
			continue
		}
		err := r.WriteMember(&m, &bytes.Buffer{})
		if !errors.Is(err, format.ErrChecksum) || !strings.Contains(err.Error(), "dictionary") {
			t.Errorf("%s: %v, want the dictionary's %v", m.Path, err, format.ErrChecksum)
		}
		return
	}
	t.Fatal("no member uses the dictionary")
}

// TestOwnerOfAMemberThatSharesNothing: the owner of a member with no data
// is the member itself.
func TestOwnerOfAMemberThatSharesNothing(t *testing.T) {
	r, err := Open(mkArchive(t, mutTree(t), false, "t"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	m := &r.index.Members[0]
	if o := r.Owner(m); o != m {
		t.Errorf("Owner(%s) = %v, want the member", m.Path, o)
	}
}
