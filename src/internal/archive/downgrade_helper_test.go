package archive

import (
	"os"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"eictar/src/internal/crypt"
	"eictar/src/internal/format"
)

// downgradeArchive strips encryption from an archive's framing, the way an
// attacker with write access but no passphrase would: clear the header's flag,
// drop the crypto header length, rewrite the plaintext index to taste and
// recompute the unkeyed digest a plaintext reader checks. The sealed member
// blobs are left where they are - the attacker cannot read them, and does not
// need to in order to control what a listing shows.
//
// ask is used only to read the original index for convenience; everything
// the attacker writes uses no key.
func downgradeArchive(t *testing.T, path string, ask PassphraseFunc, newName string) {
	t.Helper()

	r, err := Open(path, ask)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	hdr := r.Header()
	tr := r.Trailer()
	index := *r.index
	r.Close()

	for i := range index.Members {
		index.Members[i].Enc = nil
	}
	index.Members[len(index.Members)-1].Path = newName

	hdr.Flags &^= format.FlagEncrypted
	hdr.CryptoHeaderLen = 0
	hdrBytes, err := hdr.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling header: %v", err)
	}

	enc, err := index.Encode(format.EncodeOptions{Compress: true})
	if err != nil {
		t.Fatalf("encoding index: %v", err)
	}

	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	defer f.Close()

	if _, err := f.WriteAt(hdrBytes, 0); err != nil {
		t.Fatalf("writing header: %v", err)
	}
	if _, err := f.WriteAt(enc.Bytes, int64(tr.IndexOffset)); err != nil {
		t.Fatalf("writing index: %v", err)
	}

	tr.Flags = enc.Flags
	tr.IndexLength = uint64(len(enc.Bytes))
	tr.IndexDigest = crypt.IndexDigest(nil, hdr.ArchiveUUID, tr.Generation, enc.Bytes)
	trBytes, err := tr.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling trailer: %v", err)
	}
	end := int64(tr.IndexOffset) + int64(len(enc.Bytes))
	if _, err := f.WriteAt(trBytes, end); err != nil {
		t.Fatalf("writing trailer: %v", err)
	}
	if err := f.Truncate(end + format.TrailerSize); err != nil {
		t.Fatalf("truncating: %v", err)
	}
}

// cborMarshalUnchecked encodes a crypto header without the validation Marshal
// applies, which is what an attacker's own tooling would do.
func cborMarshalUnchecked(ch *format.CryptoHeader) ([]byte, error) {
	return cbor.Marshal(ch)
}
