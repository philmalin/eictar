package format

import (
	"bytes"
	"errors"
	"testing"
)

// TestKeysMatchExactly: a map key is a field only when its bytes are the
// name of the field. A reader ignores a key that it does not know
// (doc/format.md 8.3), and "salT" is not "salt". The CBOR library matches a
// key to a field of another case by default, and a reader that does so reads
// what another reader refuses: the fuzzing of the gate found it with the
// second reader (doc/testing.md 5).
func TestKeysMatchExactly(t *testing.T) {
	h := rawCryptoHeader(t, sampleCryptoHeader())
	if !bytes.Contains(h, []byte("\x64salt")) {
		t.Fatal("no salt key in the crypto header")
	}
	h = bytes.Replace(h, []byte("\x64salt"), []byte("\x64salT"), 1)
	if _, err := UnmarshalCryptoHeader(h); !errors.Is(err, ErrCorruptIndex) {
		t.Errorf("a crypto header with salT and no salt: got %v, want ErrCorruptIndex", err)
	}

	enc, err := sampleIndex().Encode(EncodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(enc.Bytes, []byte("\x64path")) {
		t.Fatal("no path key in the index")
	}
	b := bytes.ReplaceAll(enc.Bytes, []byte("\x64path"), []byte("\x64Path"))
	if _, err := DecodeIndex(b, enc.Flags, nil); !errors.Is(err, ErrCorruptIndex) {
		t.Errorf("an index whose members have Path and no path: got %v, want ErrCorruptIndex", err)
	}
}
