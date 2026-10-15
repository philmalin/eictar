package crypt

import (
	"bytes"
	"errors"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// The openers of sealed data (doc/testing.md 5, step 4). Each one takes
// bytes from the archive, which can be hostile. A success must be what the
// sealer makes from that plaintext, in that place, and no input may panic.

var fuzzKey = bytes.Repeat([]byte{0x42}, 32)

// FuzzChunkOpen opens a chunk at an index, final or not. When it opens, the
// sealer gives the same bytes for that plaintext in that place, and the
// chunk does not open at the other index, or with the other final flag.
func FuzzChunkOpen(f *testing.F) {
	s, err := NewMemberSealer(fuzzKey, 7)
	if err != nil {
		f.Fatal(err)
	}
	for _, pt := range []string{"", "a", "a chunk of member 7"} {
		for _, final := range []bool{false, true} {
			sealed, _ := s.Seal(nil, []byte(pt), 3, final)
			f.Add(sealed, uint64(3), final)
		}
	}
	f.Fuzz(func(t *testing.T, ct []byte, index uint64, final bool) {
		pt, err := s.Open(nil, ct, index, final)
		if err != nil {
			if !errors.Is(err, ErrAuthentication) {
				t.Fatalf("the error is not an authentication failure: %v", err)
			}
			return
		}
		again, _ := s.Seal(nil, pt, index, final)
		if !bytes.Equal(again, ct) {
			t.Fatal("a chunk opened that the sealer does not make")
		}
		if _, err := s.Open(nil, ct, index+1, final); err == nil {
			t.Error("the chunk opened at another index")
		}
		if _, err := s.Open(nil, ct, index, !final); err == nil {
			t.Error("the chunk opened with the other final flag")
		}
		other, _ := NewMemberSealer(fuzzKey, 8)
		if _, err := other.Open(nil, ct, index, final); err == nil {
			t.Error("the chunk opened in another member")
		}
	})
}

// FuzzIndexAndDictOpen opens a sealed index of a generation, and a sealed
// dictionary of an id. When one opens, the sealer gives the same bytes, and
// it does not open for another generation or id.
func FuzzIndexAndDictOpen(f *testing.F) {
	var nonce [chacha20poly1305.NonceSizeX]byte
	idx, _ := sealIndexWithNonce(fuzzKey, 2, nonce, []byte("an index"))
	dict, _ := SealDict(fuzzKey, 40000, []byte("a dictionary"))
	f.Add(idx, uint64(2), uint32(40000))
	f.Add(dict, uint64(2), uint32(40000))
	f.Fuzz(func(t *testing.T, sealed []byte, gen uint64, id uint32) {
		if pt, err := OpenIndex(fuzzKey, gen, sealed); err == nil {
			copy(nonce[:], sealed)
			again, _ := sealIndexWithNonce(fuzzKey, gen, nonce, pt)
			if !bytes.Equal(again, sealed) {
				t.Fatal("an index opened that the sealer does not make")
			}
			if _, err := OpenIndex(fuzzKey, gen+1, sealed); err == nil {
				t.Error("the index opened for another generation")
			}
		} else if !errors.Is(err, ErrAuthentication) {
			t.Fatalf("index: the error is not an authentication failure: %v", err)
		}
		if pt, err := OpenDict(fuzzKey, id, sealed); err == nil {
			again, _ := SealDict(fuzzKey, id, pt)
			if !bytes.Equal(again, sealed) {
				t.Fatal("a dictionary opened that the sealer does not make")
			}
			if _, err := OpenDict(fuzzKey, id+1, sealed); err == nil {
				t.Error("the dictionary opened for another id")
			}
		} else if !errors.Is(err, ErrAuthentication) {
			t.Fatalf("dictionary: the error is not an authentication failure: %v", err)
		}
	})
}
