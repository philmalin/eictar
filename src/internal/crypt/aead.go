package crypt

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// Overhead is what sealing adds to each chunk: the Poly1305 tag.
const Overhead = chacha20poly1305.Overhead

// MemberSealer seals the chunks of one member.
//
// One member, one key, and the chunk index as the nonce counter. That is what
// makes a counter safe here: nonces only have to be unique within a key, and
// no two chunks of a member share an index (doc/design.md 6.3).
type MemberSealer struct {
	aead     cipher.AEAD
	memberID uint64
}

// NewMemberSealer builds a sealer for one member.
func NewMemberSealer(key []byte, memberID uint64) (*MemberSealer, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("crypt: member cipher: %w", err)
	}
	return &MemberSealer{aead: aead, memberID: memberID}, nil
}

// Seal encrypts one chunk, appending to dst.
//
// final marks the last chunk of the member. It is authenticated, so dropping
// trailing chunks changes which one claims to be last and the claim no longer
// verifies - truncation is caught, not merely noticed later by a short file.
func (s *MemberSealer) Seal(dst, plaintext []byte, chunkIndex uint64, final bool) ([]byte, error) {
	if s.aead == nil {
		return nil, fmt.Errorf("crypt: sealer is not initialised")
	}
	nonce := chunkNonce(chunkIndex)
	return s.aead.Seal(dst, nonce[:], plaintext, chunkAAD(s.memberID, chunkIndex, final)), nil
}

// Open reverses Seal. A chunk moved to another member, to another index, or
// away from the end of its member fails here rather than decoding into
// something plausible.
func (s *MemberSealer) Open(dst, ciphertext []byte, chunkIndex uint64, final bool) ([]byte, error) {
	if s.aead == nil {
		return nil, fmt.Errorf("crypt: sealer is not initialised")
	}
	nonce := chunkNonce(chunkIndex)

	out, err := s.aead.Open(dst, nonce[:], ciphertext, chunkAAD(s.memberID, chunkIndex, final))
	if err != nil {
		return nil, fmt.Errorf("%w: chunk %d of member %d", ErrAuthentication, chunkIndex, s.memberID)
	}
	return out, nil
}

// chunkNonce is 16 zero bytes followed by the chunk counter. The key is unique
// per member, so the counter alone makes the nonce unique.
func chunkNonce(chunkIndex uint64) [chacha20poly1305.NonceSizeX]byte {
	var nonce [chacha20poly1305.NonceSizeX]byte
	binary.BigEndian.PutUint64(nonce[16:], chunkIndex)
	return nonce
}

// chunkAAD binds a chunk to its place: which member, which index, and whether
// it is the last one.
func chunkAAD(memberID, chunkIndex uint64, final bool) []byte {
	aad := make([]byte, 17)
	binary.LittleEndian.PutUint64(aad[0:8], memberID)
	binary.BigEndian.PutUint64(aad[8:16], chunkIndex)
	if final {
		aad[16] = 1
	}
	return aad
}

// SealIndex encrypts the whole index as one message. The result is the
// 24-byte nonce followed by the ciphertext.
//
// The index is a single unit: it is read in full or not at all, so it needs no
// chunking and no counter. The nonce is random, not derived from the
// generation. Two different indexes can be sealed under one (archive, generation)
// pair: a copy of an archive appended to beside the original, an append
// that failed after its index was written, a compact whose rename failed.
// With a derived nonce each of those reuses a key and nonce, which exposes
// the XOR of the two indexes and the Poly1305 key (doc/design.md 6.3). A
// random 192-bit nonce makes a collision impossible in practice.
func SealIndex(key []byte, generation uint64, plaintext []byte) ([]byte, error) {
	var nonce [chacha20poly1305.NonceSizeX]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("crypt: index nonce: %w", err)
	}
	return sealIndexWithNonce(key, generation, nonce, plaintext)
}

// sealIndexWithNonce is SealIndex with a fixed nonce, for the test vectors.
func sealIndexWithNonce(key []byte, generation uint64, nonce [chacha20poly1305.NonceSizeX]byte, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("crypt: index cipher: %w", err)
	}
	out := make([]byte, 0, len(nonce)+len(plaintext)+aead.Overhead())
	out = append(out, nonce[:]...)
	return aead.Seal(out, nonce[:], plaintext, indexAAD(generation)), nil
}

// OpenIndex reverses SealIndex.
func OpenIndex(key []byte, generation uint64, sealed []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("crypt: index cipher: %w", err)
	}
	if len(sealed) < chacha20poly1305.NonceSizeX+aead.Overhead() {
		return nil, fmt.Errorf("%w: the index is too short to be sealed", ErrAuthentication)
	}
	nonce, ciphertext := sealed[:chacha20poly1305.NonceSizeX], sealed[chacha20poly1305.NonceSizeX:]
	out, err := aead.Open(nil, nonce, ciphertext, indexAAD(generation))
	if err != nil {
		return nil, fmt.Errorf("%w: the index", ErrAuthentication)
	}
	return out, nil
}

func indexAAD(generation uint64) []byte {
	aad := make([]byte, 8)
	binary.LittleEndian.PutUint64(aad, generation)
	return aad
}

// SealDict seals a dictionary as one message (doc/design.md 6.3). Each
// dictionary has its own salt and so its own key, which seals this one
// message only: a fixed nonce is safe. The id is bound in, so a dictionary
// cannot stand in for another.
func SealDict(key []byte, id uint32, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("crypt: dictionary cipher: %w", err)
	}
	var nonce [chacha20poly1305.NonceSizeX]byte
	return aead.Seal(nil, nonce[:], plaintext, dictAAD(id)), nil
}

// OpenDict reverses SealDict.
func OpenDict(key []byte, id uint32, sealed []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("crypt: dictionary cipher: %w", err)
	}
	var nonce [chacha20poly1305.NonceSizeX]byte
	out, err := aead.Open(nil, nonce[:], sealed, dictAAD(id))
	if err != nil {
		return nil, fmt.Errorf("%w: dictionary %d", ErrAuthentication, id)
	}
	return out, nil
}

func dictAAD(id uint32) []byte {
	aad := make([]byte, 4)
	binary.LittleEndian.PutUint32(aad, id)
	return aad
}
