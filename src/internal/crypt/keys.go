// Package crypt holds the key schedule and the chunk sealing for encrypted
// archives (doc/design.md 6).
//
// Nothing here knows about the archive format. It takes a passphrase and hands
// back keys, a sealer and an opener; the format package decides what gets
// sealed and where the results go.
package crypt

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"lukechampine.com/blake3"
)

var (
	// ErrWrongPassphrase means the supplied passphrase does not open this
	// archive.
	ErrWrongPassphrase = errors.New("wrong passphrase")

	// ErrAuthentication means sealed bytes failed their tag: they were
	// altered, truncated, or moved from where they were sealed. It is
	// deliberately distinct from a wrong passphrase, because the two call for
	// different responses - retype it, versus do not trust this archive.
	ErrAuthentication = errors.New("authentication failed")
)

// Sizes fixed by the primitives.
const (
	DataKeySize = 32
	KEKSize     = 32
	SaltSize    = 16
	DigestSize  = 32
)

// KDFParams are the Argon2id settings, stored in the crypto header so that an
// archive can always be opened with the parameters it was made with.
type KDFParams struct {
	Time    uint32 // iterations
	Memory  uint32 // KiB
	Threads uint8
}

// Defaults for a new archive.
//
// The memory figure is the one that matters: it is what makes a GPU guess
// expensive, and a quarter of a gibibyte is enough to cut a card's throughput
// by orders of magnitude while staying openable on a small machine. See
// doc/design.md A.3.
var DefaultKDFParams = KDFParams{
	Time:    3,
	Memory:  256 * 1024, // 256 MiB
	Threads: 4,
}

// Validate reports whether the parameters are usable, and whether this machine
// can afford them.
func (p KDFParams) Validate() error {
	if p.Time < 1 {
		return fmt.Errorf("kdf: time must be at least 1, got %d", p.Time)
	}
	if p.Threads < 1 {
		return fmt.Errorf("kdf: threads must be at least 1, got %d", p.Threads)
	}
	// Argon2id needs 8 KiB per lane at minimum.
	if min := 8 * uint32(p.Threads); p.Memory < min {
		return fmt.Errorf("kdf: memory must be at least %d KiB for %d threads, got %d",
			min, p.Threads, p.Memory)
	}
	return nil
}

// MemoryBytes is what deriving a key from these parameters will allocate.
func (p KDFParams) MemoryBytes() int64 { return int64(p.Memory) * 1024 }

// Keys is the key schedule for one archive.
//
// Every key comes from the archive's data key: 32 random bytes made once, when
// the archive is created. The passphrase does not make any of these keys. It
// wraps the data key (doc/design.md 6.2), so that a new passphrase re-wraps
// the same data key and every key below stays the same. The data key never
// encrypts anything itself: every use derives a subkey bound to a purpose and
// to the archive, so that a key for one job cannot serve another.
type Keys struct {
	dataKey []byte
	uuid    [16]byte
}

// WrappedKeySize is the size of a wrapped data key: the nonce, the key, and
// the tag.
const WrappedKeySize = chacha20poly1305.NonceSizeX + DataKeySize + chacha20poly1305.Overhead

// NewDataKey makes the random data key of a new archive.
func NewDataKey() ([]byte, error) {
	k := make([]byte, DataKeySize)
	if _, err := rand.Read(k); err != nil {
		return nil, fmt.Errorf("crypt: making a data key: %w", err)
	}
	return k, nil
}

// NewKeys builds the key schedule of an archive from its data key. The keys
// keep their own copy.
func NewKeys(dataKey []byte, uuid [16]byte) (*Keys, error) {
	if len(dataKey) != DataKeySize {
		return nil, fmt.Errorf("crypt: data key is %d bytes, want %d", len(dataKey), DataKeySize)
	}
	return &Keys{dataKey: append([]byte(nil), dataKey...), uuid: uuid}, nil
}

// DeriveKEK runs the passphrase through Argon2id to make the key-encryption
// key that wraps the data key.
//
// This is the slow step by design: it is the only defence against someone
// guessing the passphrase offline, and its cost is set by KDFParams.
func DeriveKEK(passphrase, salt []byte, p KDFParams) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if len(salt) != SaltSize {
		return nil, fmt.Errorf("kdf: salt is %d bytes, want %d", len(salt), SaltSize)
	}
	return argon2.IDKey(passphrase, salt, p.Time, p.Memory, p.Threads, KEKSize), nil
}

// WrapKey seals a data key under a key-encryption key. The result is the
// nonce, then the sealed key. The archive id is bound in, so that a wrapped
// key cannot be moved to another archive.
func WrapKey(kek []byte, uuid [16]byte, dataKey []byte) ([]byte, error) {
	var nonce [chacha20poly1305.NonceSizeX]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("crypt: wrap nonce: %w", err)
	}
	return wrapKeyWithNonce(kek, uuid, dataKey, nonce)
}

// wrapKeyWithNonce is WrapKey with a fixed nonce, for the test vectors.
func wrapKeyWithNonce(kek []byte, uuid [16]byte, dataKey []byte, nonce [chacha20poly1305.NonceSizeX]byte) ([]byte, error) {
	if len(dataKey) != DataKeySize {
		return nil, fmt.Errorf("crypt: data key is %d bytes, want %d", len(dataKey), DataKeySize)
	}
	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return nil, fmt.Errorf("crypt: wrap cipher: %w", err)
	}
	out := make([]byte, 0, WrappedKeySize)
	out = append(out, nonce[:]...)
	return aead.Seal(out, nonce[:], dataKey, wrapAAD(uuid)), nil
}

// UnwrapKey opens a wrapped data key. A tag that fails means the passphrase
// is wrong: the tag is the check that a separate check value used to be.
func UnwrapKey(kek []byte, uuid [16]byte, wrapped []byte) ([]byte, error) {
	if len(wrapped) != WrappedKeySize {
		return nil, fmt.Errorf("%w: the wrapped key is %d bytes, want %d", ErrWrongPassphrase, len(wrapped), WrappedKeySize)
	}
	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return nil, fmt.Errorf("crypt: wrap cipher: %w", err)
	}
	nonce := wrapped[:chacha20poly1305.NonceSizeX]
	key, err := aead.Open(nil, nonce, wrapped[chacha20poly1305.NonceSizeX:], wrapAAD(uuid))
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	return key, nil
}

func wrapAAD(uuid [16]byte) []byte {
	return append([]byte("eictar/v1/wrap"), uuid[:]...)
}

// Unlock turns a passphrase and a crypto header's values into the archive's
// keys: the KEK, then the data key, then the schedule.
func Unlock(passphrase, salt []byte, uuid [16]byte, p KDFParams, wrapped []byte) (*Keys, error) {
	kek, err := DeriveKEK(passphrase, salt, p)
	if err != nil {
		return nil, err
	}
	defer zero(kek)
	dataKey, err := UnwrapKey(kek, uuid, wrapped)
	if err != nil {
		return nil, err
	}
	defer zero(dataKey)
	return NewKeys(dataKey, uuid)
}

// Wrap seals this archive's data key for a passphrase, with a new salt of
// its own. It is how create stores the data key, and how a change of
// passphrase stores it again.
func (k *Keys) Wrap(passphrase []byte, p KDFParams) (salt, wrapped []byte, err error) {
	salt = make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, fmt.Errorf("crypt: salt: %w", err)
	}
	kek, err := DeriveKEK(passphrase, salt, p)
	if err != nil {
		return nil, nil, err
	}
	defer zero(kek)
	wrapped, err = WrapKey(kek, k.uuid, k.dataKey)
	return salt, wrapped, err
}

// derive produces a subkey for one purpose.
func (k *Keys) derive(info string, extra []byte, salt []byte, n int) []byte {
	context := make([]byte, 0, len(info)+len(k.uuid)+len(extra))
	context = append(context, info...)
	context = append(context, k.uuid[:]...)
	context = append(context, extra...)

	out := make([]byte, n)
	r := hkdf.New(sha256.New, k.dataKey, salt, context)
	if _, err := io.ReadFull(r, out); err != nil {
		// HKDF cannot fail for these sizes; a failure here is a broken build.
		panic("crypt: deriving a subkey: " + err.Error())
	}
	return out
}

// ContentKey keys the member digests of an encrypted archive, so that a
// digest in an index that is not sealed tells nothing about the content
// (doc/design.md 6.2).
func (k *Keys) ContentKey() []byte {
	return k.derive("eictar/v1/content", nil, nil, 32)
}

// IndexKey seals the index. It is bound to the generation, so an index from
// one generation cannot be replayed into another.
func (k *Keys) IndexKey(generation uint64) []byte {
	return k.derive("eictar/v1/index", uint64LE(generation), nil, 32)
}

// IndexAuthKey keys the digest the trailer records for the index.
//
// It exists whether or not the index is encrypted: --encrypt-index controls
// confidentiality, while authenticity is not optional once a key exists
// (doc/design.md 6.4). Without it, an attacker who cannot read any content can
// still rewrite paths and modes.
func (k *Keys) IndexAuthKey() []byte {
	return k.derive("eictar/v1/index-auth", nil, nil, 32)
}

// MemberKey derives the key for one member from its own salt, so that every
// member has a distinct key and a chunk counter is a safe nonce.
func (k *Keys) MemberKey(salt []byte) ([]byte, error) {
	if len(salt) != SaltSize {
		return nil, fmt.Errorf("crypt: member salt is %d bytes, want %d", len(salt), SaltSize)
	}
	return k.derive("eictar/v1/member", nil, salt, 32), nil
}

// Zero wipes the data key. It is best-effort: Go may have copied it during a
// stack or heap move, and there is no way to find those copies.
func (k *Keys) Zero() { zero(k.dataKey) }

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// IndexDigest computes the value the trailer records for the index.
//
// With a key it is a keyed BLAKE3 that an attacker cannot recompute; without
// one it is the plain hash, which detects damage but not tampering. The uuid
// and generation are bound in so that an index and trailer cannot be lifted
// from one archive onto another sealed with the same passphrase.
//
// Only two inputs are meaningful: nil, meaning "no key", or a 32-byte key.
// Anything else is a programming error and panics. The previous behaviour -
// falling back to the unkeyed hash for any other length - meant a truncated
// key would quietly remove the one protection metadata has, and a function
// that authenticates must not have a silent off switch.
func IndexDigest(key []byte, uuid [16]byte, generation uint64, indexBytes []byte) [DigestSize]byte {
	var h *blake3.Hasher
	switch len(key) {
	case 0:
		if key != nil {
			panic("crypt: IndexDigest given an empty, non-nil key")
		}
		h = blake3.New(DigestSize, nil)
	case 32:
		h = blake3.New(DigestSize, key)
	default:
		panic(fmt.Sprintf("crypt: IndexDigest given a %d-byte key; want nil or 32", len(key)))
	}
	h.Write(uuid[:])
	h.Write(uint64LE(generation))
	h.Write(indexBytes)

	var out [DigestSize]byte
	copy(out[:], h.Sum(nil))
	return out
}

func uint64LE(v uint64) []byte {
	return []byte{
		byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24),
		byte(v >> 32), byte(v >> 40), byte(v >> 48), byte(v >> 56),
	}
}
