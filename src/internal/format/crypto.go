package format

import (
	"encoding/binary"
	"fmt"
)

// CryptoHeader is the plaintext block after the file header, present only in
// an encrypted archive (doc/design.md 6.2).
//
// It has to be readable before any key exists, because it holds what the key
// is derived from. Everything in it is public by necessity: the salt and the
// KDF parameters tell an attacker how to mount a guess, and the cost of that
// guess is what the parameters are for.
type CryptoHeader struct {
	Version uint32 `cbor:"v"`

	KDF     string `cbor:"kdf"`     // "argon2id"
	Salt    []byte `cbor:"salt"`    // 16 bytes
	Time    uint32 `cbor:"time"`    // iterations
	Memory  uint32 `cbor:"memory"`  // KiB
	Threads uint8  `cbor:"threads"` //

	AEAD  string `cbor:"aead"`  // "xchacha20poly1305"
	Check []byte `cbor:"check"` // 32 bytes derived from the master key

	// Recipients is reserved for public-key mode (§15). A reader that finds
	// it set must refuse rather than ignore it: the archive is addressed to
	// keys this build knows nothing about.
	Recipients []string `cbor:"recipients,omitempty"`
}

// Supported values. An archive naming anything else was written by a build
// that knew something this one does not.
const (
	CryptoHeaderVersion = 1
	KDFArgon2id         = "argon2id"
	AEADXChaCha20       = "xchacha20poly1305"
)

// MarshalCryptoHeader encodes the header with a four-byte length in front, so
// a reader can find the body without decoding anything.
func (c *CryptoHeader) Marshal() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	body, err := encMode.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("format: encoding the crypto header: %w", err)
	}
	out := make([]byte, 4, 4+len(body))
	binary.LittleEndian.PutUint32(out[0:4], uint32(len(body)))
	return append(out, body...), nil
}

// UnmarshalCryptoHeader decodes the block written by Marshal, which the caller
// has read using the header's CryptoHeaderLen.
func UnmarshalCryptoHeader(b []byte) (*CryptoHeader, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("format: crypto header: %w: %d bytes", ErrTruncated, len(b))
	}
	length := int(binary.LittleEndian.Uint32(b[0:4]))
	if length < 0 || 4+length > len(b) {
		return nil, fmt.Errorf("format: crypto header: %w: claims %d bytes of %d available",
			ErrCorruptIndex, length, len(b)-4)
	}

	dm, err := decModeFor(length)
	if err != nil {
		return nil, err
	}
	var c CryptoHeader
	if err := dm.Unmarshal(b[4:4+length], &c); err != nil {
		return nil, fmt.Errorf("format: crypto header: %w: %v", ErrCorruptIndex, err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Validate checks the header names primitives this build implements.
func (c *CryptoHeader) Validate() error {
	if c.Version != CryptoHeaderVersion {
		return fmt.Errorf("format: %w: crypto header v%d, this build reads v%d",
			ErrUnsupportedVersion, c.Version, CryptoHeaderVersion)
	}
	if c.KDF != KDFArgon2id {
		return fmt.Errorf("format: %w: key derivation %q", ErrUnsupportedVersion, c.KDF)
	}
	if c.AEAD != AEADXChaCha20 {
		return fmt.Errorf("format: %w: cipher %q", ErrUnsupportedVersion, c.AEAD)
	}
	if len(c.Recipients) > 0 {
		return fmt.Errorf("format: %w: this archive is addressed to public keys, "+
			"which this build cannot open", ErrUnsupportedVersion)
	}
	if len(c.Salt) != CryptoSaltSize {
		return fmt.Errorf("format: %w: salt is %d bytes, want %d",
			ErrCorruptIndex, len(c.Salt), CryptoSaltSize)
	}
	if len(c.Check) != CryptoCheckSize {
		return fmt.Errorf("format: %w: check value is %d bytes, want %d",
			ErrCorruptIndex, len(c.Check), CryptoCheckSize)
	}
	// The parameters come from the file, and deriving a key allocates Memory
	// kibibytes. An archive claiming terabytes must be refused before the
	// allocation, not during it.
	if c.Memory > MaxKDFMemoryKiB {
		return fmt.Errorf("format: %w: the archive asks for %d KiB of memory to derive its key, "+
			"above the %d KiB limit", ErrCorruptIndex, c.Memory, MaxKDFMemoryKiB)
	}
	if c.Time == 0 || c.Threads == 0 {
		return fmt.Errorf("format: %w: key derivation needs a positive time and thread count",
			ErrCorruptIndex)
	}
	// Time is as dangerous as memory, just slower to notice: Argon2id cost is
	// linear in it, about 1.8 s per iteration at the memory cap, so a crafted
	// header asking for 2^32-1 iterations hangs a listing for centuries after
	// the user has typed their passphrase.
	if c.Time > MaxKDFTime {
		return fmt.Errorf("format: %w: the archive asks for %d key-derivation passes, above the %d limit",
			ErrCorruptIndex, c.Time, MaxKDFTime)
	}
	return nil
}

// Sizes and limits for the crypto header.
const (
	CryptoSaltSize  = 16
	CryptoCheckSize = 32

	// MaxKDFMemoryKiB caps what an archive may ask this machine to allocate
	// while deriving its key: 4 GiB. The figure is the archive's, so without
	// a bound a crafted header is a one-line memory bomb.
	MaxKDFMemoryKiB = 4 * 1024 * 1024

	// MaxKDFTime caps the Argon2id pass count. Twenty times the default of 3
	// leaves room for anyone who wants a slower key, and bounds the worst
	// case at the memory cap to a couple of minutes rather than forever.
	MaxKDFTime = 64

	// MaxCryptoHeaderLen caps the header's own length. A real one is a couple
	// of hundred bytes; the field is 32 bits, and a reader allocates what it
	// says before it has decoded a byte.
	MaxCryptoHeaderLen = 64 * 1024
)
