package format

import (
	"encoding/binary"
	"errors"
	"testing"
)

func sampleHeader() Header {
	return Header{
		VersionMajor:     VersionMajor,
		VersionMinor:     VersionMinor,
		CreatedUnixNanos: 1758326400123456789,
		ArchiveUUID:      [16]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 1, 2, 3, 4, 5, 6, 7, 8},
	}
}

func mustMarshalHeader(t *testing.T, h Header) []byte {
	t.Helper()
	b, err := h.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if len(b) != HeaderSize {
		t.Fatalf("header is %d bytes, want %d", len(b), HeaderSize)
	}
	return b
}

func TestHeaderRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		h    Header
	}{
		{"plain", sampleHeader()},
		{"encrypted", func() Header {
			h := sampleHeader()
			h.Flags = FlagEncrypted
			h.CryptoHeaderLen = 137
			return h
		}()},
		{"zero times", Header{VersionMajor: VersionMajor, VersionMinor: VersionMinor}},
		{"negative time", func() Header {
			h := sampleHeader()
			h.CreatedUnixNanos = -1 // pre-1970; must survive the uint64 round trip
			return h
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := mustMarshalHeader(t, tc.h)

			var got Header
			if err := got.UnmarshalBinary(b); err != nil {
				t.Fatalf("UnmarshalBinary: %v", err)
			}
			if got != tc.h {
				t.Errorf("round trip changed the header:\n got %+v\nwant %+v", got, tc.h)
			}
		})
	}
}

func TestHeaderBodyOffset(t *testing.T) {
	h := sampleHeader()
	if got := h.BodyOffset(); got != HeaderSize {
		t.Errorf("plaintext body offset = %d, want %d", got, HeaderSize)
	}

	h.Flags = FlagEncrypted
	h.CryptoHeaderLen = 100
	if got, want := h.BodyOffset(), int64(HeaderSize+100); got != want {
		t.Errorf("encrypted body offset = %d, want %d", got, want)
	}
}

func TestHeaderTrailingBytesIgnored(t *testing.T) {
	// A caller may read more than it needs; the extra must not matter.
	b := append(mustMarshalHeader(t, sampleHeader()), 0xff, 0xff, 0xff)
	var got Header
	if err := got.UnmarshalBinary(b); err != nil {
		t.Fatalf("UnmarshalBinary with trailing bytes: %v", err)
	}
}

func TestHeaderRejects(t *testing.T) {
	good := mustMarshalHeader(t, sampleHeader())

	corrupt := func(fn func(b []byte)) []byte {
		b := make([]byte, HeaderSize)
		copy(b, good)
		fn(b)
		return b
	}

	for _, tc := range []struct {
		name string
		in   []byte
		want error
	}{
		{"empty", nil, ErrTruncated},
		{"short", good[:HeaderSize-1], ErrTruncated},
		{"bad magic", corrupt(func(b []byte) { b[0] ^= 0xff }), ErrBadMagic},
		{"flipped byte in body", corrupt(func(b []byte) { b[20] ^= 0x01 }), ErrChecksum},
		{"flipped byte in crc", corrupt(func(b []byte) { b[63] ^= 0x01 }), ErrChecksum},
		{"reserved bytes set", corrupt(func(b []byte) { b[50] = 1 }), ErrChecksum},
		{"future major", corrupt(func(b []byte) {
			binary.LittleEndian.PutUint16(b[8:10], VersionMajor+1)
			binary.LittleEndian.PutUint32(b[60:64], crc32c(b[0:60])) // re-checksum
		}), ErrUnsupportedVersion},
		// A flag or a reserved byte that this build does not know is a
		// change it must not ignore: the archive is too new, not damaged.
		{"unknown flag", corrupt(func(b []byte) {
			binary.LittleEndian.PutUint32(b[12:16], 1<<5)
			binary.LittleEndian.PutUint32(b[60:64], crc32c(b[0:60]))
		}), ErrUnsupportedVersion},
		{"reserved byte with a valid crc", corrupt(func(b []byte) {
			b[59] = 1
			binary.LittleEndian.PutUint32(b[60:64], crc32c(b[0:60]))
		}), ErrUnsupportedVersion},
		{"encrypted flag without crypto header", corrupt(func(b []byte) {
			binary.LittleEndian.PutUint32(b[12:16], uint32(FlagEncrypted))
			binary.LittleEndian.PutUint32(b[60:64], crc32c(b[0:60]))
		}), ErrCorruptIndex},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var h Header
			err := h.UnmarshalBinary(tc.in)
			if !errors.Is(err, tc.want) {
				t.Errorf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestHeaderMarshalRejectsInconsistentFlags(t *testing.T) {
	h := sampleHeader()
	h.Flags = FlagEncrypted // but CryptoHeaderLen stays 0
	if _, err := h.MarshalBinary(); err == nil {
		t.Fatal("marshalling an encrypted header with no crypto header should fail")
	}

	h = sampleHeader()
	h.CryptoHeaderLen = 10 // but the flag is not set
	if _, err := h.MarshalBinary(); err == nil {
		t.Fatal("marshalling a crypto header with no encrypted flag should fail")
	}
}

// TestHeaderMagicIsStable pins the magic bytes. If this test has to change,
// the format has changed and every archive ever written stops being readable.
func TestHeaderMagicIsStable(t *testing.T) {
	b := mustMarshalHeader(t, sampleHeader())
	if got, want := string(b[0:8]), "EICTAR\x1a\n"; got != want {
		t.Errorf("magic = %q, want %q", got, want)
	}
}

// TestCryptoHeaderLenIsCapped: the field is 32 bits and a reader allocates
// what it says, so an oversized claim must fail at decode.
func TestCryptoHeaderLenIsCapped(t *testing.T) {
	h := sampleHeader()
	h.Flags = FlagEncrypted
	h.CryptoHeaderLen = MaxCryptoHeaderLen
	b := mustMarshalHeader(t, h)
	var got Header
	if err := got.UnmarshalBinary(b); err != nil {
		t.Fatalf("a header at the limit was refused: %v", err)
	}

	binary.LittleEndian.PutUint32(b[40:44], MaxCryptoHeaderLen+1)
	binary.LittleEndian.PutUint32(b[60:64], crc32c(b[0:60]))
	if err := got.UnmarshalBinary(b); !errors.Is(err, ErrCorruptIndex) {
		t.Errorf("error = %v, want ErrCorruptIndex for an oversized crypto header", err)
	}
}

func TestCryptoHeaderRefusesCostlyParameters(t *testing.T) {
	base := func() *CryptoHeader {
		return &CryptoHeader{
			Version: CryptoHeaderVersion, KDF: KDFArgon2id,
			Salt: make([]byte, CryptoSaltSize), Time: 3, Memory: 256 * 1024, Threads: 4,
			AEAD: AEADXChaCha20, Key: make([]byte, CryptoWrappedKeySize),
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(c *CryptoHeader)
	}{
		{"time above the cap", func(c *CryptoHeader) { c.Time = MaxKDFTime + 1 }},
		{"time at uint32 max", func(c *CryptoHeader) { c.Time = ^uint32(0) }},
		{"memory above the cap", func(c *CryptoHeader) { c.Memory = MaxKDFMemoryKiB + 1 }},
		{"zero time", func(c *CryptoHeader) { c.Time = 0 }},
		{"zero threads", func(c *CryptoHeader) { c.Threads = 0 }},
		{"zero memory", func(c *CryptoHeader) { c.Memory = 0 }},
		{"memory below 8 KiB a thread", func(c *CryptoHeader) { c.Memory = 8*4 - 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			tc.mutate(c)
			// A damaged header is ErrCorruptIndex, which is exit 3, and not an
			// error of this build (exit 4).
			if err := c.Validate(); !errors.Is(err, ErrCorruptIndex) {
				t.Errorf("got %v, want ErrCorruptIndex", err)
			}
		})
	}
	if err := base().Validate(); err != nil {
		t.Errorf("the defaults were refused: %v", err)
	}
}
