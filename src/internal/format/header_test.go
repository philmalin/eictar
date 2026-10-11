package format

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
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

func sampleCryptoHeader() *CryptoHeader {
	return &CryptoHeader{
		Version: CryptoHeaderVersion, KDF: KDFArgon2id,
		Salt: bytes.Repeat([]byte{0x5a}, CryptoSaltSize), Time: 3, Memory: 256 * 1024, Threads: 4,
		AEAD: AEADXChaCha20, Key: bytes.Repeat([]byte{0xa5}, CryptoWrappedKeySize),
	}
}

func TestCryptoHeaderRefusesCostlyParameters(t *testing.T) {
	base := sampleCryptoHeader
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
			// A damaged header is ErrCorruptIndex: damage, which --repair
			// acts on, and not a header that only a newer build reads.
			if err := c.Validate(); !errors.Is(err, ErrCorruptIndex) {
				t.Errorf("got %v, want ErrCorruptIndex", err)
			}
		})
	}
	if err := base().Validate(); err != nil {
		t.Errorf("the defaults were refused: %v", err)
	}
}

// TestCryptoHeaderRoundTrip: a reader gets back what the writer put in, from
// a block of exactly the length that the block gives.
func TestCryptoHeaderRoundTrip(t *testing.T) {
	want := sampleCryptoHeader()
	b, err := want.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if n := binary.LittleEndian.Uint32(b[0:4]); int(n) != len(b)-4 {
		t.Fatalf("the length is %d, the body %d bytes", n, len(b)-4)
	}
	got, err := UnmarshalCryptoHeader(b)
	if err != nil {
		t.Fatalf("UnmarshalCryptoHeader: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round trip:\n got %+v\nwant %+v", got, want)
	}
}

// rawCryptoHeader encodes c as Marshal does, but without its checks: what a
// hostile or damaged archive can hold.
func rawCryptoHeader(t *testing.T, c *CryptoHeader) []byte {
	t.Helper()
	body, err := encMode.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return append(binary.LittleEndian.AppendUint32(nil, uint32(len(body))), body...)
}

// TestCryptoHeaderRefusesUnknown: each case changes one field, so that only
// the check of that field can refuse it. A name that this build does not know
// is ErrUnsupportedVersion: a newer build can read the archive, so it is not
// damage. A wrong length is ErrCorruptIndex: damage, which --repair acts on.
// Both give exit 3. The reader and the writer refuse alike.
func TestCryptoHeaderRefusesUnknown(t *testing.T) {
	for _, tc := range []struct {
		name   string
		want   error
		mutate func(c *CryptoHeader)
	}{
		{"version 0", ErrUnsupportedVersion, func(c *CryptoHeader) { c.Version = 0 }},
		{"version 2", ErrUnsupportedVersion, func(c *CryptoHeader) { c.Version = 2 }},
		{"another KDF", ErrUnsupportedVersion, func(c *CryptoHeader) { c.KDF = "scrypt" }},
		{"no KDF", ErrUnsupportedVersion, func(c *CryptoHeader) { c.KDF = "" }},
		{"another cipher", ErrUnsupportedVersion, func(c *CryptoHeader) { c.AEAD = "aes-256-gcm" }},
		{"recipients", ErrUnsupportedVersion, func(c *CryptoHeader) { c.Recipients = []string{"age1example"} }},
		{"no salt", ErrCorruptIndex, func(c *CryptoHeader) { c.Salt = nil }},
		{"short salt", ErrCorruptIndex, func(c *CryptoHeader) { c.Salt = c.Salt[:CryptoSaltSize-1] }},
		{"long salt", ErrCorruptIndex, func(c *CryptoHeader) { c.Salt = append(c.Salt, 0) }},
		{"no wrapped key", ErrCorruptIndex, func(c *CryptoHeader) { c.Key = nil }},
		{"short wrapped key", ErrCorruptIndex, func(c *CryptoHeader) { c.Key = c.Key[:CryptoWrappedKeySize-1] }},
		{"long wrapped key", ErrCorruptIndex, func(c *CryptoHeader) { c.Key = append(c.Key, 0) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := sampleCryptoHeader()
			tc.mutate(c)
			if _, err := UnmarshalCryptoHeader(rawCryptoHeader(t, c)); !errors.Is(err, tc.want) {
				t.Errorf("UnmarshalCryptoHeader: got %v, want %v", err, tc.want)
			}
			if _, err := c.Marshal(); !errors.Is(err, tc.want) {
				t.Errorf("Marshal: got %v, want %v", err, tc.want)
			}
		})
	}
}

// TestCryptoHeaderRefusesExtraBytes: bytes after the CBOR map, inside the
// length that the block gives, are damage. A decoder that stops at the end of
// the map and returns what it has hides it.
func TestCryptoHeaderRefusesExtraBytes(t *testing.T) {
	b := rawCryptoHeader(t, sampleCryptoHeader())
	b = append(b, 0x00)
	binary.LittleEndian.PutUint32(b[0:4], uint32(len(b)-4))
	if _, err := UnmarshalCryptoHeader(b); !errors.Is(err, ErrCorruptIndex) {
		t.Errorf("got %v, want ErrCorruptIndex", err)
	}
}

// TestCryptoHeaderAcceptsLimits: each limit of the key derivation at its
// exact value is accepted. TestCryptoHeaderRefusesCostlyParameters refuses
// the value one past it.
func TestCryptoHeaderAcceptsLimits(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(c *CryptoHeader)
	}{
		{"memory at the cap", func(c *CryptoHeader) { c.Memory = MaxKDFMemoryKiB }},
		{"time at the cap", func(c *CryptoHeader) { c.Time = MaxKDFTime }},
		{"memory of 8 KiB a thread", func(c *CryptoHeader) { c.Memory = 8 * 4 }},
		{"one pass", func(c *CryptoHeader) { c.Time = 1 }},
	} {
		c := sampleCryptoHeader()
		tc.mutate(c)
		if err := c.Validate(); err != nil {
			t.Errorf("%s: refused: %v", tc.name, err)
		}
	}
}
