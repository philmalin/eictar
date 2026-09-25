package format

import (
	"encoding/binary"
	"fmt"
)

// Header is the 64-byte structure at offset 0 of every archive. It is always
// plaintext: it has to be readable before any key exists.
//
// Layout (doc/design.md 3.1), little-endian:
//
//	 0   8  magic "EICTAR\x1a\n"
//	 8   2  format_major
//	10   2  format_minor
//	12   4  header_flags
//	16   8  created_unix_nanos
//	24  16  archive_uuid
//	40   4  crypto_header_len
//	44  16  reserved (zero)
//	60   4  crc32c over bytes 0..59
type Header struct {
	VersionMajor     uint16
	VersionMinor     uint16
	Flags            HeaderFlags
	CreatedUnixNanos int64
	ArchiveUUID      [16]byte
	CryptoHeaderLen  uint32
}

// Encrypted reports whether the archive's members are encrypted.
func (h *Header) Encrypted() bool { return h.Flags&FlagEncrypted != 0 }

// BodyOffset returns the offset of the first member blob: the header, plus the
// crypto header when there is one.
func (h *Header) BodyOffset() int64 {
	return HeaderSize + int64(h.CryptoHeaderLen)
}

// MarshalBinary encodes the header into exactly HeaderSize bytes.
func (h *Header) MarshalBinary() ([]byte, error) {
	if h.Encrypted() != (h.CryptoHeaderLen > 0) {
		// Catch the mistake at the writer rather than leaving a reader to
		// discover an unreadable archive later.
		return nil, fmt.Errorf("format: FlagEncrypted=%v but CryptoHeaderLen=%d",
			h.Encrypted(), h.CryptoHeaderLen)
	}

	b := make([]byte, HeaderSize)
	copy(b[0:8], HeaderMagic[:])
	binary.LittleEndian.PutUint16(b[8:10], h.VersionMajor)
	binary.LittleEndian.PutUint16(b[10:12], h.VersionMinor)
	binary.LittleEndian.PutUint32(b[12:16], uint32(h.Flags))
	binary.LittleEndian.PutUint64(b[16:24], uint64(h.CreatedUnixNanos))
	copy(b[24:40], h.ArchiveUUID[:])
	binary.LittleEndian.PutUint32(b[40:44], h.CryptoHeaderLen)
	// b[44:60] stays zero: reserved.
	binary.LittleEndian.PutUint32(b[60:64], crc32c(b[0:60]))
	return b, nil
}

// UnmarshalBinary decodes a header from b, which must be at least HeaderSize
// bytes. Bytes past HeaderSize are ignored, so a caller may hand it a larger
// read buffer.
func (h *Header) UnmarshalBinary(b []byte) error {
	if len(b) < HeaderSize {
		return fmt.Errorf("format: header: %w: have %d bytes, need %d",
			ErrTruncated, len(b), HeaderSize)
	}
	if string(b[0:8]) != string(HeaderMagic[:]) {
		return ErrBadMagic
	}
	// Checksum before trusting any field, so a damaged length cannot steer
	// later reads.
	if got, want := binary.LittleEndian.Uint32(b[60:64]), crc32c(b[0:60]); got != want {
		return fmt.Errorf("format: header: %w: stored %#08x, computed %#08x",
			ErrChecksum, got, want)
	}

	h.VersionMajor = binary.LittleEndian.Uint16(b[8:10])
	h.VersionMinor = binary.LittleEndian.Uint16(b[10:12])
	if h.VersionMajor != VersionMajor {
		return fmt.Errorf("format: header: %w: archive is v%d.x, this build reads v%d.x",
			ErrUnsupportedVersion, h.VersionMajor, VersionMajor)
	}

	h.Flags = HeaderFlags(binary.LittleEndian.Uint32(b[12:16]))
	h.CreatedUnixNanos = int64(binary.LittleEndian.Uint64(b[16:24]))
	copy(h.ArchiveUUID[:], b[24:40])
	h.CryptoHeaderLen = binary.LittleEndian.Uint32(b[40:44])

	if h.Encrypted() != (h.CryptoHeaderLen > 0) {
		return fmt.Errorf("format: header: %w: FlagEncrypted=%v with CryptoHeaderLen=%d",
			ErrCorruptIndex, h.Encrypted(), h.CryptoHeaderLen)
	}
	if h.CryptoHeaderLen > MaxCryptoHeaderLen {
		return fmt.Errorf("format: header: %w: crypto header claims %d bytes, above the %d limit",
			ErrCorruptIndex, h.CryptoHeaderLen, MaxCryptoHeaderLen)
	}
	return nil
}
