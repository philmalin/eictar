package format

import (
	"encoding/binary"
	"fmt"
)

// Trailer is the 96-byte structure at the very end of an archive. Writing it
// is the commit point for every mutation (doc/design.md section 9): until
// these bytes land, the archive still describes its previous generation.
//
// Layout (doc/format.md 10), little-endian:
//
//	 0   8  trailer_magic "EICTRAIL"
//	 8   2  format_major
//	10   2  format_minor
//	12   4  trailer_flags
//	16   8  generation
//	24   8  index_offset
//	32   8  index_length
//	40   8  prev_index_offset (0 if none)
//	48   8  live_member_count
//	56  32  index_digest (BLAKE3-256 over the on-disk index bytes)
//	88   4  reserved (zero)
//	92   4  crc32c over bytes 0..91
type Trailer struct {
	VersionMajor    uint16
	VersionMinor    uint16
	Flags           TrailerFlags
	Generation      uint64
	IndexOffset     uint64
	IndexLength     uint64
	PrevIndexOffset uint64
	LiveMembers     uint64
	IndexDigest     [DigestSize]byte
}

// IndexEncrypted reports whether the index is sealed.
func (t *Trailer) IndexEncrypted() bool { return t.Flags&FlagIndexEncrypted != 0 }

// IndexCompressed reports whether the index is zstd-compressed.
func (t *Trailer) IndexCompressed() bool { return t.Flags&FlagIndexCompressed != 0 }

// MarshalBinary encodes the trailer into exactly TrailerSize bytes.
func (t *Trailer) MarshalBinary() ([]byte, error) {
	b := make([]byte, TrailerSize)
	copy(b[0:8], TrailerMagic[:])
	binary.LittleEndian.PutUint16(b[8:10], t.VersionMajor)
	binary.LittleEndian.PutUint16(b[10:12], t.VersionMinor)
	binary.LittleEndian.PutUint32(b[12:16], uint32(t.Flags))
	binary.LittleEndian.PutUint64(b[16:24], t.Generation)
	binary.LittleEndian.PutUint64(b[24:32], t.IndexOffset)
	binary.LittleEndian.PutUint64(b[32:40], t.IndexLength)
	binary.LittleEndian.PutUint64(b[40:48], t.PrevIndexOffset)
	binary.LittleEndian.PutUint64(b[48:56], t.LiveMembers)
	copy(b[56:88], t.IndexDigest[:])
	// b[88:92] stays zero: reserved.
	binary.LittleEndian.PutUint32(b[92:96], crc32c(b[0:92]))
	return b, nil
}

// UnmarshalBinary decodes a trailer from the last TrailerSize bytes of b.
//
// It takes the tail rather than the head so a caller can hand over whatever it
// read from the end of the file without arithmetic of its own.
func (t *Trailer) UnmarshalBinary(b []byte) error {
	if len(b) < TrailerSize {
		return fmt.Errorf("format: trailer: %w: have %d bytes, need %d",
			ErrTruncated, len(b), TrailerSize)
	}
	b = b[len(b)-TrailerSize:]

	if string(b[0:8]) != string(TrailerMagic[:]) {
		return ErrBadMagic
	}
	if got, want := binary.LittleEndian.Uint32(b[92:96]), crc32c(b[0:92]); got != want {
		return fmt.Errorf("format: trailer: %w: stored %#08x, computed %#08x",
			ErrChecksum, got, want)
	}

	t.VersionMajor = binary.LittleEndian.Uint16(b[8:10])
	t.VersionMinor = binary.LittleEndian.Uint16(b[10:12])
	if t.VersionMajor != VersionMajor {
		return fmt.Errorf("format: trailer: %w: archive is v%d.x, this build reads v%d.x",
			ErrUnsupportedVersion, t.VersionMajor, VersionMajor)
	}

	t.Flags = TrailerFlags(binary.LittleEndian.Uint32(b[12:16]))
	if unknown := t.Flags &^ knownTrailerFlags; unknown != 0 {
		return fmt.Errorf("format: trailer: %w: flags %#x that this build does not know; %s",
			ErrUnsupportedVersion, uint32(unknown), newerVersion)
	}
	if !allZero(b[88:92]) {
		return fmt.Errorf("format: trailer: %w: the reserved bytes are not zero; %s",
			ErrUnsupportedVersion, newerVersion)
	}
	t.Generation = binary.LittleEndian.Uint64(b[16:24])
	t.IndexOffset = binary.LittleEndian.Uint64(b[24:32])
	t.IndexLength = binary.LittleEndian.Uint64(b[32:40])
	t.PrevIndexOffset = binary.LittleEndian.Uint64(b[40:48])
	t.LiveMembers = binary.LittleEndian.Uint64(b[48:56])
	copy(t.IndexDigest[:], b[56:88])
	return nil
}

// ValidateAgainst checks the trailer against the archive header and the total
// file size. A trailer that passes its own CRC can still be nonsense - an
// index that starts before the body or runs past the end of the file - and
// every one of those would otherwise become a bad seek or a wild allocation.
func (t *Trailer) ValidateAgainst(h *Header, fileSize int64) error {
	if t.VersionMajor != h.VersionMajor || t.VersionMinor != h.VersionMinor {
		return fmt.Errorf("format: %w: header v%d.%d, trailer v%d.%d",
			ErrVersionMismatch, h.VersionMajor, h.VersionMinor,
			t.VersionMajor, t.VersionMinor)
	}
	if t.IndexEncrypted() && !h.Encrypted() {
		return fmt.Errorf("format: trailer: %w: index marked encrypted in an unencrypted archive",
			ErrCorruptIndex)
	}

	body := h.BodyOffset()
	end := fileSize - TrailerSize // the index must end at or before the trailer

	off := int64(t.IndexOffset)
	length := int64(t.IndexLength)
	if off < body || length < 0 || off > end || length > end-off {
		return fmt.Errorf("format: trailer: %w: index [%d,+%d) outside body [%d,%d)",
			ErrCorruptIndex, t.IndexOffset, t.IndexLength, body, end)
	}
	if t.PrevIndexOffset != 0 && (int64(t.PrevIndexOffset) < body || int64(t.PrevIndexOffset) > end) {
		return fmt.Errorf("format: trailer: %w: prev index offset %d outside body [%d,%d)",
			ErrCorruptIndex, t.PrevIndexOffset, body, end)
	}
	return nil
}
