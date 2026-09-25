// Package format implements the eictar on-disk structures: the file header,
// the footer trailer and the index.
//
// The authoritative specification is doc/design.md sections 2 to 6. Any change
// here that alters bytes on disk must be reflected there, and must bump
// VersionMinor (for a backward-compatible addition) or VersionMajor (for a
// change that older readers cannot handle).
package format

import "hash/crc32"

// Format version written into the header and the trailer.
const (
	VersionMajor uint16 = 1
	VersionMinor uint16 = 0
)

// Fixed structure sizes, in bytes.
const (
	HeaderSize  = 64
	TrailerSize = 96
	DigestSize  = 32 // BLAKE3-256
)

// Magic values. The \x1a\n in the header magic stops a terminal from spewing
// when an archive is cat-ed, and defeats naive text sniffing.
var (
	HeaderMagic  = [8]byte{'E', 'I', 'C', 'T', 'A', 'R', 0x1a, '\n'}
	TrailerMagic = [8]byte{'E', 'I', 'C', 'T', 'R', 'A', 'I', 'L'}
)

// HeaderFlags and TrailerFlags are the two flag words, kept as distinct types
// so that one cannot be tested against the other's constants.
//
// Both are bit 0 of a uint32 field, and both mean something about encryption,
// but they are different fields of different structures: FlagEncrypted says
// the members are encrypted, FlagIndexEncrypted says the index is sealed. As
// plain uint32s, `trailer.Flags&FlagEncrypted` would compile and answer the
// wrong question in silence. As distinct types it does not compile at all.
type (
	HeaderFlags  uint32
	TrailerFlags uint32
)

// Header flags.
const (
	// FlagEncrypted marks an archive whose members are encrypted. When set, a
	// crypto header of CryptoHeaderLen bytes follows the file header.
	FlagEncrypted HeaderFlags = 1 << 0
)

// Trailer flags.
const (
	// FlagIndexEncrypted marks an index sealed with the index key.
	FlagIndexEncrypted TrailerFlags = 1 << 0
	// FlagIndexCompressed marks a zstd-compressed index.
	FlagIndexCompressed TrailerFlags = 1 << 1
)

// crc32cTable is the Castagnoli polynomial used by both fixed structures.
var crc32cTable = crc32.MakeTable(crc32.Castagnoli)

// crc32c returns the CRC-32C of b.
func crc32c(b []byte) uint32 { return crc32.Checksum(b, crc32cTable) }
