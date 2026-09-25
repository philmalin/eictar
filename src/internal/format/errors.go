package format

import "errors"

// Sentinel errors. Callers distinguish "this is not an eictar archive" from
// "this archive is damaged" from "this archive is too new for me", because the
// three warrant different exit codes (doc/design.md section 10.7) and very
// different advice to the user.
var (
	// ErrBadMagic means the bytes are not an eictar structure at all.
	ErrBadMagic = errors.New("not an eictar archive: bad magic")

	// ErrUnsupportedVersion means the structure is an eictar one, but its
	// major version is beyond what this build understands.
	ErrUnsupportedVersion = errors.New("unsupported format version")

	// ErrChecksum means a fixed structure failed its CRC-32C, so the archive
	// is damaged rather than merely foreign.
	ErrChecksum = errors.New("checksum mismatch")

	// ErrTruncated means the input is shorter than the structure requires.
	ErrTruncated = errors.New("truncated")

	// ErrCorruptIndex means the index failed to decompress, decode, or passed
	// decode but violates an invariant the rest of the code relies on.
	ErrCorruptIndex = errors.New("corrupt index")

	// ErrIndexTooLarge means the index exceeded the decode limit. It is
	// reported separately from ErrCorruptIndex because it is the signature of
	// a decompression bomb rather than of ordinary damage.
	ErrIndexTooLarge = errors.New("index exceeds maximum decoded size")

	// ErrVersionMismatch means the header and the trailer disagree about the
	// format version, which no writer of ours produces.
	ErrVersionMismatch = errors.New("header and trailer version mismatch")
)
