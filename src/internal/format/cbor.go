package format

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// CBOR policy for the index.
//
// The library defaults are wrong for us in three separate ways, and each one
// is a real defect rather than a preference:
//
//  1. Map keys are emitted in Go map iteration order, so encoding the same
//     index twice produces different bytes and therefore a different trailer
//     digest. Sorting is required for a reproducible archive.
//  2. Text strings are rejected on decode unless they are valid UTF-8, but a
//     POSIX path is an arbitrary byte sequence. A file named with Latin-1
//     bytes would be archivable and then unreadable.
//  3. The default limit of 131072 array elements silently caps an archive at
//     131072 members, while raising that limit without a second bound turns a
//     nine-byte header into an unbounded allocation.
const (
	// MaxIndexMembers caps the members in one index. Archives beyond this
	// need the paged index described in doc/design.md section 15, not a
	// bigger number here.
	MaxIndexMembers = 1 << 22 // 4,194,304

	// minBytesPerElement converts the input length into a bound on how many
	// array elements it can possibly hold, so a small input cannot claim a
	// huge array.
	//
	// It must be the true minimum, which is one byte: a CBOR array element
	// can be a small integer encoded in a single byte, and a chunk table is
	// exactly that - thousands of lengths in an otherwise tiny index. A
	// larger assumption rejects valid archives, which is how this constant
	// was found: one 200 MB file produced a 300-byte index holding 48 chunk
	// lengths, and a bound of len/8 refused it.
	//
	// The bomb this guards against is therefore stopped by MaxIndexMembers
	// rather than by this figure; see decModeFor.
	minBytesPerElement = 1

	// maxIndexMapPairs caps one map, which in practice means the xattrs of a
	// single member.
	maxIndexMapPairs = 1 << 16
)

// encMode is the deterministic encoder. Bytewise-lexical key sorting is what
// makes an index reproducible: the same members must always yield the same
// bytes, because the trailer commits to their digest.
var encMode = func() cbor.EncMode {
	m, err := cbor.EncOptions{
		Sort: cbor.SortBytewiseLexical,
	}.EncMode()
	if err != nil {
		panic("format: building the CBOR encoder: " + err.Error())
	}
	return m
}()

// decModeFor builds a decoder whose array bound is derived from the input, so
// that a claimed element count is always backed by bytes actually present.
//
// It is built per call because the bound depends on the input length; the cost
// is paid once per archive open, against an index read that dwarfs it.
func decModeFor(inputLen int) (cbor.DecMode, error) {
	// Two bounds, both needed. The input length says how many elements the
	// bytes could possibly encode; MaxIndexMembers caps the worst-case
	// allocation, since the decoder sizes a slice straight from the array
	// header before reading any of it.
	maxElems := inputLen / minBytesPerElement
	maxElems = min(maxElems, MaxIndexMembers)
	// The library requires at least 16, and a tiny valid index must still
	// decode.
	maxElems = max(maxElems, 16)

	m, err := cbor.DecOptions{
		// POSIX paths and xattr names are byte sequences, not UTF-8. Refusing
		// them here would make perfectly ordinary files unarchivable.
		UTF8:             cbor.UTF8DecodeInvalid,
		MaxArrayElements: maxElems,
		MaxMapPairs:      maxIndexMapPairs,
		// Our encoder emits neither of these; accepting them would only widen
		// what a crafted archive can express.
		IndefLength: cbor.IndefLengthForbidden,
		TagsMd:      cbor.TagsForbidden,
		// A duplicate key lets two readers disagree about the same index.
		DupMapKey: cbor.DupMapKeyEnforcedAPF,
	}.DecMode()
	if err != nil {
		return nil, fmt.Errorf("format: building the CBOR decoder: %w", err)
	}
	return m, nil
}
