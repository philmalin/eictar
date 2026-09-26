package format

import (
	"fmt"
	"sort"
	"strings"

	"github.com/klauspost/compress/zstd"
	"lukechampine.com/blake3"
)

// MemberType names the kind of filesystem object a member holds.
type MemberType string

const (
	TypeReg      MemberType = "reg"
	TypeDir      MemberType = "dir"
	TypeSymlink  MemberType = "symlink"
	TypeHardlink MemberType = "hardlink"
	TypeFIFO     MemberType = "fifo"
	TypeSocket   MemberType = "sock"
	TypeCharDev  MemberType = "chardev"
	TypeBlockDev MemberType = "blockdev"
)

// HasPayload reports whether this member type stores content in the body.
// Everything else lives entirely in the index.
func (t MemberType) HasPayload() bool { return t == TypeReg }

// Valid reports whether t is a type this build knows.
func (t MemberType) Valid() bool {
	switch t {
	case TypeReg, TypeDir, TypeSymlink, TypeHardlink,
		TypeFIFO, TypeSocket, TypeCharDev, TypeBlockDev:
		return true
	}
	return false
}

// NoCodec is the Member.Codec value for stored (uncompressed) content.
const NoCodec = -1

// CodecSpec is one entry of the index's codec catalog. Members reference it by
// position, so an archive of a million files compressed alike stores the
// parameters once.
type CodecSpec struct {
	Name   string         `cbor:"name"`
	Params map[string]any `cbor:"params,omitempty"`
	// Dict is the id of the dictionary (Index.Dicts) that the codec used, or
	// zero. Unlike Params, a reader needs it to decode (doc/design.md 4.2).
	Dict uint32 `cbor:"dict,omitempty"`
}

// Dict is a dictionary that some codec entries use (doc/design.md 4.2). Its
// blob is one chunk, not compressed, and sealed as a whole when the archive
// is encrypted.
type Dict struct {
	ID         uint32   `cbor:"id"` // the id that the dictionary carries
	Generation uint64   `cbor:"gen"`
	Size       uint32   `cbor:"size"`   // plaintext length
	Digest     []byte   `cbor:"digest"` // BLAKE3-256 of the plaintext, keyed as member digests are
	Enc        *EncInfo `cbor:"enc,omitempty"`
	Offset     uint64   `cbor:"off"`
	Length     uint64   `cbor:"len"` // on disk: Size, or Size plus the tag when sealed
}

// MaxDictSize caps a dictionary. A reader holds each one that it uses in
// memory, so the index must not be able to claim more.
const MaxDictSize = 1 << 20

// MaxDicts caps the dictionaries of one index.
const MaxDicts = 1024

// EncInfo carries the per-member encryption parameters. The key itself is
// derived from the passphrase and this salt; see doc/design.md 6.2.
type EncInfo struct {
	Salt []byte `cbor:"salt"`
}

// SparseSegment is one run of real data in a sparse file. Absent segments mean
// a dense file.
type SparseSegment struct {
	Offset uint64 `cbor:"off"`
	Length uint64 `cbor:"len"`
}

// Member is one entry in the archive: a file, a directory, a link or a device.
//
// Field order here follows doc/design.md section 5. The cbor keys are short
// but remain strings, so an index dumped with a generic CBOR tool is still
// readable by a human debugging an archive.
type Member struct {
	ID         uint64     `cbor:"id"`
	Generation uint64     `cbor:"gen"`
	Path       string     `cbor:"path"`
	Type       MemberType `cbor:"type"`
	Mode       uint32     `cbor:"mode"`
	// UID and GID are pointers so that "not recorded" (--no-owner) is
	// distinct from uid 0. A stored zero would silently mean root to a reader
	// run with --preserve-owner.
	UID        *uint32 `cbor:"uid,omitempty"`
	GID        *uint32 `cbor:"gid,omitempty"`
	Uname      string  `cbor:"uname,omitempty"`
	Gname      string  `cbor:"gname,omitempty"`
	MTimeNanos int64   `cbor:"mtime"`
	ATimeNanos int64   `cbor:"atime,omitempty"`
	CTimeNanos int64   `cbor:"ctime,omitempty"`
	Size       uint64  `cbor:"size"`
	LinkTarget string  `cbor:"link,omitempty"`
	HardlinkTo uint64  `cbor:"hardlink,omitempty"`
	// Data is the id of the member whose blob holds this member's content
	// (doc/design.md 4.3). Such a member has no blob of its own.
	Data      uint64            `cbor:"data,omitempty"`
	RDev      []uint32          `cbor:"rdev,omitempty"` // {major, minor}
	Xattrs    map[string][]byte `cbor:"xattrs,omitempty"`
	Sparse    []SparseSegment   `cbor:"sparse,omitempty"`
	Digest    []byte            `cbor:"digest,omitempty"` // BLAKE3-256 of the plaintext
	Codec     int               `cbor:"codec"`            // index into Index.Codecs, or NoCodec
	ChunkSize uint32            `cbor:"chunk,omitempty"`  // plaintext bytes per chunk
	Enc       *EncInfo          `cbor:"enc,omitempty"`
	Offset    uint64            `cbor:"off,omitempty"`
	Length    uint64            `cbor:"len,omitempty"`
	Chunks    []uint32          `cbor:"chunks,omitempty"` // on-disk length of each chunk
	Dead      bool              `cbor:"dead,omitempty"`   // tombstone
}

// Index is the archive's catalog, stored once at the end of the file.
type Index struct {
	Version    uint32      `cbor:"v"`
	Generation uint64      `cbor:"gen"`
	Codecs     []CodecSpec `cbor:"codecs,omitempty"`
	Dicts      []Dict      `cbor:"dicts,omitempty"`
	Members    []Member    `cbor:"members"`
}

// IndexVersion is the schema version of the index document itself. It is
// separate from the format version in the header: the index can gain fields
// without the container changing.
const IndexVersion uint32 = 1

// MaxChunkSize caps a member's declared chunk size.
//
// A reader sizes its decode buffer from this number, and the number comes out
// of the index, which is attacker-controlled: a 200-byte archive claiming a
// 2 GiB chunk size made the reader allocate 2 GiB before discovering the chunk
// was five bytes long. Extraction runs one of those per worker.
//
// 256 MiB is far above the 4 MiB default and any plausible setting, and bounds
// the damage a crafted index can do to memory it can claim without providing
// bytes to back it.
const MaxChunkSize = 1 << 28

// Limits on metadata, from Linux's own: XATTR_NAME_MAX and XATTR_SIZE_MAX.
// A value the kernel could never have produced is a crafted index.
const (
	MaxXattrName  = 255
	MaxXattrValue = 64 * 1024
	// MaxXattrs caps the attributes on one member, so that a crafted member
	// cannot spend the whole index budget on attribute maps.
	MaxXattrs = 1024
)

// ModeMask is every bit a member's mode may carry: permissions plus setuid,
// setgid and sticky. The file type is the Type field, never mode bits.
const ModeMask = 0o7777

// OwnerID returns a pointer for Member.UID and Member.GID.
func OwnerID(v uint32) *uint32 { return &v }

// PayloadSize is the number of plaintext bytes the member's blob carries.
//
// For a dense file it is the size. For a sparse file only the data segments
// are stored, so it is their total, and Size is the logical length including
// the holes. The chunk table describes the payload, not the logical file.
func (m *Member) PayloadSize() uint64 {
	if len(m.Sparse) == 0 {
		return m.Size
	}
	var n uint64
	for _, seg := range m.Sparse {
		n += seg.Length
	}
	return n
}

// MaxIndexSize caps the decoded index. Without it, a hostile archive claims a
// small compressed index that inflates without bound, and a listing turns into
// an out-of-memory kill.
const MaxIndexSize = 1 << 30 // 1 GiB

// Live returns the members that are not tombstoned.
func (ix *Index) Live() []Member {
	out := make([]Member, 0, len(ix.Members))
	for _, m := range ix.Members {
		if !m.Dead {
			out = append(out, m)
		}
	}
	return out
}

// LiveCount returns the number of members that are not tombstoned, which is
// what the trailer records.
func (ix *Index) LiveCount() uint64 {
	var n uint64
	for _, m := range ix.Members {
		if !m.Dead {
			n++
		}
	}
	return n
}

// Sealer seals plaintext index bytes. It is nil until encryption lands (M4);
// the signature is fixed now so the pipeline does not have to change then.
type Sealer func(plaintext []byte) (ciphertext []byte, err error)

// Opener is the inverse of a Sealer.
type Opener func(ciphertext []byte) (plaintext []byte, err error)

// EncodeOptions controls how an index becomes bytes on disk.
type EncodeOptions struct {
	// Compress runs the encoded index through zstd. On by default for any
	// real archive; tests turn it off to inspect the CBOR directly.
	Compress bool
	// Seal, when non-nil, encrypts the (possibly compressed) index.
	Seal Sealer
	// Digest computes the value the trailer records. It is supplied by the
	// caller because an encrypted archive keys it, and a keyed digest is what
	// stops an attacker rewriting metadata they cannot read (doc/design.md
	// 6.4). Nil means the plain BLAKE3 of the bytes.
	Digest func([]byte) [DigestSize]byte
}

// EncodedIndex is the result of encoding: the bytes to write, the flags the
// trailer must carry so a reader can reverse the pipeline, and the digest the
// trailer records.
type EncodedIndex struct {
	Bytes []byte
	// Flags are trailer flags: the index's own encoding is recorded there, so
	// a reader knows how to reverse the pipeline before decoding anything.
	Flags  TrailerFlags
	Digest [DigestSize]byte
}

// Encode serializes the index: CBOR, then optional zstd, then optional seal.
//
// The order matters and is not negotiable: compressing after encryption would
// achieve nothing, and sealing before compression would leak nothing useful
// either. See doc/design.md 6.3.
func (ix *Index) Encode(opt EncodeOptions) (*EncodedIndex, error) {
	if ix.Version == 0 {
		ix.Version = IndexVersion
	}
	if err := ix.Validate(); err != nil {
		return nil, err
	}

	b, err := encMode.Marshal(ix)
	if err != nil {
		return nil, fmt.Errorf("format: encoding index: %w", err)
	}

	var flags TrailerFlags
	if opt.Compress {
		enc, err := zstd.NewWriter(nil,
			zstd.WithEncoderLevel(zstd.SpeedDefault),
			// The index is encoded on one goroutine while the rest of the
			// program is busy with member payloads; do not let zstd spawn its
			// own pool on top of our worker pool.
			zstd.WithEncoderConcurrency(1))
		if err != nil {
			return nil, fmt.Errorf("format: index compressor: %w", err)
		}
		b = enc.EncodeAll(b, nil)
		if err := enc.Close(); err != nil {
			return nil, fmt.Errorf("format: index compressor: %w", err)
		}
		flags |= FlagIndexCompressed
	}

	if opt.Seal != nil {
		if b, err = opt.Seal(b); err != nil {
			return nil, fmt.Errorf("format: sealing index: %w", err)
		}
		flags |= FlagIndexEncrypted
	}

	digest := blake3.Sum256(b)
	if opt.Digest != nil {
		digest = opt.Digest(b)
	}
	return &EncodedIndex{Bytes: b, Flags: flags, Digest: digest}, nil
}

// DecodeIndex reverses Encode. flags come from the trailer, and open must be
// non-nil exactly when the trailer says the index is sealed.
//
// Every failure here is attacker-reachable: the bytes may be arbitrary. The
// function must therefore return an error for anything it does not like, and
// never panic or allocate without bound.
func DecodeIndex(b []byte, flags TrailerFlags, open Opener) (*Index, error) {
	if flags&FlagIndexEncrypted != 0 {
		if open == nil {
			return nil, fmt.Errorf("format: index is encrypted but no passphrase was supplied")
		}
		plain, err := open(b)
		if err != nil {
			return nil, fmt.Errorf("format: opening index: %w", err)
		}
		b = plain
	} else if open != nil {
		// A sealed index that lost its flag would silently decode as garbage;
		// say so instead.
		return nil, fmt.Errorf("format: %w: index key supplied but index is not sealed",
			ErrCorruptIndex)
	}

	if flags&FlagIndexCompressed != 0 {
		dec, err := zstd.NewReader(nil,
			zstd.WithDecoderConcurrency(1),
			zstd.WithDecoderMaxMemory(MaxIndexSize))
		if err != nil {
			return nil, fmt.Errorf("format: index decompressor: %w", err)
		}
		defer dec.Close()

		plain, err := dec.DecodeAll(b, nil)
		if err != nil {
			// zstd reports its own limit breach here; map it to our sentinel
			// so callers need not know which layer complained.
			if len(plain) >= MaxIndexSize {
				return nil, fmt.Errorf("format: %w", ErrIndexTooLarge)
			}
			return nil, fmt.Errorf("format: %w: decompressing: %v", ErrCorruptIndex, err)
		}
		b = plain
	}

	if len(b) > MaxIndexSize {
		return nil, fmt.Errorf("format: %w: %d bytes", ErrIndexTooLarge, len(b))
	}

	dm, err := decModeFor(len(b))
	if err != nil {
		return nil, err
	}

	var ix Index
	if err := dm.Unmarshal(b, &ix); err != nil {
		return nil, fmt.Errorf("format: %w: decoding: %v", ErrCorruptIndex, err)
	}
	if ix.Version != IndexVersion {
		return nil, fmt.Errorf("format: %w: index schema v%d, this build reads v%d",
			ErrUnsupportedVersion, ix.Version, IndexVersion)
	}
	if err := ix.Validate(); err != nil {
		return nil, err
	}
	return &ix, nil
}

// Validate checks the invariants the rest of the program relies on. It runs on
// both encode and decode: on encode it catches our own bugs before they reach
// the disk, on decode it catches a hostile or damaged archive before a bad
// value reaches a seek or an allocation.
func (ix *Index) Validate() error {
	if len(ix.Members) > MaxIndexMembers {
		return fmt.Errorf("format: %w: %d members exceeds the limit of %d",
			ErrIndexTooLarge, len(ix.Members), MaxIndexMembers)
	}

	if err := ix.validateDicts(); err != nil {
		return err
	}

	types := make(map[uint64]MemberType, len(ix.Members))

	for i := range ix.Members {
		m := &ix.Members[i]

		if _, dup := types[m.ID]; dup {
			return corrupt(m, "duplicate member id")
		}
		types[m.ID] = m.Type

		if err := validateCommon(ix, m); err != nil {
			return err
		}
		if err := validateTypeFields(m); err != nil {
			return err
		}
		if err := validatePayload(m); err != nil {
			return err
		}
	}

	if err := ix.validateData(); err != nil {
		return err
	}

	// A hardlink names another member by id, so it can only be checked once
	// every id is known. The target must be a regular file: that rules out
	// chains and cycles, and a link to a directory, which POSIX forbids.
	for i := range ix.Members {
		m := &ix.Members[i]
		if m.Type != TypeHardlink {
			continue
		}
		target, ok := types[m.HardlinkTo]
		if !ok {
			return corrupt(m, fmt.Sprintf("hardlink to member %d, which does not exist", m.HardlinkTo))
		}
		if target != TypeReg {
			return corrupt(m, fmt.Sprintf("hardlink to member %d, which is a %s", m.HardlinkTo, target))
		}
	}
	return nil
}

// validateData checks each member that shares the content of another
// (doc/design.md 4.3): the owner is a regular file with a blob of its own,
// so that there are no chains, and it has the same payload - size, sparse map
// and digest - so that the member reads what its own fields describe.
func (ix *Index) validateData() error {
	byID := make(map[uint64]*Member, len(ix.Members))
	for i := range ix.Members {
		byID[ix.Members[i].ID] = &ix.Members[i]
	}
	for i := range ix.Members {
		m := &ix.Members[i]
		if m.Data == 0 {
			continue
		}
		o, ok := byID[m.Data]
		switch {
		case !ok:
			return corrupt(m, fmt.Sprintf("shares the content of member %d, which does not exist", m.Data))
		case o.Type != TypeReg || o.Data != 0 || o.Length == 0:
			return corrupt(m, fmt.Sprintf("shares the content of member %d, which holds no blob of its own", m.Data))
		case o.Size != m.Size || !sameSparse(o.Sparse, m.Sparse) || string(o.Digest) != string(m.Digest):
			return corrupt(m, fmt.Sprintf("shares the content of member %d, whose content differs", m.Data))
		}
	}
	return nil
}

func sameSparse(a, b []SparseSegment) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// validateDicts checks the dictionaries, and that each catalog entry names a
// dictionary that is there. Only zstd has dictionaries.
func (ix *Index) validateDicts() error {
	if len(ix.Dicts) > MaxDicts {
		return fmt.Errorf("format: %w: %d dictionaries exceeds the limit of %d",
			ErrIndexTooLarge, len(ix.Dicts), MaxDicts)
	}
	ids := make(map[uint32]bool, len(ix.Dicts))
	for _, d := range ix.Dicts {
		bad := func(what string) error {
			return fmt.Errorf("format: %w: dictionary %d: %s", ErrCorruptIndex, d.ID, what)
		}
		switch {
		case d.ID == 0:
			return bad("id 0")
		case ids[d.ID]:
			return bad("duplicate id")
		case d.Size == 0 || d.Size > MaxDictSize:
			return bad(fmt.Sprintf("size %d is outside 1..%d", d.Size, MaxDictSize))
		case len(d.Digest) != DigestSize:
			return bad(fmt.Sprintf("has a %d-byte digest", len(d.Digest)))
		case d.Length < uint64(d.Size) || d.Offset+d.Length < d.Offset:
			return bad(fmt.Sprintf("blob [%d,+%d) cannot hold %d bytes", d.Offset, d.Length, d.Size))
		}
		ids[d.ID] = true
	}
	for i, c := range ix.Codecs {
		if c.Dict == 0 {
			continue
		}
		if c.Name != "zstd" {
			return fmt.Errorf("format: %w: codec %d (%s) names a dictionary; only zstd has them",
				ErrCorruptIndex, i, c.Name)
		}
		if !ids[c.Dict] {
			return fmt.Errorf("format: %w: codec %d names dictionary %d, which the index does not hold",
				ErrCorruptIndex, i, c.Dict)
		}
	}
	return nil
}

func corrupt(m *Member, what string) error {
	return fmt.Errorf("format: %w: member %d (%q): %s", ErrCorruptIndex, m.ID, m.Path, what)
}

// validateCommon checks what every member type shares.
func validateCommon(ix *Index, m *Member) error {
	if !m.Type.Valid() {
		return corrupt(m, fmt.Sprintf("unknown type %q", m.Type))
	}
	if m.Path == "" {
		return corrupt(m, "empty path")
	}
	if m.Mode&^ModeMask != 0 {
		return corrupt(m, fmt.Sprintf("mode %#o carries bits beyond %#o", m.Mode, ModeMask))
	}
	if m.Codec < NoCodec || m.Codec >= len(ix.Codecs) {
		return corrupt(m, fmt.Sprintf("references codec %d of %d", m.Codec, len(ix.Codecs)))
	}
	if m.Digest != nil && len(m.Digest) != DigestSize {
		return corrupt(m, fmt.Sprintf("has a %d-byte digest", len(m.Digest)))
	}
	if m.ChunkSize > MaxChunkSize {
		return corrupt(m, fmt.Sprintf("claims a chunk size of %d, above the %d limit", m.ChunkSize, MaxChunkSize))
	}
	if len(m.Xattrs) > MaxXattrs {
		return corrupt(m, fmt.Sprintf("has %d extended attributes, above the %d limit", len(m.Xattrs), MaxXattrs))
	}
	for name, value := range m.Xattrs {
		if name == "" || len(name) > MaxXattrName {
			return corrupt(m, fmt.Sprintf("has an extended attribute with a %d-byte name", len(name)))
		}
		if len(value) > MaxXattrValue {
			return corrupt(m, fmt.Sprintf("extended attribute %q is %d bytes, above the %d limit",
				name, len(value), MaxXattrValue))
		}
	}
	return nil
}

// validateTypeFields checks that each field appears only on the types it
// belongs to. A symlink target on a regular file, or a device number on a
// directory, is not harmless noise: a reader keyed on the field rather than
// the type would act on it.
func validateTypeFields(m *Member) error {
	switch {
	case m.Type == TypeSymlink && m.LinkTarget == "":
		return corrupt(m, "symlink with no target")
	case m.Type != TypeSymlink && m.LinkTarget != "":
		return corrupt(m, "link target on a member that is not a symlink")
	case m.Type == TypeHardlink && m.HardlinkTo == 0:
		return corrupt(m, "hardlink with no target member")
	case m.Type != TypeHardlink && m.HardlinkTo != 0:
		return corrupt(m, "hardlink target on a member that is not a hardlink")
	case (m.Type == TypeCharDev || m.Type == TypeBlockDev) && len(m.RDev) != 2:
		return corrupt(m, fmt.Sprintf("device with %d rdev components, want 2", len(m.RDev)))
	case m.Type != TypeCharDev && m.Type != TypeBlockDev && len(m.RDev) != 0:
		return corrupt(m, "device number on a member that is not a device")
	case m.Type != TypeReg && len(m.Sparse) != 0:
		return corrupt(m, "sparse map on a member that is not a regular file")
	case m.Type != TypeReg && m.Data != 0:
		return corrupt(m, "shared content on a member that is not a regular file")
	}
	return nil
}

// validatePayload checks the blob and the chunk table against the member.
func validatePayload(m *Member) error {
	// A regular file must carry a digest. It is the only thing that detects
	// a member whose offset or chunk table points at the wrong bytes, and
	// without it a damaged index yields wrong content in silence.
	if m.Type == TypeReg && len(m.Digest) != DigestSize {
		return corrupt(m, "regular file with no digest")
	}

	if !m.Type.HasPayload() {
		if m.Length != 0 || len(m.Chunks) != 0 || m.Size != 0 {
			return corrupt(m, fmt.Sprintf("a %s claiming %d bytes of content", m.Type, m.Size))
		}
		return nil
	}

	if err := validateSparse(m); err != nil {
		return err
	}

	// A member that shares another's content has no blob, no chunks and no
	// codec of its own; validateData checks it against its owner.
	if m.Data != 0 {
		if m.Offset != 0 || m.Length != 0 || len(m.Chunks) != 0 || m.ChunkSize != 0 || m.Enc != nil || m.Codec != NoCodec {
			return corrupt(m, "shares the content of another member but has a blob of its own")
		}
		return nil
	}

	// The chunk table must account for the blob exactly. A mismatch means a
	// read would run off the end of the member, into the next one.
	var total uint64
	for _, c := range m.Chunks {
		total += uint64(c)
	}
	if total != m.Length {
		return corrupt(m, fmt.Sprintf("blob is %d bytes but its chunks total %d", m.Length, total))
	}
	if m.Offset+m.Length < m.Offset {
		return corrupt(m, fmt.Sprintf("blob [%d,+%d) overflows", m.Offset, m.Length))
	}

	// The chunk table has to agree with the payload, or a reader cannot tell
	// how much each chunk should decode to, and a crafted table becomes a
	// decompression bomb with no expected size to check against. For a
	// sparse file the payload is the data segments, not the logical size.
	payload := m.PayloadSize()
	if n := uint64(len(m.Chunks)); n > 0 {
		if m.ChunkSize == 0 {
			return corrupt(m, fmt.Sprintf("has %d chunks but no chunk size", n))
		}
		cs := uint64(m.ChunkSize)
		if payload > cs*n || (n > 1 && payload <= cs*(n-1)) {
			return corrupt(m, fmt.Sprintf("payload of %d bytes cannot fill %d chunks of %d", payload, n, cs))
		}
	} else if payload != 0 {
		return corrupt(m, fmt.Sprintf("payload of %d bytes but no chunks", payload))
	}
	return nil
}

// validateSparse checks a sparse map: segments in order, not overlapping, not
// empty, and inside the file. A reader writes each segment at its offset, so
// an overlapping or out-of-range map is a write the archive did not mean.
func validateSparse(m *Member) error {
	var end uint64
	for i, seg := range m.Sparse {
		if seg.Length == 0 {
			return corrupt(m, fmt.Sprintf("sparse segment %d is empty", i))
		}
		if seg.Offset+seg.Length < seg.Offset {
			return corrupt(m, fmt.Sprintf("sparse segment %d overflows", i))
		}
		if i > 0 && seg.Offset < end {
			return corrupt(m, fmt.Sprintf("sparse segment %d overlaps or is out of order", i))
		}
		end = seg.Offset + seg.Length
		if end > m.Size {
			return corrupt(m, fmt.Sprintf("sparse segment %d ends at %d, past the file size %d", i, end, m.Size))
		}
	}
	return nil
}

// String renders a catalog entry the way --compress takes it: NAME, or
// NAME:k=v,... with the keys in order, so that one codec always prints the
// same way.
func (c CodecSpec) String() string {
	keys := make([]string, 0, len(c.Params))
	for k := range c.Params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys)+1)
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, c.Params[k]))
	}
	// A codec with a dictionary shows "dict", the way a key given alone is
	// written (doc/design.md 10.2).
	if c.Dict != 0 {
		parts = append(parts, "dict")
	}
	if len(parts) == 0 {
		return c.Name
	}
	return c.Name + ":" + strings.Join(parts, ",")
}

// SameCodec reports whether two catalog entries describe the same codec with
// the same parameters.
//
// It compares canonical encodings, not Go values: a parameter decoded from an
// index is a uint64 while a freshly resolved one is an int, and a plain
// DeepEqual would call them different and grow the catalog on every append.
func SameCodec(a, b CodecSpec) bool {
	ea, err1 := encMode.Marshal(a)
	eb, err2 := encMode.Marshal(b)
	return err1 == nil && err2 == nil && string(ea) == string(eb)
}
