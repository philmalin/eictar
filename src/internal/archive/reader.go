package archive

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"

	"lukechampine.com/blake3"

	"eictar/src/internal/codec"
	"eictar/src/internal/crypt"
	"eictar/src/internal/format"
)

// Reader opens an archive for listing and extraction.
//
// Everything it needs to answer a question lives in the index, so listing
// touches only the tail of the file, and extracting one member reads only
// that member's bytes.
type Reader struct {
	f    *os.File
	path string
	size int64

	hdr   format.Header
	tr    format.Trailer
	index *format.Index

	crypto *format.CryptoHeader
	keys   *crypt.Keys
	// borrowedKeys means keys belong to the caller, who zeroes them.
	borrowedKeys bool
}

// PassphraseFunc supplies the passphrase for an encrypted archive. It is
// called only after the archive has been found to need one, so a plaintext
// archive never prompts.
type PassphraseFunc func() ([]byte, error)

// ErrNotEncrypted means an archive the caller expected to be encrypted is
// not. That is how a stripped or substituted archive shows itself: clearing
// the header flag and rewriting the plaintext index needs no passphrase, and
// yields an archive that opens without asking for one (doc/design.md 14.4).
var ErrNotEncrypted = errors.New("the archive is not encrypted")

// OpenOptions configures Open.
type OpenOptions struct {
	// Passphrase supplies the key for an encrypted archive. Nil means an
	// encrypted archive is reported as such rather than opened.
	Passphrase PassphraseFunc
	// RequireEncryption refuses an archive that is not encrypted.
	RequireEncryption bool

	// keys, when set, are used instead of a passphrase. They stay the
	// caller's: the reader does not zero them. Repair uses this to derive the
	// keys once for many candidate trailers.
	keys *crypt.Keys
}

// Open reads an archive's header, trailer and index.
//
// ask may be nil, in which case an encrypted archive is reported as such
// rather than opened.
func Open(path string, ask PassphraseFunc) (*Reader, error) {
	return OpenWith(path, OpenOptions{Passphrase: ask})
}

// OpenWith is Open with options.
func OpenWith(path string, opt OpenOptions) (*Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}

	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}

	r := &Reader{f: f, path: path, size: fi.Size()}
	if err := r.load(opt); err != nil {
		r.Close()
		return nil, err
	}
	return r, nil
}

// repairHint ends the message for a damaged trailer. That is what a crash
// during a mutation leaves, and the reader does not fall back to an older
// generation by itself (doc/design.md 9.5).
const repairHint = "; if a write to the archive was interrupted, --repair restores the last complete generation"

// Encrypted reports whether the archive's members are sealed.
func (r *Reader) Encrypted() bool { return r.hdr.Encrypted() }

func (r *Reader) load(opt OpenOptions) error {
	if r.size < format.HeaderSize+format.TrailerSize {
		return fmt.Errorf("%s: %w: %d bytes is too small to be an archive",
			r.path, format.ErrTruncated, r.size)
	}

	hdrBytes := make([]byte, format.HeaderSize)
	if _, err := r.f.ReadAt(hdrBytes, 0); err != nil {
		return fmt.Errorf("%s: reading header: %w", r.path, err)
	}
	if err := r.hdr.UnmarshalBinary(hdrBytes); err != nil {
		return fmt.Errorf("%s: %w", r.path, err)
	}

	trBytes := make([]byte, format.TrailerSize)
	if _, err := r.f.ReadAt(trBytes, r.size-format.TrailerSize); err != nil {
		return fmt.Errorf("%s: reading trailer: %w", r.path, err)
	}
	if err := r.tr.UnmarshalBinary(trBytes); err != nil {
		return fmt.Errorf("%s: %w%s", r.path, err, repairHint)
	}
	if err := r.tr.ValidateAgainst(&r.hdr, r.size); err != nil {
		return fmt.Errorf("%s: %w%s", r.path, err, repairHint)
	}

	if r.hdr.Encrypted() && opt.keys != nil {
		r.keys, r.borrowedKeys = opt.keys, true
	} else if r.hdr.Encrypted() {
		if err := r.unlock(opt.Passphrase); err != nil {
			return err
		}
	} else if opt.RequireEncryption {
		// Checked before anything else is read, so a stripped archive cannot
		// even show a listing to someone who expected a sealed one.
		return fmt.Errorf("%s: %w; if it should be, it has been replaced or stripped",
			r.path, ErrNotEncrypted)
	}

	// The trailer's length is already known to fit inside the file, but a
	// large sparse file can still claim an index of gigabytes. Refuse before
	// allocating rather than after.
	if r.tr.IndexLength > format.MaxIndexSize {
		return fmt.Errorf("%s: %w: trailer claims a %d-byte index",
			r.path, format.ErrIndexTooLarge, r.tr.IndexLength)
	}

	indexBytes := make([]byte, r.tr.IndexLength)
	if _, err := r.f.ReadAt(indexBytes, int64(r.tr.IndexOffset)); err != nil {
		return fmt.Errorf("%s: reading index: %w", r.path, err)
	}

	// The digest is checked before the index is decoded: damage should be
	// reported as damage, not as a confusing decode failure. With a key the
	// digest is keyed, so this also refuses metadata an attacker edited
	// without being able to read it (doc/design.md 6.4).
	var authKey []byte
	if r.keys != nil {
		authKey = r.keys.IndexAuthKey()
	}
	want := crypt.IndexDigest(authKey, r.hdr.ArchiveUUID, r.tr.Generation, indexBytes)
	if subtle.ConstantTimeCompare(want[:], r.tr.IndexDigest[:]) != 1 {
		if r.keys != nil {
			return fmt.Errorf("%s: %w: the index failed authentication; its metadata has been altered",
				r.path, format.ErrChecksum)
		}
		return fmt.Errorf("%s: %w: index digest does not match the trailer%s",
			r.path, format.ErrChecksum, repairHint)
	}

	var open format.Opener
	if r.tr.IndexEncrypted() {
		if r.keys == nil {
			return fmt.Errorf("%s: the index is encrypted but no passphrase was supplied", r.path)
		}
		gen := r.tr.Generation
		key := r.keys.IndexKey(gen)
		open = func(ciphertext []byte) ([]byte, error) {
			return crypt.OpenIndex(key, gen, ciphertext)
		}
	}

	index, err := format.DecodeIndex(indexBytes, r.tr.Flags, open)
	if err != nil {
		return fmt.Errorf("%s: %w", r.path, err)
	}
	r.index = index

	if got, want := index.LiveCount(), r.tr.LiveMembers; got != want {
		return fmt.Errorf("%s: %w: trailer counts %d live members, the index holds %d",
			r.path, format.ErrCorruptIndex, want, got)
	}
	return r.validateMemberRanges()
}

// validateMemberRanges checks every blob against the archive it claims to live
// in.
//
// format.Index.Validate cannot do this: it has no file in front of it, so it
// can only check a member against itself. Here the body and the index bounds
// are known, and a member that points outside them - into the header, into the
// index, or past the end of the file - is a corrupt index rather than a read
// that happens to fail later, or worse, one that happens to succeed and return
// the wrong bytes.
func (r *Reader) validateMemberRanges() error {
	body := r.hdr.BodyOffset()
	indexStart := int64(r.tr.IndexOffset)

	for i := range r.index.Members {
		m := &r.index.Members[i]
		if !m.Type.HasPayload() || m.Length == 0 {
			continue
		}

		off := int64(m.Offset)
		length := int64(m.Length)
		if off < 0 || length < 0 || off+length < off {
			return fmt.Errorf("%s: %w: member %q has an impossible blob range [%d,+%d)",
				r.path, format.ErrCorruptIndex, m.Path, m.Offset, m.Length)
		}
		if off < body || off+length > indexStart {
			return fmt.Errorf("%s: %w: member %q blob [%d,+%d) lies outside the archive body [%d,%d)",
				r.path, format.ErrCorruptIndex, m.Path, m.Offset, m.Length, body, indexStart)
		}
	}
	return nil
}

// unlock reads the crypto header and derives the archive's keys.
func (r *Reader) unlock(ask PassphraseFunc) error {
	if ask == nil {
		return fmt.Errorf("%s: this archive is encrypted and no passphrase was supplied", r.path)
	}

	cryptoBytes := make([]byte, r.hdr.CryptoHeaderLen)
	if _, err := r.f.ReadAt(cryptoBytes, format.HeaderSize); err != nil {
		return fmt.Errorf("%s: reading crypto header: %w", r.path, err)
	}

	ch, err := format.UnmarshalCryptoHeader(cryptoBytes)
	if err != nil {
		return fmt.Errorf("%s: %w", r.path, err)
	}
	r.crypto = ch

	params := crypt.KDFParams{Time: ch.Time, Memory: ch.Memory, Threads: ch.Threads}

	// The parameters are the archive's, not ours. Check this machine can
	// afford them before asking for a passphrase: after is too late to be
	// useful, and deriving without checking is an out-of-memory kill with
	// no explanation (doc/design.md A.3).
	if err := checkAffordable(params); err != nil {
		return fmt.Errorf("%s: %w", r.path, err)
	}

	passphrase, err := ask()
	if err != nil {
		return err
	}
	defer zero(passphrase)

	keys, err := crypt.Derive(passphrase, ch.Salt, r.hdr.ArchiveUUID, params)
	if err != nil {
		return fmt.Errorf("%s: %w", r.path, err)
	}
	if err := keys.VerifyCheck(ch.Check); err != nil {
		return fmt.Errorf("%s: %w", r.path, err)
	}
	r.keys = keys
	return nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Header returns the archive header.
func (r *Reader) Header() format.Header { return r.hdr }

// Trailer returns the archive trailer.
func (r *Reader) Trailer() format.Trailer { return r.tr }

// Members returns the live members, in index order.
func (r *Reader) Members() []format.Member { return r.index.Live() }

// AllMembers returns every member, tombstones included. A live hardlink can
// point to a tombstone, whose blob still holds the content (doc/design.md
// 9.2), so resolving one needs the whole list.
func (r *Reader) AllMembers() []format.Member { return r.index.Members }

// CodecName returns the codec a member was compressed with, or "none".
func (r *Reader) CodecName(m *format.Member) (string, error) {
	if m.Codec == format.NoCodec {
		return "none", nil
	}
	if m.Codec < 0 || m.Codec >= len(r.index.Codecs) {
		return "", fmt.Errorf("%w: member %q references codec %d of %d",
			format.ErrCorruptIndex, m.Path, m.Codec, len(r.index.Codecs))
	}
	return r.index.Codecs[m.Codec].Name, nil
}

// WriteMember decodes a member's content to dst, verifying its digest.
//
// The digest check covers the whole member, so a truncated or altered blob is
// caught even when every individual chunk decodes cleanly.
func (r *Reader) WriteMember(m *format.Member, dst io.Writer) error {
	if !m.Type.HasPayload() {
		return nil
	}

	codecName, err := r.CodecName(m)
	if err != nil {
		return err
	}

	// The chunk table describes the payload: the whole file when it is dense,
	// only its data segments when it has holes (doc/design.md 5.2).
	payload := m.PayloadSize()

	chunkSize := int(m.ChunkSize)
	if chunkSize <= 0 {
		if payload != 0 {
			return fmt.Errorf("%w: member %q has content but no chunk size",
				format.ErrCorruptIndex, m.Path)
		}
		chunkSize = DefaultChunkSize
	}

	dec, err := codec.NewDecoder(codecName, chunkSize)
	if err != nil {
		return err
	}
	defer dec.Close()

	var sealer *crypt.MemberSealer
	if m.Enc != nil {
		if r.keys == nil {
			return fmt.Errorf("%s: member %q is encrypted and no passphrase was supplied",
				r.path, m.Path)
		}
		memberKey, err := r.keys.MemberKey(m.Enc.Salt)
		if err != nil {
			return fmt.Errorf("%s: member %q: %w", r.path, m.Path, err)
		}
		if sealer, err = crypt.NewMemberSealer(memberKey, m.ID); err != nil {
			return fmt.Errorf("%s: member %q: %w", r.path, m.Path, err)
		}
	} else if r.keys != nil && r.hdr.Encrypted() {
		// An encrypted archive whose member claims to be in the clear: the
		// index says one thing and the header another.
		return fmt.Errorf("%s: %w: member %q is unsealed in an encrypted archive",
			r.path, format.ErrCorruptIndex, m.Path)
	}

	hasher := blake3.New(format.DigestSize, nil)
	out := io.MultiWriter(dst, hasher)

	var opened []byte

	var (
		off       = int64(m.Offset)
		remaining = payload
		raw       []byte // the chunk as it sits on disk
		plain     []byte // the decode destination; must never alias raw
	)
	for i, onDisk := range m.Chunks {
		plainSize := uint64(chunkSize)
		if remaining < plainSize {
			plainSize = remaining
		}
		if plainSize == 0 {
			return fmt.Errorf("%w: member %q has %d chunks but only %d bytes of content",
				format.ErrCorruptIndex, m.Path, len(m.Chunks), payload)
		}

		if cap(raw) < int(onDisk) {
			raw = make([]byte, onDisk)
		}
		raw = raw[:onDisk]
		if _, err := r.f.ReadAt(raw, off); err != nil {
			return fmt.Errorf("%s: reading chunk %d of %q: %w", r.path, i, m.Path, err)
		}

		// Unseal first: everything below works on the compressed form, and
		// the tag covers exactly what was written.
		encoded := raw
		if sealer != nil {
			final := i == len(m.Chunks)-1
			opened, err = sealer.Open(opened[:0], raw, uint64(i), final)
			if err != nil {
				return fmt.Errorf("%s: member %q: %w", r.path, m.Path, err)
			}
			encoded = opened
		}

		// A chunk that compression would have grown is stored as plaintext.
		// Compressed chunks are always strictly shorter than their plaintext,
		// so equality here is unambiguous (doc/design.md 4.1). Under
		// encryption the comparison is against the encoded form, which is why
		// it is made after unsealing rather than against the on-disk length.
		content := encoded
		if uint64(len(encoded)) != plainSize {
			plain, err = dec.Decode(plain[:0], encoded, int(plainSize))
			if err != nil {
				// The codec's own error says what it found; the sentinel says
				// that this is damage, not I/O (exit 3, doc/design.md 10.7).
				return fmt.Errorf("%w: chunk %d of %q: %v", format.ErrCorruptData, i, m.Path, err)
			}
			content = plain
		}

		if _, err := out.Write(content); err != nil {
			return fmt.Errorf("writing %q: %w", m.Path, err)
		}

		off += int64(onDisk)
		remaining -= plainSize
	}

	if remaining != 0 {
		return fmt.Errorf("%w: member %q carries %d bytes but its chunks cover %d",
			format.ErrCorruptIndex, m.Path, payload, payload-remaining)
	}
	if len(m.Digest) == format.DigestSize {
		if got := hasher.Sum(nil); subtle.ConstantTimeCompare(got, m.Digest) != 1 {
			return fmt.Errorf("%w: member %q failed its digest check",
				format.ErrChecksum, m.Path)
		}
	}
	return nil
}

// Close releases the archive file and wipes the key material the reader held.
func (r *Reader) Close() error {
	if r.keys != nil && !r.borrowedKeys {
		r.keys.Zero()
	}
	r.keys = nil
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}
