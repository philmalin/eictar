package archive

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/philmalin/eictar/src/internal/codec"
	"github.com/philmalin/eictar/src/internal/crypt"
	"github.com/philmalin/eictar/src/internal/format"
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

	// dicts holds each dictionary that a member needed, by id. Extraction
	// decodes members in parallel, so dictMu guards it.
	dictMu sync.Mutex
	dicts  map[uint32][]byte

	// byID finds the owner of shared content; extraction asks from several
	// goroutines, so it is built once.
	byIDOnce sync.Once
	byID     map[uint64]*format.Member

	// decoders holds the decoders that no member is using, by what they
	// decode. Making a zstd decoder costs more than decoding a small file,
	// and with a dictionary much more, so they are used again (doc/design.md
	// 8.3). Each WriteMember takes one and gives it back, so a list never
	// holds more decoders than there are callers at one time. A worker that
	// decodes many members uses a decoderSet of its own instead, with no
	// lock.
	decMu    sync.Mutex
	decoders map[decoderKey][]codec.Decoder
	decClose bool
}

// maxDecoderKinds bounds the kinds of decoder that the pool and a decoderSet
// keep. The codec, the chunk size and the dictionary come from the index, so a
// hostile archive can give each member a kind of its own. Each idle decoder
// holds its tables, and a dictionary when it has one. Without a bound, an
// index of a million members with a million chunk sizes keeps a million
// decoders. A real archive has one kind for each catalog entry and chunk size
// that it uses: a few. A decoder of a kind beyond the bound is closed after
// its member, as each decoder was before the pool.
const maxDecoderKinds = 16

// decoderKey is what makes two decoders the same: the codec, the chunk size
// that bounds each decode, and the dictionary.
type decoderKey struct {
	codec string
	chunk int
	dict  uint32
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
	f, err := openArchiveFile(path, os.O_RDONLY)
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

	for _, d := range r.index.Dicts {
		off, length := int64(d.Offset), int64(d.Length)
		if off < body || length < 0 || off+length < off || off+length > indexStart {
			return fmt.Errorf("%s: %w: dictionary %d blob [%d,+%d) lies outside the archive body [%d,%d)",
				r.path, format.ErrCorruptIndex, d.ID, d.Offset, d.Length, body, indexStart)
		}
		// A dictionary is one message: its plaintext, and the tag when it
		// is sealed.
		want := uint64(d.Size)
		if d.Enc != nil {
			want += crypt.Overhead
		}
		if d.Length != want {
			return fmt.Errorf("%s: %w: dictionary %d is %d bytes on disk, want %d",
				r.path, format.ErrCorruptIndex, d.ID, d.Length, want)
		}
	}

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

	// A wrong passphrase gives another key-encryption key, and the wrapped
	// data key fails its tag: that is the check (doc/design.md 6.2).
	keys, err := crypt.Unlock(passphrase, ch.Salt, r.hdr.ArchiveUUID, params, ch.Key)
	if err != nil {
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
	return r.writeMember(m, dst, nil)
}

// writeMember is WriteMember with the decoders of one goroutine. With a nil
// set, it takes a decoder from the shared pool of the Reader.
func (r *Reader) writeMember(m *format.Member, dst io.Writer, set *decoderSet) error {
	if !m.Type.HasPayload() {
		return nil
	}
	// A member that shares another's content reads the owner's blob, with
	// the owner's codec and keys: the chunk AAD binds the owner's id
	// (doc/design.md 4.3). The index checks that the owner has the same
	// payload and digest, and holds a blob of its own.
	if m.Data != 0 {
		o := r.Owner(m)
		if o == nil {
			return fmt.Errorf("%w: member %q shares the content of member %d, which does not exist",
				format.ErrCorruptIndex, m.Path, m.Data)
		}
		m = o
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

	key := decoderKey{codec: codecName, chunk: chunkSize}
	if m.Codec >= 0 && m.Codec < len(r.index.Codecs) {
		key.dict = r.index.Codecs[m.Codec].Dict
	}
	var dec codec.Decoder
	if set != nil {
		dec, err = set.take(key, m)
	} else {
		dec, err = r.takeDecoder(key, m)
	}
	if err != nil {
		return err
	}
	// A decoder that returned an error is closed, not used again: nothing
	// says what state the error left it in.
	decodeFailed := false
	defer func() {
		switch {
		case set != nil && !set.holds(key, dec):
			dec.Close()
		case decodeFailed && set != nil:
			set.drop(key)
		case decodeFailed:
			dec.Close()
		case set == nil:
			r.giveDecoder(key, dec)
		}
	}()

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

	hasher := newDigest(r.keys)
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
				decodeFailed = true
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

// Owner returns the member whose blob holds m's content: m itself, or the
// member that m shares its content with (doc/design.md 4.3). It returns nil
// for an owner that the index does not hold.
func (r *Reader) Owner(m *format.Member) *format.Member {
	if m.Data == 0 {
		return m
	}
	r.byIDOnce.Do(func() {
		r.byID = make(map[uint64]*format.Member, len(r.index.Members))
		for i := range r.index.Members {
			r.byID[r.index.Members[i].ID] = &r.index.Members[i]
		}
	})
	return r.byID[m.Data]
}

// Close releases the archive file and wipes the key material the reader held.
func (r *Reader) Close() error {
	r.decMu.Lock()
	for _, list := range r.decoders {
		for _, dec := range list {
			dec.Close()
		}
	}
	r.decoders = nil
	r.decClose = true
	r.decMu.Unlock()

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

// takeDecoder returns a decoder for m's chunks: a free one when there is one,
// or a new one. The caller gives it back with giveDecoder.
func (r *Reader) takeDecoder(key decoderKey, m *format.Member) (codec.Decoder, error) {
	r.decMu.Lock()
	if list := r.decoders[key]; len(list) > 0 {
		dec := list[len(list)-1]
		r.decoders[key] = list[:len(list)-1]
		r.decMu.Unlock()
		return dec, nil
	}
	r.decMu.Unlock()
	return r.newDecoder(key, m)
}

// newDecoder makes a decoder for key. m names the dictionary.
func (r *Reader) newDecoder(key decoderKey, m *format.Member) (codec.Decoder, error) {
	dict, err := r.dictFor(m)
	if err != nil {
		return nil, err
	}
	return codec.NewDecoderWithDict(key.codec, key.chunk, dict)
}

// giveDecoder returns a decoder that takeDecoder gave, for the next member.
func (r *Reader) giveDecoder(key decoderKey, dec codec.Decoder) {
	r.decMu.Lock()
	defer r.decMu.Unlock()
	if r.decClose {
		dec.Close()
		return
	}
	if r.decoders == nil {
		r.decoders = map[decoderKey][]codec.Decoder{}
	}
	if _, known := r.decoders[key]; !known && len(r.decoders) >= maxDecoderKinds {
		dec.Close()
		return
	}
	r.decoders[key] = append(r.decoders[key], dec)
}

// decoderSet holds the decoders of one goroutine, one for each key, with no
// lock. A worker that decodes many members keeps one, so that the workers do
// not wait for each other on the shared pool of the Reader.
type decoderSet struct {
	r   *Reader
	dec map[decoderKey]codec.Decoder
}

func (r *Reader) newDecoderSet() *decoderSet {
	return &decoderSet{r: r, dec: map[decoderKey]codec.Decoder{}}
}

// take returns the decoder for key, and makes it the first time. The set
// keeps the new decoder while it holds fewer than maxDecoderKinds kinds;
// otherwise the caller closes it after use (holds says which).
func (s *decoderSet) take(key decoderKey, m *format.Member) (codec.Decoder, error) {
	if dec, ok := s.dec[key]; ok {
		return dec, nil
	}
	dec, err := s.r.newDecoder(key, m)
	if err != nil {
		return nil, err
	}
	if len(s.dec) < maxDecoderKinds {
		s.dec[key] = dec
	}
	return dec, nil
}

// holds reports whether dec is the decoder that the set keeps for key.
func (s *decoderSet) holds(key decoderKey, dec codec.Decoder) bool {
	kept, ok := s.dec[key]
	return ok && kept == dec
}

// drop closes the decoder for key, after an error.
func (s *decoderSet) drop(key decoderKey) {
	if dec, ok := s.dec[key]; ok {
		dec.Close()
		delete(s.dec, key)
	}
}

// close closes every decoder of the set.
func (s *decoderSet) close() {
	for key := range s.dec {
		s.drop(key)
	}
}
