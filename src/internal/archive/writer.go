// Package archive reads, writes and changes eictar archives.
//
// It implements the layout of doc/design.eml sections 2 to 6: a header, member
// blobs, an index, and a trailer that commits them. Create, list and extract
// are in ops.go and extract.go; the walk and the metadata capture feed the
// compression pipeline of package pipeline. The mutations of section 9 -
// append, update, delete, compact, verify, info and repair - are in
// mutate.go.
package archive

import (
	"crypto/rand"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"lukechampine.com/blake3"

	"github.com/philmalin/eictar/src/internal/codec"
	"github.com/philmalin/eictar/src/internal/crypt"
	"github.com/philmalin/eictar/src/internal/format"
	"github.com/philmalin/eictar/src/internal/fsutil"
)

// Defaults for the writer and the pipeline.
const (
	// DefaultChunkSize is the plaintext chunk size when none is given.
	DefaultChunkSize = 4 << 20
	// DefaultSpillThreshold is where a member's encoded payload moves from
	// memory to a temporary file.
	DefaultSpillThreshold = 32 << 20
)

// Options configures a writer.
type Options struct {
	// Codec names the compression algorithm; empty means "none".
	Codec string
	// Params are the codec's k=v settings.
	Params codec.Params
	// ChunkSize is the plaintext bytes per chunk. Zero means
	// DefaultChunkSize.
	ChunkSize int
	// Concurrency is how many goroutines will share the encoder. Zero means
	// one. It sizes the codec's per-caller state, not a thread pool.
	Concurrency int

	// Keys, when non-nil, encrypts the archive: every member's chunks are
	// sealed, and the index is authenticated whether or not it is also
	// encrypted.
	Keys *crypt.Keys
	// KDFParams are recorded in the crypto header so the archive can be
	// opened later with the parameters it was made with.
	KDFParams crypt.KDFParams
	// Salt is the Argon2id salt of the key that wraps the data key.
	Salt []byte
	// WrappedKey is the data key, wrapped for the passphrase
	// (doc/design.eml 6.2).
	WrappedKey []byte
	// EncryptIndex adds confidentiality to the index. Authentication does not
	// depend on it.
	EncryptIndex bool
	// ArchiveUUID is the archive's identity. The zero value means "generate
	// one"; an encrypted archive must supply the id its keys were derived
	// against.
	ArchiveUUID [16]byte
}

// Writer builds an archive. Members are added one at a time and the index is
// written by Close, which is the point at which the archive becomes readable.
type Writer struct {
	f    archiveFile
	path string // the archive's final path
	// self is the identity of f, from one stat when the file opens. The walk
	// compares each file with it: a stat for each file could fail, and then
	// the archive could go into itself.
	self os.FileInfo
	// tmpPath is where a new archive is written until Close renames it to
	// path. It is empty for an append, which writes in place.
	tmpPath string
	// guard is the file a create replaces, held open to keep its lock until
	// the rename (doc/design.eml 9.6). It is nil when nothing was there.
	guard archiveFile

	hdr   format.Header
	index format.Index

	keys         *crypt.Keys
	encryptIndex bool

	enc       codec.Encoder
	codecName string
	codecRef  int
	chunkSize int
	// params and concurrency build the encoder again with a dictionary
	// (doc/design.eml 4.2). addedCodec means this writer added the catalog
	// entry at codecRef, so that it can take it away when it is not used.
	params      codec.Params
	concurrency int
	addedCodec  bool
	// dedup finds content that the archive holds already (doc/design.eml
	// 4.3). It is nil under --no-dedup, and for a compact.
	dedup *dedup

	off    int64 // where the next blob goes
	nextID uint64
	closed bool

	// Set when the writer extends an existing archive rather than creating
	// one (doc/design.eml 9.1).
	appending       bool
	origSize        int64  // the archive's length before this generation
	prevIndexOffset uint64 // the index this generation supersedes
}

// Create makes a new archive at path.
//
// The archive is written to a temporary file beside path, and Close renames
// it into place. Until then, a file already at path is untouched: a create
// that fails - a mistyped source path, a full disk, a crash - leaves the old
// archive as it was, rather than truncated or removed. If path is a symbolic
// link, the file it points to is replaced, and the link stays.
func Create(path string, opt Options) (*Writer, error) {
	chunkSize := opt.ChunkSize
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}

	codecName := opt.Codec
	if codecName == "" {
		codecName = "none"
	}
	enc, err := codec.NewEncoderWith(codecName, opt.Params,
		codec.EncoderOptions{Concurrency: opt.Concurrency, MaxChunk: chunkSize})
	if err != nil {
		return nil, err
	}

	target, guard, mode, err := createTarget(path)
	if err != nil {
		enc.Close()
		return nil, err
	}
	f, self, tmpPath, err := createTemp(target, mode)
	if err != nil {
		enc.Close()
		if guard != nil {
			guard.Close()
		}
		return nil, err
	}

	w := &Writer{
		f:           f,
		self:        self,
		path:        target,
		tmpPath:     tmpPath,
		guard:       guard,
		enc:         enc,
		codecName:   codecName,
		codecRef:    format.NoCodec,
		chunkSize:   chunkSize,
		params:      opt.Params,
		concurrency: max(1, opt.Concurrency),
		nextID:      1,
		dedup:       newDedup(nil, 1),
	}

	// Keys are derived against the archive id, so keys without the id they
	// were derived for would produce an archive nobody can ever open.
	if opt.Keys != nil && opt.ArchiveUUID == ([16]byte{}) {
		w.abort()
		return nil, errors.New("archive: encryption keys supplied without the archive id they were derived for")
	}
	if opt.Keys != nil && len(opt.Salt) != crypt.SaltSize {
		w.abort()
		return nil, fmt.Errorf("archive: encryption keys supplied with a %d-byte salt", len(opt.Salt))
	}
	if opt.Keys != nil && len(opt.WrappedKey) != crypt.WrappedKeySize {
		w.abort()
		return nil, fmt.Errorf("archive: encryption keys supplied with a %d-byte wrapped key", len(opt.WrappedKey))
	}

	w.keys = opt.Keys
	w.encryptIndex = opt.EncryptIndex

	w.hdr = format.Header{
		VersionMajor:     format.VersionMajor,
		VersionMinor:     format.VersionMinor,
		CreatedUnixNanos: time.Now().UnixNano(),
	}
	if opt.ArchiveUUID != ([16]byte{}) {
		w.hdr.ArchiveUUID = opt.ArchiveUUID
	} else if _, err := rand.Read(w.hdr.ArchiveUUID[:]); err != nil {
		w.abort()
		return nil, fmt.Errorf("generating archive id: %w", err)
	}

	// The crypto header is built first: the file header records its length,
	// and both are written before any member.
	var cryptoBytes []byte
	if opt.Keys != nil {
		ch := &format.CryptoHeader{
			Version: format.CryptoHeaderVersion,
			KDF:     format.KDFArgon2id,
			Salt:    opt.Salt,
			Time:    opt.KDFParams.Time,
			Memory:  opt.KDFParams.Memory,
			Threads: opt.KDFParams.Threads,
			AEAD:    format.AEADXChaCha20,
			Key:     opt.WrappedKey,
		}
		if cryptoBytes, err = ch.Marshal(); err != nil {
			w.abort()
			return nil, err
		}
		w.hdr.Flags |= format.FlagEncrypted
		w.hdr.CryptoHeaderLen = uint32(len(cryptoBytes))
	}

	hdrBytes, err := w.hdr.MarshalBinary()
	if err != nil {
		w.abort()
		return nil, err
	}
	if _, err := f.Write(hdrBytes); err != nil {
		w.abort()
		return nil, fmt.Errorf("writing header: %w", err)
	}
	if len(cryptoBytes) > 0 {
		if _, err := f.Write(cryptoBytes); err != nil {
			w.abort()
			return nil, fmt.Errorf("writing crypto header: %w", err)
		}
	}

	w.off = int64(len(hdrBytes)) + int64(len(cryptoBytes))
	w.index = format.Index{Version: format.IndexVersion, Generation: 1}

	// The codec catalog entry is created on first use, so an archive of
	// nothing but directories does not claim a compressor it never ran.
	if codecName != "none" {
		w.codecRef, w.addedCodec = 0, true
		w.index.Codecs = []format.CodecSpec{{Name: codecName, Params: enc.Resolved()}}
	}
	return w, nil
}

// OpenAppend opens an existing archive to add a generation to it.
//
// The archive is loaded and checked exactly as a reader would - trailer,
// index digest, member ranges, and the passphrase for an encrypted one - and
// the new generation's blobs start after the old trailer, at the old end of
// the file. Until Close writes the new trailer, the old one still describes
// the old generation, in place (doc/design.eml 9.1).
func OpenAppend(path string, opt Options, open OpenOptions) (*Writer, error) {
	f, err := fsys.OpenArchive(path, os.O_RDWR)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	// Before the trailer is read: two appends that both read it would both
	// write after it, each over the blobs of the other (doc/design.eml 9.6).
	if err := lockArchive(f, path); err != nil {
		f.Close()
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}

	r := &Reader{f: f, path: path, size: fi.Size()}
	if err := r.load(open); err != nil {
		r.Close()
		return nil, err
	}

	// Every write goes through the file position, and O_RDWR starts it at
	// zero - on top of the header. The new generation starts at the old end.
	if _, err := f.Seek(r.size, io.SeekStart); err != nil {
		r.Close()
		return nil, fmt.Errorf("seeking in %s: %w", path, err)
	}

	chunkSize := opt.ChunkSize
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	codecName := opt.Codec
	if codecName == "" {
		codecName = "none"
	}
	enc, err := codec.NewEncoderWith(codecName, opt.Params,
		codec.EncoderOptions{Concurrency: opt.Concurrency, MaxChunk: chunkSize})
	if err != nil {
		r.Close()
		return nil, err
	}

	index := format.Index{
		Version:    format.IndexVersion,
		Generation: r.tr.Generation + 1,
		Codecs:     append([]format.CodecSpec(nil), r.index.Codecs...),
		Dicts:      append([]format.Dict(nil), r.index.Dicts...),
		Members:    append([]format.Member(nil), r.index.Members...),
	}
	var maxID uint64
	for _, m := range index.Members {
		maxID = max(maxID, m.ID)
	}

	w := &Writer{
		f:               f,
		self:            fi,
		path:            path,
		hdr:             r.hdr,
		index:           index,
		keys:            r.keys, // the reader's keys now belong to the writer
		encryptIndex:    r.tr.IndexEncrypted(),
		enc:             enc,
		codecName:       codecName,
		codecRef:        format.NoCodec,
		chunkSize:       chunkSize,
		params:          opt.Params,
		concurrency:     max(1, opt.Concurrency),
		off:             r.size,
		nextID:          maxID + 1,
		appending:       true,
		origSize:        r.size,
		prevIndexOffset: r.tr.IndexOffset,
		// The reader stays, to check an old owner before a member first
		// shares its content. Its keys are the writer's now.
		dedup: newDedup(r, maxID+1),
	}
	r.borrowedKeys = true

	// Reuse the catalog entry when this codec, with these parameters, is
	// already there; add one otherwise.
	if codecName != "none" {
		w.codecRef, w.addedCodec = w.catalogRef(format.CodecSpec{Name: codecName, Params: enc.Resolved()})
	}
	return w, nil
}

// Members returns the index as it stands, tombstones included. It is for the
// mutation layer, on the goroutine that owns the writer.
func (w *Writer) Members() []format.Member { return w.index.Members }

// Tombstone marks members dead in the new generation. It must be called when
// no emitter is running, since it changes the index in place.
func (w *Writer) Tombstone(ids map[uint64]bool) {
	for i := range w.index.Members {
		if ids[w.index.Members[i].ID] {
			w.index.Members[i].Dead = true
		}
	}
}

// AppendMember writes a member's payload at the current offset and records
// it in the index.
//
// It is called from the pipeline's single emitting goroutine, which is what
// makes the unsynchronised offset arithmetic here safe: one goroutine owns the
// file position for the whole run.
func (w *Writer) AppendMember(m *format.Member, payload io.WriterTo) error {
	if err := w.checkPath(m.Path); err != nil {
		return err
	}

	// Content that the archive holds already is shared, not written again
	// (doc/design.eml 4.3). This catches two copies that one run adds; the
	// capturer finds the others before they are compressed.
	if payload != nil && w.dedup != nil && m.Type == format.TypeReg && m.Data == 0 && m.Length > 0 {
		if owner, ok := w.dedup.atEmit(m); ok {
			share(m, owner)
			payload = nil
		}
	}

	// Only a blob has an offset and an enc (doc/format.md 8.3). Earlier
	// writers also put the write position on members with no blob, and a
	// salt on an empty file.
	m.Offset = 0
	if m.Data == 0 && m.Length > 0 {
		m.Offset = uint64(w.off)
	} else {
		m.Enc = nil
	}
	if payload != nil {
		n, err := payload.WriteTo(w.f)
		if err != nil {
			return fmt.Errorf("writing %q to %s: %w", m.Path, w.path, err)
		}
		if uint64(n) != m.Length {
			return fmt.Errorf("%q: wrote %d bytes, expected %d", m.Path, n, m.Length)
		}
		w.off += n
	}

	w.index.Members = append(w.index.Members, *m)
	return nil
}

// newSealer gives one member its own key and sealer, recording the salt that
// key was derived from in the member itself.
//
// It is called from the scheduling goroutine, one member at a time, before any
// of that member's chunks reach a worker.
func (w *Writer) newSealer(m *format.Member) (*crypt.MemberSealer, error) {
	if w.keys == nil {
		return nil, nil
	}

	salt := make([]byte, crypt.SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generating a member salt: %w", err)
	}
	key, err := w.keys.MemberKey(salt)
	if err != nil {
		return nil, err
	}

	m.Enc = &format.EncInfo{Salt: salt}
	return crypt.NewMemberSealer(key, m.ID)
}

// Encoder is the compressor the archive was opened with, shared by the
// pipeline's workers. Codec encoders are safe for concurrent use.
func (w *Writer) Encoder() codec.Encoder { return w.enc }

// CodecRef is the catalog index members should record, or format.NoCodec.
func (w *Writer) CodecRef() int { return w.codecRef }

func (w *Writer) newDigest() hash.Hash { return newDigest(w.keys) }

// newDigest is the hash of a member's content: BLAKE3 keyed with the
// content key in an encrypted archive, plain BLAKE3 otherwise
// (doc/design.eml 6.2).
//
// It is a variable so that a test can give it a fault that create, --verify
// and --diff all share, and that only --diff-extract finds (doc/design.eml
// 9.10).
var newDigest = func(keys *crypt.Keys) hash.Hash {
	var key []byte
	if keys != nil {
		key = keys.ContentKey()
	}
	return blake3.New(format.DigestSize, key)
}

// NextID hands out member ids in walk order, so that the ids in an archive do
// not depend on which worker happened to finish first.
func (w *Writer) NextID() uint64 { return w.takeID() }

// Generation is the index generation being written.
func (w *Writer) Generation() uint64 { return w.index.Generation }

// Close writes the index and the trailer, then syncs. Until it returns, the
// file on disk is not a readable archive: the trailer is the commit point
// (doc/design.eml 9).
func (w *Writer) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	defer w.enc.Close()
	defer w.releaseGuard() // after the rename, which the deferred calls follow

	// If the index or the trailer does not land, the file is not a readable
	// archive. discard removes a new file, and cuts an appended one back to
	// the generation it had.
	if err := w.writeIndexAndTrailer(); err != nil {
		w.discard()
		return err
	}
	if err := w.f.Sync(); err != nil {
		w.discard()
		return fmt.Errorf("syncing %s: %w", w.path, err)
	}
	if err := w.f.Close(); err != nil {
		w.f = nil
		if w.tmpPath != "" {
			fsys.Remove(w.tmpPath)
		}
		return fmt.Errorf("closing %s: %w", w.path, err)
	}
	if w.tmpPath == "" {
		return nil
	}

	// The rename is the commit for a new archive: before it, any old file at
	// the path is intact, and after it the new one is complete. A create that
	// found no file at the path holds no lock. It must not replace an archive
	// that another run made there since, and that a third run can be
	// appending to (doc/design.eml 9.6).
	replace := w.guard != nil
	if err := fsys.Rename(w.tmpPath, w.path, replace); err != nil {
		fsys.Remove(w.tmpPath)
		if !replace && errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%s: %w (another run created it while this one wrote it)", w.path, ErrLocked)
		}
		return fmt.Errorf("replacing %s: %w", w.path, err)
	}
	return fsys.SyncDir(filepath.Dir(w.path))
}

// SameFile reports whether fi is the file this writer is writing. The walk
// uses it so that an archive is never archived into itself.
func (w *Writer) SameFile(fi os.FileInfo) bool {
	return w.self != nil && os.SameFile(fi, w.self)
}

// indexEncodeOptions builds the encode settings for this archive's index:
// sealed when asked, and always authenticated when a key exists.
func (w *Writer) indexEncodeOptions() format.EncodeOptions {
	opt := format.EncodeOptions{Compress: true}

	gen := w.index.Generation
	uuid := w.hdr.ArchiveUUID

	// The digest binds the index to its archive and generation whether or not
	// there is a key. Without one it detects damage; with one it is keyed and
	// also detects metadata an attacker edited (doc/design.eml 6.4).
	var authKey []byte
	if w.keys != nil {
		authKey = w.keys.IndexAuthKey()
	}
	opt.Digest = func(b []byte) [format.DigestSize]byte {
		return crypt.IndexDigest(authKey, uuid, gen, b)
	}

	if w.keys != nil && w.encryptIndex {
		key := w.keys.IndexKey(gen)
		opt.Seal = func(plaintext []byte) ([]byte, error) {
			return crypt.SealIndex(key, gen, plaintext)
		}
	}
	return opt
}

func (w *Writer) writeIndexAndTrailer() error {
	// Members arrive in whatever order the workers finished. Sorting by id
	// restores walk order, so that two runs over the same tree produce the
	// same index whatever the worker count did.
	sort.Slice(w.index.Members, func(i, j int) bool {
		return w.index.Members[i].ID < w.index.Members[j].ID
	})

	enc, err := w.index.Encode(w.indexEncodeOptions())
	if err != nil {
		return err
	}

	indexOffset := w.off
	if _, err := w.f.Write(enc.Bytes); err != nil {
		return fmt.Errorf("writing index: %w", err)
	}
	w.off += int64(len(enc.Bytes))

	// The data and the index must be durable before the trailer that points
	// at them, or a crash can leave a trailer describing bytes that never
	// reached the disk.
	if err := w.f.Sync(); err != nil {
		return fmt.Errorf("syncing %s: %w", w.path, err)
	}

	tr := format.Trailer{
		VersionMajor:    format.VersionMajor,
		VersionMinor:    format.VersionMinor,
		Flags:           enc.Flags,
		Generation:      w.index.Generation,
		IndexOffset:     uint64(indexOffset),
		IndexLength:     uint64(len(enc.Bytes)),
		PrevIndexOffset: w.prevIndexOffset,
		LiveMembers:     w.index.LiveCount(),
		IndexDigest:     enc.Digest,
	}
	trBytes, err := tr.MarshalBinary()
	if err != nil {
		return err
	}
	if _, err := w.f.Write(trBytes); err != nil {
		return fmt.Errorf("writing trailer: %w", err)
	}
	w.off += int64(len(trBytes))
	return nil
}

// Abort gives up the write. A new archive's temporary file is removed, and a
// file that was already at the path is left as it was. An appended archive is
// cut back to the generation it had.
func (w *Writer) Abort() error {
	if w.closed {
		return nil
	}
	w.closed = true
	w.abort()
	return nil
}

func (w *Writer) abort() {
	if w.enc != nil {
		w.enc.Close()
	}
	w.discard()
}

// discard undoes what this writer put on disk.
func (w *Writer) discard() {
	defer w.releaseGuard()
	if w.f == nil {
		return
	}
	if w.appending {
		// A failed append leaves the archive exactly as it was: cut off
		// whatever this generation wrote after the old trailer. Removing the
		// file, as a failed create does, would destroy every earlier
		// generation. A run that wrote nothing leaves the file alone, its
		// times included.
		if fi, err := w.f.Stat(); err != nil || fi.Size() != w.origSize {
			w.f.Truncate(w.origSize)
			w.f.Sync()
		}
		w.f.Close()
		return
	}
	w.f.Close()
	w.f = nil
	// Only the temporary file: whatever was at the path before stays.
	fsys.Remove(w.tmpPath)
}

// releaseGuard drops the lock on the file a create replaced.
func (w *Writer) releaseGuard() {
	if w.guard != nil {
		w.guard.Close()
		w.guard = nil
	}
}

func (w *Writer) takeID() uint64 {
	id := w.nextID
	w.nextID++
	return id
}

// checkPath refuses anything not in canonical stored form. The caller
// normalises with fsutil.StorePath; this catches the case where it forgot.
func (w *Writer) checkPath(stored string) error {
	if !fsutil.IsStoredPath(stored) {
		return fmt.Errorf("%w: %q is not in canonical stored form", fsutil.ErrUnsafePath, stored)
	}
	return nil
}
