// Package archive reads, writes and changes eictar archives.
//
// It implements the layout of doc/design.md sections 2 to 6: a header, member
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
	"os"
	"path/filepath"
	"sort"
	"time"

	"lukechampine.com/blake3"

	"eictar/src/internal/codec"
	"eictar/src/internal/crypt"
	"eictar/src/internal/format"
	"eictar/src/internal/fsutil"
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
	// (doc/design.md 6.2).
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
	f    *os.File
	path string // the archive's final path
	// tmpPath is where a new archive is written until Close renames it to
	// path. It is empty for an append, which writes in place.
	tmpPath string
	// guard is the file a create replaces, held open to keep its lock until
	// the rename (doc/design.md 9.6). It is nil when nothing was there.
	guard *os.File

	hdr   format.Header
	index format.Index

	keys         *crypt.Keys
	encryptIndex bool

	enc       codec.Encoder
	codecName string
	codecRef  int
	chunkSize int

	off    int64 // where the next blob goes
	nextID uint64
	closed bool

	// Set when the writer extends an existing archive rather than creating
	// one (doc/design.md 9.1).
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
	enc, err := codec.NewEncoder(codecName, opt.Params, opt.Concurrency)
	if err != nil {
		return nil, err
	}

	target, mode, err := createTarget(path)
	if err != nil {
		enc.Close()
		return nil, err
	}
	guard, err := guardExisting(target)
	if err != nil {
		enc.Close()
		return nil, err
	}
	f, tmpPath, err := createTemp(target, mode)
	if err != nil {
		enc.Close()
		if guard != nil {
			guard.Close()
		}
		return nil, err
	}

	w := &Writer{
		f:         f,
		path:      target,
		tmpPath:   tmpPath,
		guard:     guard,
		enc:       enc,
		codecName: codecName,
		codecRef:  format.NoCodec,
		chunkSize: chunkSize,
		nextID:    1,
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
		w.codecRef = 0
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
// the old generation, in place (doc/design.md 9.1).
func OpenAppend(path string, opt Options, open OpenOptions) (*Writer, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	// Before the trailer is read: two appends that both read it would both
	// write after it, each over the blobs of the other (doc/design.md 9.6).
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
	enc, err := codec.NewEncoder(codecName, opt.Params, opt.Concurrency)
	if err != nil {
		r.Close()
		return nil, err
	}

	index := format.Index{
		Version:    format.IndexVersion,
		Generation: r.tr.Generation + 1,
		Codecs:     append([]format.CodecSpec(nil), r.index.Codecs...),
		Members:    append([]format.Member(nil), r.index.Members...),
	}
	var maxID uint64
	for _, m := range index.Members {
		maxID = max(maxID, m.ID)
	}

	w := &Writer{
		f:               f,
		path:            path,
		hdr:             r.hdr,
		index:           index,
		keys:            r.keys, // the reader's keys now belong to the writer
		encryptIndex:    r.tr.IndexEncrypted(),
		enc:             enc,
		codecName:       codecName,
		codecRef:        format.NoCodec,
		chunkSize:       chunkSize,
		off:             r.size,
		nextID:          maxID + 1,
		appending:       true,
		origSize:        r.size,
		prevIndexOffset: r.tr.IndexOffset,
	}

	// Reuse the catalog entry when this codec, with these parameters, is
	// already there; add one otherwise.
	if codecName != "none" {
		spec := format.CodecSpec{Name: codecName, Params: enc.Resolved()}
		w.codecRef = -1
		for i, c := range w.index.Codecs {
			if format.SameCodec(c, spec) {
				w.codecRef = i
				break
			}
		}
		if w.codecRef < 0 {
			w.index.Codecs = append(w.index.Codecs, spec)
			w.codecRef = len(w.index.Codecs) - 1
		}
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

	m.Offset = uint64(w.off)
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

// newDigest is the hash of a member's content: BLAKE3 keyed with the
// content key in an encrypted archive, plain BLAKE3 otherwise
// (doc/design.md 6.2).
func (w *Writer) newDigest() hash.Hash { return newDigest(w.keys) }

func newDigest(keys *crypt.Keys) hash.Hash {
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
// (doc/design.md 9).
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
			os.Remove(w.tmpPath)
		}
		return fmt.Errorf("closing %s: %w", w.path, err)
	}
	if w.tmpPath == "" {
		return nil
	}

	// The rename is the commit for a new archive: before it, any old file at
	// the path is intact, and after it the new one is complete.
	if err := os.Rename(w.tmpPath, w.path); err != nil {
		os.Remove(w.tmpPath)
		return fmt.Errorf("replacing %s: %w", w.path, err)
	}
	return syncDir(filepath.Dir(w.path))
}

// createTarget resolves where a new archive goes, and the mode it gets.
//
// A symbolic link is followed, so that the rename replaces the file and keeps
// the link. A file already there lends its permissions to the new one:
// replacing a 0600 archive with a 0644 one would be a silent change of who
// can read it. A new file gets 0666 less the umask, as os.Create does.
func createTarget(path string) (string, os.FileMode, error) {
	target := path
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		target = resolved
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", 0, fmt.Errorf("resolving %s: %w", path, err)
	}
	fi, err := os.Stat(target)
	switch {
	case err == nil && !fi.Mode().IsRegular():
		return "", 0, fmt.Errorf("%s exists and is not a regular file", path)
	case err == nil:
		return target, fi.Mode().Perm(), nil
	case errors.Is(err, os.ErrNotExist):
		return target, 0, nil
	default:
		return "", 0, fmt.Errorf("stat %s: %w", path, err)
	}
}

// guardExisting locks the archive that a create will replace, so that the
// create cannot rename over a file that another run is appending to. It
// returns nil when there is no file at target yet.
func guardExisting(target string) (*os.File, error) {
	f, err := os.Open(target)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", target, err)
	}
	if err := lockArchive(f, target); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// createTemp opens a new file beside target. mode 0 means the default for a
// new file.
func createTemp(target string, mode os.FileMode) (*os.File, string, error) {
	dir, base := filepath.Split(target)
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, "", fmt.Errorf("generating a temporary name: %w", err)
	}
	tmpPath := filepath.Join(dir, fmt.Sprintf(".%s.create-%x", base, b))

	// 0666 through open(2), not os.CreateTemp's 0600, so that the umask
	// decides the mode of a new archive exactly as it would for os.Create.
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o666)
	if err != nil {
		return nil, "", fmt.Errorf("creating %s: %w", target, err)
	}
	if mode != 0 {
		if err := f.Chmod(mode); err != nil {
			f.Close()
			os.Remove(tmpPath)
			return nil, "", fmt.Errorf("setting the mode of %s: %w", target, err)
		}
	}
	return f, tmpPath, nil
}

// SameFile reports whether fi is the file this writer is writing. The walk
// uses it so that an archive is never archived into itself.
func (w *Writer) SameFile(fi os.FileInfo) bool {
	mine, err := w.f.Stat()
	return err == nil && os.SameFile(fi, mine)
}

// indexEncodeOptions builds the encode settings for this archive's index:
// sealed when asked, and always authenticated when a key exists.
func (w *Writer) indexEncodeOptions() format.EncodeOptions {
	opt := format.EncodeOptions{Compress: true}

	gen := w.index.Generation
	uuid := w.hdr.ArchiveUUID

	// The digest binds the index to its archive and generation whether or not
	// there is a key. Without one it detects damage; with one it is keyed and
	// also detects metadata an attacker edited (doc/design.md 6.4).
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
	os.Remove(w.tmpPath)
}

// releaseGuard drops the lock on the file a create replaced.
func (w *Writer) releaseGuard() {
	if w.guard != nil {
		w.guard.Close()
		w.guard = nil
	}
}

// releaseID returns the most recent id when the entry it was taken for is not
// archived after all, so that skipping a socket leaves no gap in the ids.
func (w *Writer) releaseID(id uint64) {
	if id == w.nextID-1 {
		w.nextID--
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
