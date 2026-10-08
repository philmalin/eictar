package archive

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/philmalin/eictar/src/internal/codec"
	"github.com/philmalin/eictar/src/internal/crypt"
	"github.com/philmalin/eictar/src/internal/format"
	"github.com/philmalin/eictar/src/internal/fsutil"
	"github.com/philmalin/eictar/src/internal/meta"
	"github.com/philmalin/eictar/src/internal/pipeline"
)

// ErrNoMatch means a pattern matched no live member. The whole operation is
// refused: a typing mistake in one pattern must not go unnoticed while the
// others take effect.
var ErrNoMatch = errors.New("matches nothing in the archive")

// Update modes for -u (doc/design.md 10.5).
const (
	UpdateNewer     = "newer"
	UpdateDifferent = "different"
	UpdateDigest    = "digest"
)

// AppendConfig drives -r and -u. The embedded CreateConfig says what to walk
// and how to compress it; its Encryption must be nil, because the header of
// the existing archive fixes the encryption.
type AppendConfig struct {
	CreateConfig

	// Open supplies the passphrase for an encrypted archive.
	Open OpenOptions
	// OnConflict is the -r policy for a path that is already live: replace
	// (the default), skip or error.
	OnConflict string
	// UpdateMode, when set, makes this -u: a live path is replaced only when
	// the test of that mode finds it out of date. OnConflict is then unused.
	UpdateMode string
}

// AppendArchive adds the paths of cfg to an existing archive as a new
// generation (doc/design.md 9.1 and 9.2).
//
// On an error the file is cut back to its old length, so the archive is
// exactly as it was. A run that changes nothing - every path skipped or
// unchanged - also leaves the file untouched, rather than add a generation
// that says nothing new.
func AppendArchive(cfg AppendConfig) (Stats, error) {
	if cfg.Encryption != nil {
		return Stats{}, errors.New("internal: append takes its encryption from the archive")
	}
	if err := cfg.checkPolicies(); err != nil {
		return Stats{}, err
	}

	workers := cfg.Workers
	if workers < 1 {
		workers = runtime.GOMAXPROCS(0)
	}
	opts := cfg.Options
	opts.Concurrency = encoderSlots(opts, workers, cfg.MemoryLimit)

	w, err := OpenAppend(cfg.Archive, opts, cfg.Open)
	if err != nil {
		return Stats{}, err
	}
	if cfg.NoDedup {
		w.dedup = nil
	}
	if err := w.useDictionary(func(budget int) ([][]byte, int, error) { return sampleTree(w, cfg.CreateConfig, budget) }, warnOf(cfg.Reporter)); err != nil {
		w.Abort()
		return Stats{}, err
	}

	// A copy, not pointers into w's slice: the emitter appends to that slice
	// while the walk reads this map.
	live := map[string]*format.Member{}
	byID := map[uint64]*format.Member{}
	for _, m := range w.Members() {
		m := m
		byID[m.ID] = &m
		if !m.Dead {
			live[m.Path] = &m
		}
	}

	stats, capture, err := addPaths(w, cfg.CreateConfig, workers, func(c *capturer) {
		c.live = live
		c.byID = byID
		c.onConflict = cfg.OnConflict
		c.updateMode = cfg.UpdateMode
	})
	if err != nil {
		w.Abort()
		return stats, err
	}
	if stats.Members == 0 && len(capture.tombstones) == 0 {
		w.Abort()
		return stats, nil
	}

	// The emitter has stopped, so the index is ours alone again.
	w.Tombstone(capture.tombstones)
	stats.Replaced = len(capture.tombstones)
	return stats, w.Close()
}

// checkPolicies checks --on-conflict and --update-mode, and fills in the
// default conflict policy.
func (cfg *AppendConfig) checkPolicies() error {
	switch cfg.OnConflict {
	case "":
		cfg.OnConflict = ConflictReplace
	case ConflictReplace, ConflictSkip, ConflictError:
	default:
		return fmt.Errorf("unknown conflict policy %q", cfg.OnConflict)
	}
	switch cfg.UpdateMode {
	case "", UpdateNewer, UpdateDifferent, UpdateDigest:
	default:
		return fmt.Errorf("unknown update mode %q", cfg.UpdateMode)
	}
	return nil
}

// DeleteConfig drives --delete.
type DeleteConfig struct {
	Archive  string
	Patterns []string
	Regex    fsutil.Regexps // -R
	Open     OpenOptions
	Reporter Reporter
}

// DeleteMembers tombstones the live members that match the patterns, in a
// new generation. The blobs stay until --compact.
func DeleteMembers(cfg DeleteConfig) (Stats, error) {
	var stats Stats
	if len(cfg.Patterns) == 0 && len(cfg.Regex) == 0 {
		return stats, errors.New("--delete needs at least one pattern or -R")
	}

	w, err := OpenAppend(cfg.Archive, Options{}, cfg.Open)
	if err != nil {
		return stats, err
	}

	var live []format.Member
	for _, m := range w.Members() {
		if !m.Dead {
			live = append(live, m)
		}
	}
	deleted, err := selectMembers(live, cfg.Patterns, cfg.Regex)
	if err != nil {
		w.Abort()
		return stats, err
	}
	ids := make(map[uint64]bool, len(deleted))
	for _, m := range deleted {
		ids[m.ID] = true
	}

	w.Tombstone(ids)
	if err := w.Close(); err != nil {
		return stats, err
	}
	stats.Members = len(deleted)
	if cfg.Reporter != nil {
		for i := range deleted {
			cfg.Reporter.Member(&deleted[i])
		}
	}
	return stats, nil
}

// kept returns the members that a compacted archive holds: every live member,
// and every tombstone that a live hardlink points to (doc/design.md 9.2).
func kept(all []format.Member) []format.Member {
	needed := map[uint64]bool{}
	for _, m := range all {
		if !m.Dead && m.Type == format.TypeHardlink {
			needed[m.HardlinkTo] = true
		}
	}
	// A tombstone that a kept member shares content with holds the blob, as
	// the target of a hardlink does (doc/design.md 4.3). A kept hardlink can
	// point to a tombstone that shares content, so the owners come after.
	for _, m := range all {
		if (!m.Dead || needed[m.ID]) && m.Data != 0 {
			needed[m.Data] = true
		}
	}
	var out []format.Member
	for _, m := range all {
		if !m.Dead || needed[m.ID] {
			out = append(out, m)
		}
	}
	return out
}

// deadSpace is the number of bytes that compact would reclaim: everything
// that is not the header, a kept blob, the current index or the trailer.
func deadSpace(r *Reader) int64 {
	used := r.hdr.BodyOffset() + int64(r.tr.IndexLength) + format.TrailerSize
	keep := kept(r.index.Members)
	for _, m := range keep {
		if m.Type.HasPayload() {
			used += int64(m.Length)
		}
	}
	// A dictionary that no kept member uses is dead space (doc/design.md 9.3).
	inUse := usedDicts(keep, r.index.Codecs)
	for _, d := range r.index.Dicts {
		if inUse[d.ID] {
			used += int64(d.Length)
		}
	}
	return r.size - used
}

// usedDicts returns the ids of the dictionaries that the members' codecs use.
func usedDicts(members []format.Member, codecs []format.CodecSpec) map[uint32]bool {
	out := map[uint32]bool{}
	for _, m := range members {
		if m.Codec >= 0 && m.Codec < len(codecs) && codecs[m.Codec].Dict != 0 {
			out[codecs[m.Codec].Dict] = true
		}
	}
	return out
}

// pruneCatalog keeps the catalog entries that the members use, in their
// order, and renumbers each member's codec to match. Compact uses it, so that
// an entry cannot name a dictionary that the new archive does not hold.
func pruneCatalog(members []format.Member, codecs []format.CodecSpec) []format.CodecSpec {
	renumber := make([]int, len(codecs))
	for i := range renumber {
		renumber[i] = format.NoCodec
	}
	for _, m := range members {
		if m.Codec >= 0 && m.Codec < len(codecs) {
			renumber[m.Codec] = 0
		}
	}
	var out []format.CodecSpec
	for i, c := range codecs {
		if renumber[i] == 0 {
			renumber[i] = len(out)
			out = append(out, c)
		}
	}
	for i := range members {
		if c := members[i].Codec; c >= 0 && c < len(codecs) {
			members[i].Codec = renumber[c]
		}
	}
	return out
}

// copyDicts copies, byte for byte, each dictionary that the kept members use.
// A sealed dictionary stays valid: its key comes from its salt and its id,
// not from where it lies.
func copyDicts(r *Reader, w *Writer, keep []format.Member) error {
	inUse := usedDicts(keep, w.index.Codecs)
	for _, d := range r.index.Dicts {
		if !inUse[d.ID] {
			continue
		}
		src := io.NewSectionReader(r.f, int64(d.Offset), int64(d.Length))
		if _, err := io.Copy(w.f, src); err != nil {
			return fmt.Errorf("copying dictionary %d: %w", d.ID, err)
		}
		d.Offset = uint64(w.off)
		w.off += int64(d.Length)
		w.index.Dicts = append(w.index.Dicts, d)
	}
	return nil
}

// CompactConfig drives --compact.
type CompactConfig struct {
	Archive  string
	Open     OpenOptions
	Reporter Reporter
	// Recompress, when set, encodes every member again with other codec
	// settings (--recompress). Otherwise the blobs are copied as they are.
	Recompress *RecompressConfig
	// Rewrap, when set, seals the data key under a new passphrase
	// (--change-passphrase, doc/design.md 9.7).
	Rewrap *RewrapConfig
}

// RewrapConfig is the new passphrase of --change-passphrase. Passphrase is
// asked only after the old passphrase has opened the archive. A zero field of
// Params keeps the archive's own value.
type RewrapConfig struct {
	Passphrase PassphraseFunc
	Params     crypt.KDFParams
}

// RecompressConfig is how --recompress encodes the members again. The fields
// mean what they mean for a create.
type RecompressConfig struct {
	Codec          string
	Params         codec.Params
	ChunkSize      int
	Workers        int
	MemoryLimit    int64
	SpillThreshold int64
}

// CompactResult says what a compact did.
type CompactResult struct {
	OldSize, NewSize int64
	Dropped          int  // tombstones removed from the index
	NothingToDo      bool // no dead space and no removable tombstone
	Recompressed     int  // members encoded again
}

// CompactArchive writes the archive again without its dead space
// (doc/design.md 9.3).
//
// By default the blobs are copied byte for byte: nothing is decompressed or
// unsealed, which is why the uuid must stay the same - the member keys come
// from it. With Recompress, each member is decoded and encoded again instead.
// The new file is written beside the original and renamed over it, so a crash
// at any point leaves one complete archive at the path.
func CompactArchive(cfg CompactConfig) (CompactResult, error) {
	var res CompactResult

	// Through a symlink, the rename must replace the file, not the link, and
	// the link must be one that the program follows (checkLinks).
	if err := checkLinks(cfg.Archive); err != nil {
		return res, err
	}
	path, err := filepath.EvalSymlinks(cfg.Archive)
	if err != nil {
		return res, fmt.Errorf("resolving %s: %w", cfg.Archive, err)
	}
	r, err := openLocked(path, cfg.Open)
	if err != nil {
		return res, err
	}
	defer r.Close()

	res.OldSize = r.size
	keep := kept(r.index.Members)
	res.Dropped = len(r.index.Members) - len(keep)
	if cfg.Rewrap != nil && r.crypto == nil {
		return res, fmt.Errorf("%s: %w; there is no passphrase to change", cfg.Archive, ErrNotEncrypted)
	}
	if cfg.Recompress == nil && cfg.Rewrap == nil && res.Dropped == 0 && deadSpace(r) == 0 {
		res.NothingToDo = true
		res.NewSize = r.size
		return res, nil
	}

	fi, err := r.f.Stat()
	if err != nil {
		return res, fmt.Errorf("stat %s: %w", cfg.Archive, err)
	}
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, "."+base+".rewrite-*")
	if err != nil {
		return res, fmt.Errorf("creating the compacted archive: %w", err)
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			tmp.Close()
			os.Remove(tmpPath)
		}
	}()

	// The header and the crypto header are copied as they are: same uuid, same
	// salt, same KDF parameters, so the same passphrase opens the result. A
	// change of passphrase writes a new crypto header instead, and a header
	// that gives its new length.
	hdr := r.hdr
	var body int64
	if cfg.Rewrap == nil {
		body = r.hdr.BodyOffset()
		if _, err := io.Copy(tmp, io.NewSectionReader(r.f, 0, body)); err != nil {
			return res, fmt.Errorf("copying the header: %w", err)
		}
	} else {
		head, newHdr, err := rewrapHeaders(r, cfg.Rewrap)
		if err != nil {
			return res, err
		}
		if _, err := tmp.Write(head); err != nil {
			return res, fmt.Errorf("writing the header: %w", err)
		}
		hdr, body = newHdr, int64(len(head))
	}

	// The old index chain is gone, so there is no previous index to name.
	w := &Writer{
		f:    tmp,
		path: tmpPath,
		hdr:  hdr,
		index: format.Index{
			Version:    format.IndexVersion,
			Generation: r.tr.Generation + 1,
			Codecs:     r.index.Codecs,
		},
		keys:         r.keys,
		encryptIndex: r.tr.IndexEncrypted(),
		off:          body,
	}
	progress := progressOf(cfg.Reporter)
	if cfg.Recompress == nil {
		if progress != nil {
			var total int64
			for _, m := range keep {
				total += int64(m.Length)
			}
			progress.Total(total)
		}
		w.index.Codecs = pruneCatalog(keep, r.index.Codecs)
		if err = copyDicts(r, w, keep); err == nil {
			err = copyBlobs(r, w, keep, progress)
		}
	} else {
		if progress != nil {
			progress.Total(payloadTotal(keep))
		}
		res.Recompressed, err = recompressBlobs(r, w, keep, cfg.Recompress, tmpPath, progress, warnOf(cfg.Reporter))
	}
	if err != nil {
		return res, err
	}
	if err := w.writeIndexAndTrailer(); err != nil {
		return res, err
	}

	// The same permissions, and the same owner where this process may set it.
	if err := tmp.Chmod(fi.Mode().Perm()); err != nil {
		return res, fmt.Errorf("setting the mode of the compacted archive: %w", err)
	}
	if info := meta.Stat(fi); info.OK {
		if err := tmp.Chown(int(info.UID), int(info.GID)); err != nil && cfg.Reporter != nil {
			cfg.Reporter.Warn("%s: could not keep the owner %d:%d: %v", cfg.Archive, info.UID, info.GID, err)
		}
	}
	if err := tmp.Sync(); err != nil {
		return res, fmt.Errorf("syncing the compacted archive: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return res, fmt.Errorf("closing the compacted archive: %w", err)
	}
	if err := renameOver(tmpPath, path); err != nil {
		return res, fmt.Errorf("replacing %s: %w", cfg.Archive, err)
	}
	committed = true
	if err := syncDir(dir); err != nil {
		return res, err
	}
	res.NewSize = w.off
	return res, nil
}

// testBeforeCompactLock, when set by a test, runs after compact opens the
// archive and before it takes the lock.
var testBeforeCompactLock func()

// openLocked opens the archive at path, takes the writer's lock, and only
// then reads the trailer and the index (doc/design.md 9.6). The lock is held
// until the reader is closed: for compact, after the rename. Reading first
// and locking after let an append commit in between, and compact then wrote
// the archive again from the older index and renamed it over the append.
func openLocked(path string, opt OpenOptions) (*Reader, error) {
	f, err := openArchiveFile(path, os.O_RDONLY)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	if testBeforeCompactLock != nil {
		testBeforeCompactLock()
	}
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
	if err := r.load(opt); err != nil {
		r.Close()
		return nil, err
	}
	return r, nil
}

// rewrapHeaders builds the file header and the crypto header of a change of
// passphrase: the same archive id and data key, a new salt, new KDF
// parameters where given, and the data key wrapped for the new passphrase.
func rewrapHeaders(r *Reader, rw *RewrapConfig) ([]byte, format.Header, error) {
	params := crypt.KDFParams{Time: r.crypto.Time, Memory: r.crypto.Memory, Threads: r.crypto.Threads}
	if rw.Params.Time != 0 {
		params.Time = rw.Params.Time
	}
	if rw.Params.Memory != 0 {
		params.Memory = rw.Params.Memory
	}
	if rw.Params.Threads != 0 {
		params.Threads = rw.Params.Threads
	}
	if err := params.Validate(); err != nil {
		return nil, format.Header{}, err
	}
	if params.Time > format.MaxKDFTime || params.Memory > format.MaxKDFMemoryKiB {
		return nil, format.Header{}, fmt.Errorf("kdf: time %d and memory %d KiB: the format allows at most %d and %d KiB",
			params.Time, params.Memory, format.MaxKDFTime, format.MaxKDFMemoryKiB)
	}
	// The new parameters must open on this machine, or the change locks the
	// archive against the one that made it (doc/design.md A.3).
	if err := checkAffordable(params); err != nil {
		return nil, format.Header{}, err
	}

	pass, err := rw.Passphrase()
	if err != nil {
		return nil, format.Header{}, fmt.Errorf("the new passphrase: %w", err)
	}
	defer clear(pass)
	if len(pass) == 0 {
		return nil, format.Header{}, errors.New("an empty passphrase cannot protect anything")
	}
	salt, wrapped, err := r.keys.Wrap(pass, params)
	if err != nil {
		return nil, format.Header{}, err
	}
	ch := *r.crypto
	ch.Salt, ch.Key = salt, wrapped
	ch.Time, ch.Memory, ch.Threads = params.Time, params.Memory, params.Threads
	cryptoBytes, err := ch.Marshal()
	if err != nil {
		return nil, format.Header{}, err
	}
	hdr := r.hdr
	hdr.CryptoHeaderLen = uint32(len(cryptoBytes))
	hdrBytes, err := hdr.MarshalBinary()
	if err != nil {
		return nil, format.Header{}, err
	}
	return append(hdrBytes, cryptoBytes...), hdr, nil
}

// copyBlobs moves the kept blobs into w as they are, in file order so that
// the reads are sequential.
func copyBlobs(r *Reader, w *Writer, keep []format.Member, progress Progress) error {
	sort.Slice(keep, func(i, j int) bool { return keep[i].Offset < keep[j].Offset })
	for i := range keep {
		m := &keep[i]
		if !m.Type.HasPayload() || m.Data != 0 {
			continue // no blob of its own
		}
		if m.Length > 0 {
			src := io.NewSectionReader(r.f, int64(m.Offset), int64(m.Length))
			if _, err := io.Copy(w.f, countReader(src, progress)); err != nil {
				return fmt.Errorf("copying %q: %w", m.Path, err)
			}
		}
		m.Offset = uint64(w.off)
		w.off += int64(m.Length)
	}
	w.index.Members = keep
	return nil
}

// recompressBlobs decodes each kept member and encodes it again through the
// same pipeline a create uses, into w. It returns the number of members with
// content.
//
// A member keeps its id, its digest and its metadata. It gets a new member
// salt, and so a new key: its chunks are new ciphertext at the old chunk
// indexes, and sealing them under the old key would use each nonce twice
// (doc/design.md 6.3). The catalog is replaced, because no old entry is used
// any more.
func recompressBlobs(r *Reader, w *Writer, keep []format.Member, rc *RecompressConfig, tmpPath string, progress Progress, warn func(string, ...any)) (int, error) {
	workers := rc.Workers
	if workers < 1 {
		workers = runtime.GOMAXPROCS(0)
	}
	chunkSize := rc.ChunkSize
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	spill := rc.SpillThreshold
	if spill <= 0 {
		spill = DefaultSpillThreshold
	}
	name := rc.Codec
	if name == "" {
		name = "none"
	}
	slots := encoderSlots(Options{Codec: name, Params: rc.Params, ChunkSize: chunkSize}, workers, rc.MemoryLimit)
	enc, err := codec.NewEncoderWith(name, rc.Params, codec.EncoderOptions{Concurrency: slots, MaxChunk: chunkSize})
	if err != nil {
		return 0, err
	}

	w.enc, w.codecName, w.chunkSize = enc, name, chunkSize
	w.params, w.concurrency = rc.Params, slots
	defer func() { w.enc.Close() }()
	w.codecRef, w.addedCodec = format.NoCodec, false
	w.index.Codecs = nil
	if name != "none" {
		w.index.Codecs = []format.CodecSpec{{Name: name, Params: enc.Resolved()}}
		w.codecRef, w.addedCodec = 0, true
	}
	// --recompress zstd:train trains a new dictionary from the members; the
	// old dictionaries go, with the catalog that used them (doc/design.md
	// 4.2). The members are already in the archive, so there is none to reuse.
	if err := w.useDictionary(func(budget int) ([][]byte, int, error) { return sampleMembers(r, keep, budget) }, warn); err != nil {
		return 0, err
	}
	enc = w.enc

	builder := pipeline.New(pipeline.Config{
		Workers:        workers,
		ChunkSize:      chunkSize,
		Budget:         pipeline.NewBudget(budgetFor(rc.MemoryLimit, workers, chunkSize)),
		SpillThreshold: spill,
		SpillDir:       filepath.Dir(tmpPath),
		Encoder:        enc,
		Stored:         w.codecRef == format.NoCodec,
		NewSealer:      w.newSealer,
		Emit:           w.AppendMember,
	})
	builder.Start()

	// In id order, so that the new archive is laid out as a create would lay
	// it out.
	sort.Slice(keep, func(i, j int) bool { return keep[i].ID < keep[j].ID })
	count := 0
	var addErr error
	for i := range keep {
		m := keep[i]
		// A member that shares content stays a sharer: its owner keeps its
		// id, and is encoded again below (doc/design.md 4.3).
		if !m.Type.HasPayload() || m.Data != 0 {
			if addErr = builder.AddMeta(m); addErr != nil {
				break
			}
			continue
		}
		if addErr = recompressOne(r, w, builder, m, progress); addErr != nil {
			break
		}
		count++
	}
	if err := builder.Finish(); addErr == nil {
		addErr = err
	}
	return count, addErr
}

// recompressOne feeds one member's content, decoded, to the pipeline.
func recompressOne(r *Reader, w *Writer, b *pipeline.Builder, m format.Member, progress Progress) error {
	old := m
	m.Offset, m.Length, m.Chunks, m.ChunkSize = 0, 0, nil, 0
	m.Enc, m.Digest = nil, nil
	m.Codec = w.CodecRef()

	// The decoder writes into the pipe while the pipeline reads from it. The
	// old digest is checked at the end of the decode, and the pipeline
	// computes the new one over the same bytes, so a member that changes on
	// the way fails instead of being stored with a digest that lies.
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(r.WriteMember(&old, pw)) }()
	err := b.AddFile(m, countReader(pr, progress), w.newDigest())
	pr.CloseWithError(errors.New("recompression stopped")) // unblock the decoder on an early return
	if err != nil {
		return fmt.Errorf("%s: %w", old.Path, err)
	}
	return nil
}

// decodeInParallel decodes the content of each member of work with a pool of
// workers, and discards it: the decode checks every AEAD tag and the digest.
// It calls report for each member in the order of work, from the calling
// goroutine only, so report needs no lock.
//
// The workers take members in batches of consecutive members. One channel
// operation for each small member costs more than its decode, so a batch
// holds up to decodeBatchMembers members, or decodeBatchBytes of content. A
// batch that finishes early waits in pending until the batches before it are
// reported. pending holds only an error for each member, not content.
func decodeInParallel(r *Reader, work []*format.Member, workers int, memoryLimit int64,
	progress Progress, report func(*format.Member, error)) {
	if workers < 1 {
		workers = runtime.GOMAXPROCS(0)
	}
	workers = min(workers, len(work))
	if workers < 1 {
		return
	}
	// The members of work hold their own blobs, so each is its own owner.
	workers = boundByMemory(workers, largestChunk(work, func(*format.Member) *format.Member { return nil }), memoryLimit)

	// starts[b] is the first member of batch b; the last entry is len(work).
	starts := []int{0}
	var size uint64
	for i, m := range work {
		if i > starts[len(starts)-1] && (i-starts[len(starts)-1] == decodeBatchMembers || size >= decodeBatchBytes) {
			starts = append(starts, i)
			size = 0
		}
		size += m.PayloadSize()
	}
	starts = append(starts, len(work))
	batches := len(starts) - 1

	type outcome struct {
		batch int
		errs  []error
	}
	var next atomic.Int64
	results := make(chan outcome, workers)
	var wg sync.WaitGroup
	for range min(workers, batches) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			set := r.newDecoderSet()
			defer set.close()
			for {
				b := int(next.Add(1) - 1)
				if b >= batches {
					return
				}
				errs := make([]error, starts[b+1]-starts[b])
				for k := range errs {
					errs[k] = r.writeMember(work[starts[b]+k], countWriter(io.Discard, progress), set)
				}
				results <- outcome{b, errs}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	pending := map[int][]error{}
	reported := 0
	for o := range results {
		pending[o.batch] = o.errs
		for {
			errs, ok := pending[reported]
			if !ok {
				break
			}
			delete(pending, reported)
			for k, err := range errs {
				report(work[starts[reported]+k], err)
			}
			reported++
		}
	}
}

// The size of a batch of decodeInParallel: enough members that the channel
// costs little, and little enough content that the work stays balanced.
const (
	decodeBatchMembers = 64
	decodeBatchBytes   = 1 << 20
)

// VerifyConfig drives --verify.
type VerifyConfig struct {
	Archive  string
	Patterns []string
	Regex    fsutil.Regexps // -R
	Open     OpenOptions
	// Quick checks the structure only and reads no member data.
	Quick bool
	// Workers is the number of decoding goroutines; 0 means GOMAXPROCS.
	Workers int
	// MemoryLimit bounds what the decoders may allocate; 0 takes the
	// default of extraction.
	MemoryLimit int64
	Reporter    Reporter
}

// VerifyResult says what a verify checked.
type VerifyResult struct {
	Checked int    // members whose content was decoded
	Bytes   uint64 // plaintext bytes decoded
	Failed  int
}

// VerifyArchive checks an archive without extracting it (doc/design.md 9.4).
//
// Opening already checks the structure: header, trailer, index digest and
// member ranges. Unless Quick is set, every selected member is then decoded
// in full, which checks every AEAD tag and every content digest. The
// tombstone that a selected hardlink points to is decoded too, because
// extraction reads it. Each damaged member is reported, and the error names
// the first.
//
// Workers decode the blobs in parallel, as extraction does. The results are
// reported in the order of the index, whatever order the workers finish in,
// so the output and the error do not depend on the number of workers.
func VerifyArchive(cfg VerifyConfig) (VerifyResult, error) {
	var res VerifyResult

	r, err := OpenWith(cfg.Archive, cfg.Open)
	if err != nil {
		return res, err
	}
	defer r.Close()
	if cfg.Quick {
		return res, nil
	}

	members, err := selectMembers(r.Members(), cfg.Patterns, cfg.Regex)
	if err != nil {
		return res, err
	}
	byID := map[uint64]*format.Member{}
	for i := range r.index.Members {
		byID[r.index.Members[i].ID] = &r.index.Members[i]
	}
	seen := map[uint64]bool{}
	var todo []*format.Member
	// sharers counts, for each owner, the selected members that share its
	// content. Each blob is decoded one time, and its result is theirs too
	// (doc/design.md 4.3).
	sharers := map[uint64][]*format.Member{}
	sharing := map[uint64]bool{}
	add := func(m *format.Member) {
		if m.Data != 0 {
			if o, ok := byID[m.Data]; ok {
				if !sharing[m.ID] {
					sharing[m.ID] = true
					sharers[o.ID] = append(sharers[o.ID], m)
				}
				m = o
			}
		}
		if !seen[m.ID] {
			seen[m.ID] = true
			todo = append(todo, m)
		}
	}
	// picked are the members that the patterns selected. Only they count as
	// checked: a tombstone that holds content for one of them is decoded,
	// but it is not a member that the user asked about.
	picked := map[uint64]bool{}
	for i := range members {
		m := &members[i]
		picked[m.ID] = true
		if m.Type == format.TypeHardlink {
			// A hardlink's content is its target's: it passes or fails with
			// the target, as a member that shares content does.
			if t, ok := byID[m.HardlinkTo]; ok {
				add(t)
				t = byID[t.ID]
				if t.Data != 0 {
					t = byID[t.Data]
				}
				sharers[t.ID] = append(sharers[t.ID], m)
			}
			continue
		}
		add(m)
	}

	progress := progressOf(cfg.Reporter)
	if progress != nil {
		var total int64
		for _, m := range todo {
			if m.Type.HasPayload() {
				total += int64(m.PayloadSize())
			}
		}
		progress.Total(total)
	}

	var work []*format.Member
	for _, m := range todo {
		if m.Type.HasPayload() {
			work = append(work, m)
		}
	}

	var first error
	report := func(m *format.Member, err error) {
		if err != nil {
			if picked[m.ID] {
				res.Failed++
			}
			if first == nil {
				first = err
			}
			if cfg.Reporter != nil {
				cfg.Reporter.Warn("%s: %v", m.Path, err)
			}
			for _, s := range sharers[m.ID] {
				if picked[s.ID] {
					res.Failed++
					if cfg.Reporter != nil {
						cfg.Reporter.Warn("%s: has the content of %s, which failed", s.Path, m.Path)
					}
				}
			}
			return
		}
		res.Bytes += m.Size
		if picked[m.ID] {
			res.Checked++
			if cfg.Reporter != nil {
				cfg.Reporter.Member(m)
			}
		}
		for _, s := range sharers[m.ID] {
			if picked[s.ID] {
				res.Checked++
				if cfg.Reporter != nil {
					cfg.Reporter.Member(s)
				}
			}
		}
	}
	decodeInParallel(r, work, cfg.Workers, cfg.MemoryLimit, progress, report)
	if first != nil {
		return res, fmt.Errorf("%d of %d members failed verification; the first: %w",
			res.Failed, res.Failed+res.Checked, first)
	}
	return res, nil
}

// CodecUse is one codec of the catalog and the live members that use it.
type CodecUse struct {
	Spec    format.CodecSpec
	Members int
}

// DictUse is one dictionary, and the number of live members that use it.
type DictUse struct {
	Dict    format.Dict
	Members int
}

// ArchiveInfo is what --info shows.
type ArchiveInfo struct {
	Size    int64
	Header  format.Header
	Trailer format.Trailer
	// Crypto is nil for a plaintext archive.
	Crypto *format.CryptoHeader

	Live, Dead  int
	Stored      int // live members with no codec
	Codecs      []CodecUse
	Dicts       []DictUse
	Shared      int    // live members that share the content of another
	NotStored   uint64 // the bytes that those members did not store
	Plain       uint64 // plaintext bytes of the live members
	Blobs       uint64 // on-disk bytes of the live members' blobs
	IndexLength uint64
	DeadSpace   int64 // what --compact would reclaim
}

// Info gathers what --info shows.
func Info(path string, open OpenOptions) (*ArchiveInfo, error) {
	r, err := OpenWith(path, open)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	in := &ArchiveInfo{
		Size:        r.size,
		Header:      r.hdr,
		Trailer:     r.tr,
		Crypto:      r.crypto,
		IndexLength: r.tr.IndexLength,
		DeadSpace:   deadSpace(r),
	}
	for _, c := range r.index.Codecs {
		in.Codecs = append(in.Codecs, CodecUse{Spec: c})
	}
	for _, m := range r.index.Members {
		if m.Dead {
			in.Dead++
			continue
		}
		in.Live++
		if m.Data != 0 {
			in.Shared++
			if o := r.Owner(&m); o != nil {
				in.NotStored += o.Length
			}
		}
		if m.Type.HasPayload() {
			in.Plain += m.Size
			in.Blobs += m.Length
			if m.Codec == format.NoCodec {
				in.Stored++
			} else if m.Codec >= 0 && m.Codec < len(in.Codecs) {
				in.Codecs[m.Codec].Members++
			}
		}
	}
	for _, d := range r.index.Dicts {
		use := DictUse{Dict: d}
		for _, c := range in.Codecs {
			if c.Spec.Dict == d.ID {
				use.Members += c.Members
			}
		}
		in.Dicts = append(in.Dicts, use)
	}
	return in, nil
}

// RepairResult says what --repair did.
type RepairResult struct {
	AlreadyValid bool  // the archive opened; nothing was changed
	Removed      int64 // bytes cut from the end
	Generation   uint64
}

// repairWindow is how much of the file one scan step reads.
const repairWindow = 1 << 20

// trailerMagic starts every trailer.
var trailerMagic = format.TrailerMagic[:]

// RepairArchive restores the last complete generation of an archive whose end
// is damaged, usually by a crash during a mutation (doc/design.md 9.5).
//
// It searches back from the end for a trailer that passes every check a
// reader makes - magic, CRC, bounds, index digest, index decode, member
// ranges - as if the file ended right after it. Then it cuts the file there.
// An archive that opens is left alone. A wrong passphrase stops the repair
// before anything is scanned: that archive is not damaged.
func RepairArchive(path string, open OpenOptions) (RepairResult, error) {
	var res RepairResult

	// The passphrase is asked for at most once, although the checks below can
	// need it more than once.
	var secret []byte
	defer func() { zero(secret) }()
	if ask := open.Passphrase; ask != nil {
		open.Passphrase = func() ([]byte, error) {
			if secret == nil {
				p, err := ask()
				if err != nil {
					return nil, err
				}
				secret = append([]byte(nil), p...)
				zero(p)
			}
			return append([]byte(nil), secret...), nil
		}
	}

	r, err := OpenWith(path, open)
	if err == nil {
		res.AlreadyValid = true
		res.Generation = r.tr.Generation
		r.Close()
		return res, nil
	}
	if !IsDamage(err) {
		return res, err
	}

	f, err := openArchiveFile(path, os.O_RDWR)
	if err != nil {
		return res, fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()
	// A repair that ran beside an append would cut off what the append is
	// still writing.
	if err := lockArchive(f, path); err != nil {
		return res, err
	}
	fi, err := f.Stat()
	if err != nil {
		return res, fmt.Errorf("stat %s: %w", path, err)
	}
	size := fi.Size()

	// The header is not repairable: every trailer is checked against it.
	base := &Reader{f: f, path: path, size: size}
	hdrBytes := make([]byte, format.HeaderSize)
	if _, err := f.ReadAt(hdrBytes, 0); err != nil {
		return res, fmt.Errorf("%s: reading header: %w", path, err)
	}
	if err := base.hdr.UnmarshalBinary(hdrBytes); err != nil {
		return res, fmt.Errorf("%s: the header is damaged, and repair cannot restore it: %w", path, err)
	}

	// Derive the keys once, and hand them to each candidate. One Argon2id run
	// per candidate is slow, and an archive of archives stored without
	// compression holds a real trailer inside every member.
	if base.hdr.Encrypted() {
		if err := base.unlock(open.Passphrase); err != nil {
			return res, err
		}
		defer base.keys.Zero()
	} else if open.RequireEncryption {
		return res, fmt.Errorf("%s: %w; if it should be, it has been replaced or stripped", path, ErrNotEncrypted)
	}

	candidate := func(p int64) (*Reader, bool) {
		c := &Reader{f: f, path: path, size: p + format.TrailerSize}
		if err := c.load(OpenOptions{keys: base.keys}); err != nil {
			return nil, false
		}
		return c, true
	}

	body := base.hdr.BodyOffset()
	buf := make([]byte, repairWindow)
	end := size
	for end > body {
		start := max(body, end-repairWindow)
		n, err := f.ReadAt(buf[:end-start], start)
		if err != nil && !errors.Is(err, io.EOF) {
			return res, fmt.Errorf("%s: reading: %w", path, err)
		}
		win := buf[:n]
		// Each step looks only at the matches that start before the last one.
		// Trailers can overlap in principle, so lim keeps the magic's tail.
		for lim := len(win); ; {
			i := bytes.LastIndex(win[:lim], trailerMagic)
			if i < 0 {
				break
			}
			p := start + int64(i)
			if p+format.TrailerSize <= size {
				if c, ok := candidate(p); ok {
					res.Generation = c.tr.Generation
					res.Removed = size - c.size
					if err := f.Truncate(c.size); err != nil {
						return res, fmt.Errorf("%s: truncating: %w", path, err)
					}
					if err := f.Sync(); err != nil {
						return res, fmt.Errorf("%s: syncing: %w", path, err)
					}
					return res, nil
				}
			}
			lim = i + len(trailerMagic) - 1
		}
		if start == body {
			break
		}
		// Overlap by one byte less than the magic, so that a magic across
		// the boundary is found once, in the next window.
		end = start + int64(len(trailerMagic)) - 1
	}
	return res, fmt.Errorf("%s: %w: no complete generation found; the archive cannot be repaired",
		path, format.ErrCorruptIndex)
}

// damage lists the errors that mean the archive's bytes are damaged or were
// altered.
var damage = []error{
	format.ErrBadMagic, format.ErrChecksum, format.ErrCorruptIndex, format.ErrCorruptData,
	format.ErrTruncated, format.ErrIndexTooLarge, format.ErrVersionMismatch,
	crypt.ErrAuthentication,
}

// IsDamage reports whether err means the archive is damaged or was altered,
// as opposed to a wrong passphrase, an archive too new for this build, or an
// I/O error. Repair scans only past damage, and the command line reports it
// with its own exit code (doc/design.md 10.7).
func IsDamage(err error) bool {
	for _, e := range damage {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}
