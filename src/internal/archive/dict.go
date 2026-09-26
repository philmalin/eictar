package archive

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/philmalin/eictar/src/internal/codec"
	"github.com/philmalin/eictar/src/internal/crypt"
	"github.com/philmalin/eictar/src/internal/format"
)

// Dictionaries (doc/design.md 4.2): zstd trains one from samples of the
// files, the archive stores it as a blob, and each catalog entry names the
// dictionary of its codec.

const (
	// sampleSize is how much of each file the trainer sees. The start of a
	// file is what the trainer learns from; more adds little.
	sampleSize = 32 << 10
	// sampleFactor bounds the samples: at most this many times the
	// dictionary size, which is what zstd's own trainer asks for.
	sampleFactor = 100
)

// errEnoughSample stops a decode once a sample is full.
var errEnoughSample = errors.New("the sample is full")

// useDictionary gives the writer a dictionary, before any member is added,
// when the codec parameters ask for one (-Z zstd:train). An append reuses the
// archive's newest dictionary; otherwise sample supplies the samples and a
// new dictionary is trained. When no dictionary can be trained, the writer
// goes on without one, and warn says so.
func (w *Writer) useDictionary(sample func(size int) ([][]byte, error), warn func(string, ...any)) error {
	size, err := codec.TrainSize(w.codecName, w.params)
	if err != nil || size == 0 {
		return err
	}
	if w.appending {
		if d, ok := newestDict(w.index.Dicts); ok {
			content, err := loadDict(w.f, w.keys, w.hdr.Encrypted(), d)
			if err != nil {
				return err
			}
			return w.switchEncoder(d.ID, content)
		}
	}
	samples, err := sample(size)
	if err != nil {
		return err
	}
	content, id, err := w.train(samples, size)
	if err != nil {
		if warn != nil {
			warn("compressing without a dictionary: %v", err)
		}
		return nil
	}
	if err := w.storeDict(id, content); err != nil {
		return err
	}
	return w.switchEncoder(id, content)
}

// train makes a dictionary with an id that the archive does not have.
func (w *Writer) train(samples [][]byte, size int) ([]byte, uint32, error) {
	if len(samples) == 0 {
		return nil, 0, errors.New("there are no files to learn from")
	}
	id, err := w.newDictID()
	if err != nil {
		return nil, 0, err
	}
	content, err := codec.TrainDict(w.codecName, w.params, samples, size, id)
	if err == nil && len(content) > format.MaxDictSize {
		// The codec keeps within size, and size within the limit. This is
		// the check that the index makes on Close, made before any member
		// is compressed, so that a fault costs a notice and not the run.
		err = fmt.Errorf("the dictionary is %d bytes, above the %d limit", len(content), format.MaxDictSize)
	}
	return content, id, err
}

// newDictID takes a random id that the archive does not use. Ids below
// 32768 are reserved by the zstd format, and zero means "none".
func (w *Writer) newDictID() (uint32, error) {
	for {
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			return 0, fmt.Errorf("generating a dictionary id: %w", err)
		}
		id := binary.LittleEndian.Uint32(b[:])&0x7fffffff | 1<<15
		taken := false
		for _, d := range w.index.Dicts {
			taken = taken || d.ID == id
		}
		if !taken {
			return id, nil
		}
	}
}

// storeDict writes a dictionary blob at the current offset, sealed when the
// archive is encrypted, and lists it in the index.
func (w *Writer) storeDict(id uint32, content []byte) error {
	h := w.newDigest()
	h.Write(content)
	d := format.Dict{
		ID:         id,
		Generation: w.index.Generation,
		Size:       uint32(len(content)),
		Digest:     h.Sum(nil),
		Offset:     uint64(w.off),
	}
	blob := content
	if w.keys != nil {
		salt := make([]byte, crypt.SaltSize)
		if _, err := rand.Read(salt); err != nil {
			return fmt.Errorf("generating a dictionary salt: %w", err)
		}
		key, err := w.keys.DictKey(salt)
		if err != nil {
			return err
		}
		if blob, err = crypt.SealDict(key, id, content); err != nil {
			return err
		}
		d.Enc = &format.EncInfo{Salt: salt}
	}
	n, err := w.f.Write(blob)
	if err != nil {
		return fmt.Errorf("writing a dictionary to %s: %w", w.path, err)
	}
	w.off += int64(n)
	d.Length = uint64(n)
	w.index.Dicts = append(w.index.Dicts, d)
	return nil
}

// switchEncoder replaces the writer's encoder with one that uses the
// dictionary, and points the catalog at an entry that names it. It must run
// before the pipeline starts.
func (w *Writer) switchEncoder(id uint32, content []byte) error {
	enc, err := codec.NewEncoderWith(w.codecName, w.params, codec.EncoderOptions{Concurrency: w.concurrency, Dict: content, MaxChunk: w.chunkSize})
	if err != nil {
		return err
	}
	w.enc.Close()
	w.enc = enc

	// The entry without the dictionary was added for this writer, and no
	// member uses it: take it away again.
	if w.addedCodec {
		w.index.Codecs = w.index.Codecs[:len(w.index.Codecs)-1]
	}
	w.codecRef, w.addedCodec = w.catalogRef(format.CodecSpec{
		Name: w.codecName, Params: enc.Resolved(), Dict: id,
	})
	return nil
}

// catalogRef returns the position of spec in the catalog, and adds it when it
// is not there. added reports that it was added.
func (w *Writer) catalogRef(spec format.CodecSpec) (ref int, added bool) {
	for i, c := range w.index.Codecs {
		if format.SameCodec(c, spec) {
			return i, false
		}
	}
	w.index.Codecs = append(w.index.Codecs, spec)
	return len(w.index.Codecs) - 1, true
}

// newestDict is the dictionary of the latest generation. Of two in one
// generation, the later in the list wins.
func newestDict(dicts []format.Dict) (format.Dict, bool) {
	var best format.Dict
	found := false
	for _, d := range dicts {
		if !found || d.Generation >= best.Generation {
			best, found = d, true
		}
	}
	return best, found
}

// loadDict reads a dictionary blob and checks it: the tag when it is sealed,
// the size, the digest, and the id that the dictionary carries. Each failure
// is damage (exit 3).
func loadDict(f io.ReaderAt, keys *crypt.Keys, encrypted bool, d format.Dict) ([]byte, error) {
	raw := make([]byte, d.Length)
	if _, err := f.ReadAt(raw, int64(d.Offset)); err != nil {
		return nil, fmt.Errorf("reading dictionary %d: %w", d.ID, err)
	}
	content := raw
	switch {
	case d.Enc != nil:
		if keys == nil {
			return nil, fmt.Errorf("dictionary %d is encrypted and no passphrase was supplied", d.ID)
		}
		key, err := keys.DictKey(d.Enc.Salt)
		if err != nil {
			return nil, fmt.Errorf("%w: dictionary %d: %v", format.ErrCorruptIndex, d.ID, err)
		}
		if content, err = crypt.OpenDict(key, d.ID, raw); err != nil {
			return nil, err
		}
	case encrypted:
		return nil, fmt.Errorf("%w: dictionary %d is unsealed in an encrypted archive", format.ErrCorruptIndex, d.ID)
	}
	if len(content) != int(d.Size) {
		return nil, fmt.Errorf("%w: dictionary %d is %d bytes, the index says %d",
			format.ErrCorruptIndex, d.ID, len(content), d.Size)
	}
	h := newDigest(keys)
	h.Write(content)
	if subtle.ConstantTimeCompare(h.Sum(nil), d.Digest) != 1 {
		return nil, fmt.Errorf("%w: dictionary %d failed its digest check", format.ErrChecksum, d.ID)
	}
	if id, err := codec.DictID("zstd", content); err != nil || id != d.ID {
		return nil, fmt.Errorf("%w: dictionary %d carries the id %d (%v)", format.ErrCorruptData, d.ID, id, err)
	}
	return content, nil
}

// dictFor returns the dictionary that a member's codec names, or nil. The
// reader keeps each one that it loads, for the other members that use it.
func (r *Reader) dictFor(m *format.Member) ([]byte, error) {
	if m.Codec < 0 || m.Codec >= len(r.index.Codecs) {
		return nil, nil
	}
	id := r.index.Codecs[m.Codec].Dict
	if id == 0 {
		return nil, nil
	}
	r.dictMu.Lock()
	defer r.dictMu.Unlock()
	if content, ok := r.dicts[id]; ok {
		return content, nil
	}
	for _, d := range r.index.Dicts {
		if d.ID != id {
			continue
		}
		content, err := loadDict(r.f, r.keys, r.hdr.Encrypted(), d)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", r.path, err)
		}
		if r.dicts == nil {
			r.dicts = map[uint32][]byte{}
		}
		r.dicts[id] = content
		return content, nil
	}
	// format.Index.Validate refuses this; it is here for a caller that built
	// an index by hand.
	return nil, fmt.Errorf("%w: codec %d names dictionary %d, which the index does not hold",
		format.ErrCorruptIndex, m.Codec, id)
}

// sampleTree is the pass before a create or an append (doc/design.md 4.2).
// It walks the paths with the same filters as the real walk, and takes the
// start of each regular file. Over the budget, it takes every k-th file, so
// that the choice depends only on the tree. An error here is not reported:
// the real walk meets the same file and reports it there.
func sampleTree(w *Writer, cfg CreateConfig, size int) ([][]byte, error) {
	type file struct {
		e entry
		n int
	}
	var files []file
	oldArchive, oldErr := os.Stat(cfg.Archive)
	wk := newWalker(walkOptions{
		baseDir:       cfg.BaseDir,
		dereference:   cfg.Dereference,
		exclude:       cfg.Exclude,
		regex:         cfg.Regex,
		excludeRegex:  cfg.ExcludeRegex,
		oneFileSystem: cfg.OneFileSystem,
	}, func(e entry) error {
		if e.Kind != kindFile || e.Info.Size() == 0 || w.SameFile(e.Info) ||
			(oldErr == nil && os.SameFile(e.Info, oldArchive)) {
			return nil
		}
		files = append(files, file{e, int(min(e.Info.Size(), sampleSize))})
		return nil
	})
	for _, p := range cfg.Paths {
		wk.Walk(p)
	}

	sizes := make([]int, len(files))
	for i, f := range files {
		sizes[i] = f.n
	}
	var samples [][]byte
	for _, i := range pickSamples(sizes, size) {
		// As the capture does: a link put there after the walk is not
		// followed, or its target would go into the dictionary.
		f, err := openWalked(files[i].e)
		if err != nil {
			continue
		}
		buf := make([]byte, files[i].n)
		n, _ := io.ReadFull(f, buf)
		f.Close()
		if n > 0 {
			samples = append(samples, buf[:n])
		}
	}
	return samples, nil
}

// sampleMembers is the pass before --recompress with a dictionary: the start
// of each kept member's content, decoded.
func sampleMembers(r *Reader, keep []format.Member, size int) ([][]byte, error) {
	var members []format.Member
	var sizes []int
	for _, m := range keep {
		if m.Type.HasPayload() && m.PayloadSize() > 0 {
			members = append(members, m)
			sizes = append(sizes, int(min(m.PayloadSize(), sampleSize)))
		}
	}
	var samples [][]byte
	for _, i := range pickSamples(sizes, size) {
		s := &sampleWriter{buf: make([]byte, 0, sizes[i])}
		if err := r.WriteMember(&members[i], s); err != nil && !errors.Is(err, errEnoughSample) {
			return nil, err
		}
		samples = append(samples, s.buf)
	}
	return samples, nil
}

// pickSamples chooses which of the files to sample: all of them, or every
// k-th one, with the smallest k that keeps the samples within the budget.
func pickSamples(sizes []int, dictSize int) []int {
	budget := sampleFactor * dictSize
	total := 0
	for _, n := range sizes {
		total += n
	}
	k := max(1, (total+budget-1)/budget)
	var out []int
	for i := 0; i < len(sizes); i += k {
		out = append(out, i)
	}
	return out
}

// sampleWriter keeps the first cap(buf) bytes, then stops the decode.
type sampleWriter struct{ buf []byte }

func (s *sampleWriter) Write(p []byte) (int, error) {
	room := cap(s.buf) - len(s.buf)
	if len(p) >= room {
		s.buf = append(s.buf, p[:room]...)
		return room, errEnoughSample
	}
	s.buf = append(s.buf, p...)
	return len(p), nil
}

// warnOf is the Warn of a reporter, or nil.
func warnOf(rep Reporter) func(string, ...any) {
	if rep == nil {
		return nil
	}
	return rep.Warn
}
