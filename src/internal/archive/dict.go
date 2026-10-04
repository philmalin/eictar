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

	// The measurement of train=auto (doc/design.md 4.2). Each candidate
	// size trains on trialFactor times its size of samples, from all files
	// but every heldOut-th one. The held-out files, at most trialBudget
	// bytes of them, are compressed with and without the dictionary.
	trialFactor = 20
	heldOut     = 4
	trialBudget = 1 << 20
	// trialMargin is the share of the best net gain that a larger candidate
	// must add to win.
	trialMargin = 0.02
	// trialLookahead is how many candidates may run at once from the first
	// one that is not done. Two lets each candidate run beside the next.
	trialLookahead = 2
	// trialMin is the smallest candidate, and the smallest train=SIZE.
	trialMin = 4 << 10
	// trialID is the id of the candidate dictionaries, which the archive
	// does not store. It is the lowest id outside the reserved range.
	trialID = 1 << 15
)

// errEnoughSample stops a decode once a sample is full.
var errEnoughSample = errors.New("the sample is full")

// useDictionary gives the writer a dictionary, before any member is added,
// when the codec parameters ask for one (-Z zstd:train). An append reuses the
// archive's newest dictionary; otherwise sample supplies the samples within a
// budget of bytes, and the size of all the samples there are, and a new
// dictionary is trained. With train=auto, a measurement on the samples
// chooses the size first. When no dictionary can be trained, or none pays
// for its size, the writer goes on without one, and warn says so.
func (w *Writer) useDictionary(sample func(budget int) ([][]byte, int, error), warn func(string, ...any)) error {
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
	budget := sampleFactor * size
	if size == codec.TrainAuto {
		budget = sampleFactor * format.MaxDictSize
	}
	samples, total, err := sample(budget)
	if err != nil {
		return err
	}
	if size == codec.TrainAuto {
		if size, err = w.chooseDictSize(samples, total); err != nil {
			return err
		}
		if size == 0 {
			if warn != nil {
				warn("compressing without a dictionary: on these files, a dictionary saves less than its own size")
			}
			return nil
		}
		samples = pick(samples, sampleFactor*size)
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

// dictTrial is the result of one candidate size of train=auto: the bytes
// that the dictionary saves on the whole tree, less its own size. ok is
// false when the trainer could not make the dictionary.
type dictTrial struct {
	size int
	net  float64
	ok   bool
}

// chooseDictSize measures which dictionary size makes the smallest archive
// (doc/design.md 4.2), or returns 0 when no size saves more than it costs.
// total is the size of the samples of all the files, of which samples may be
// every k-th one.
//
// The candidates are 4 KiB, 8 KiB, and so on up to the 1 MiB limit, and at
// most half of total. Each trains on the files but every heldOut-th one, and
// the held-out files are compressed with and without the dictionary. The
// saving, scaled from the held-out files to total, less the dictionary
// size, is the net gain. Files that the trainer saw would flatter large
// dictionaries.
//
// bestTrial walks the results in order of size, and the measurement stops at
// two candidates in a row with no gain. The candidates run in parallel, but
// a candidate past the stop point is not used, so the choice does not depend
// on -j.
func (w *Writer) chooseDictSize(samples [][]byte, total int) (int, error) {
	var training, held [][]byte
	for i, s := range samples {
		if i%heldOut == heldOut-1 {
			held = append(held, s)
		} else {
			training = append(training, s)
		}
	}
	held = pick(held, trialBudget)
	heldBytes := 0
	for _, s := range held {
		heldBytes += len(s)
	}
	var sizes []int
	for size := trialMin; size <= format.MaxDictSize && 2*size <= total; size *= 2 {
		sizes = append(sizes, size)
	}
	if heldBytes == 0 || len(sizes) == 0 {
		return 0, nil
	}
	scale := float64(total) / float64(heldBytes)

	// compressed is the size of the held-out files with dict, or without a
	// dictionary when dict is nil. Each call has its own encoder, at the
	// archive's level. A window of one sample gives the same result as a
	// window of a chunk, in less memory.
	compressed := func(dict []byte) (int, error) {
		enc, err := codec.NewEncoderWith(w.codecName, w.params, codec.EncoderOptions{Concurrency: 1, Dict: dict, MaxChunk: sampleSize})
		if err != nil {
			return 0, err
		}
		defer enc.Close()
		n := 0
		var buf []byte
		for _, s := range held {
			if buf, err = enc.Encode(buf[:0], s); err != nil {
				return 0, err
			}
			n += len(buf)
		}
		return n, nil
	}
	base, err := compressed(nil)
	if err != nil {
		return 0, err
	}

	// The candidates start in order of size. At most w.concurrency run at
	// once: that is -j, bounded by memory, as for the compression. A
	// candidate starts only when all those trialLookahead places before it
	// are done, and have not stopped the measurement. The training time
	// doubles with each size, so a candidate past the stop point costs as
	// much as all the smaller ones together: no more than one runs.
	trials := make([]dictTrial, len(sizes))
	type result struct {
		i   int
		err error
	}
	results := make(chan result)
	run := func(i int) {
		size := sizes[i]
		trials[i].size = size
		dict, err := codec.TrainDict(w.codecName, w.params, pick(training, trialFactor*size), size, trialID)
		if err != nil {
			results <- result{i, nil} // a candidate that cannot be trained has no gain
			return
		}
		n, err := compressed(dict)
		if err == nil {
			trials[i].net = float64(base-n)*scale - float64(len(dict))
			trials[i].ok = true
		}
		results <- result{i, err}
	}
	slots := max(1, w.concurrency)
	done := make([]bool, len(sizes))
	next, running, prefix := 0, 0, 0
	var firstErr error
	best, stop := 0, false
	for {
		for !stop && firstErr == nil && next < len(sizes) && next < prefix+trialLookahead && running < slots {
			go run(next)
			next, running = next+1, running+1
		}
		if running == 0 {
			break
		}
		r := <-results
		running--
		done[r.i] = true
		if r.err != nil && firstErr == nil {
			firstErr = r.err
		}
		for prefix < len(sizes) && done[prefix] {
			prefix++
		}
		best, stop = bestTrial(trials[:prefix])
	}
	if firstErr != nil {
		return 0, firstErr
	}
	return best, nil
}

// bestTrial walks the trials in order of size, and returns the size with the
// largest net gain, or 0 when none gains. A larger size must add more than
// trialMargin to the best gain: the measurement varies by about 1% from run
// to run, and below that, the smaller dictionary is as good and is cheaper.
// It stops at the second trial in a row that does not improve on the best,
// and says so.
func bestTrial(trials []dictTrial) (best int, stop bool) {
	bestNet, misses := 0.0, 0
	for _, t := range trials {
		if t.ok && t.net > 0 && t.net > bestNet*(1+trialMargin) {
			best, bestNet, misses = t.size, t.net, 0
			continue
		}
		if misses++; misses == 2 {
			return best, true
		}
	}
	return best, false
}

// pick keeps every k-th sample, with the smallest k that keeps the samples
// within the budget of bytes.
func pick(samples [][]byte, budget int) [][]byte {
	sizes := make([]int, len(samples))
	for i, s := range samples {
		sizes[i] = len(s)
	}
	var out [][]byte
	for _, i := range pickSamples(sizes, budget) {
		out = append(out, samples[i])
	}
	return out
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
//
// It walks two times. The first walk counts the files and their sizes, which
// decide k. The second reads the files that k selects. A file is read while
// the walk holds its directory, as the capture reads it, so that a directory
// that became a link does not put another file into the dictionary
// (doc/Security_Audit.md, finding 11). A tree that changes between the two
// walks costs ratio only.
func sampleTree(w *Writer, cfg CreateConfig, budget int) ([][]byte, int, error) {
	oldArchive, oldErr := os.Stat(cfg.Archive)
	walkFiles := func(visit func(e entry, n int)) {
		wk := newWalker(walkOptions{
			baseDir:       cfg.BaseDir,
			dereference:   cfg.Dereference,
			exclude:       cfg.Exclude,
			regex:         cfg.Regex,
			excludeRegex:  cfg.ExcludeRegex,
			oneFileSystem: cfg.OneFileSystem,
			// The walk that archives reports what cannot be read; the
			// sample goes on without it.
			onError: func(string, error) error { return nil },
		}, func(e entry) error {
			if e.Kind != kindFile || e.Info.Size() == 0 || w.SameFile(e.Info) ||
				(oldErr == nil && os.SameFile(e.Info, oldArchive)) {
				return nil
			}
			visit(e, int(min(e.Info.Size(), sampleSize)))
			return nil
		})
		for _, p := range cfg.Paths {
			wk.Walk(p)
		}
	}

	var sizes []int
	total := 0
	walkFiles(func(_ entry, n int) {
		sizes = append(sizes, n)
		total += n
	})
	picked := map[int]bool{}
	for _, i := range pickSamples(sizes, budget) {
		picked[i] = true
	}

	var samples [][]byte
	i := 0
	walkFiles(func(e entry, n int) {
		defer func() { i++ }()
		if !picked[i] {
			return
		}
		// As the capture does: a link put there after the walk is not
		// followed, or its target would go into the dictionary.
		f, err := openWalked(e)
		if err != nil {
			return
		}
		buf := make([]byte, n)
		got, _ := io.ReadFull(f, buf)
		f.Close()
		if got > 0 {
			samples = append(samples, buf[:got])
		}
	})
	return samples, total, nil
}

// sampleMembers is the pass before --recompress with a dictionary: the start
// of each kept member's content, decoded.
func sampleMembers(r *Reader, keep []format.Member, budget int) ([][]byte, int, error) {
	var members []format.Member
	var sizes []int
	total := 0
	for _, m := range keep {
		if m.Type.HasPayload() && m.PayloadSize() > 0 {
			members = append(members, m)
			sizes = append(sizes, int(min(m.PayloadSize(), sampleSize)))
			total += sizes[len(sizes)-1]
		}
	}
	var samples [][]byte
	for _, i := range pickSamples(sizes, budget) {
		s := &sampleWriter{buf: make([]byte, 0, sizes[i])}
		if err := r.WriteMember(&members[i], s); err != nil && !errors.Is(err, errEnoughSample) {
			return nil, 0, err
		}
		samples = append(samples, s.buf)
	}
	return samples, total, nil
}

// pickSamples chooses which of the files to sample: all of them, or every
// k-th one, with the smallest k that keeps the samples within the budget of
// bytes.
func pickSamples(sizes []int, budget int) []int {
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
