package archive

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/philmalin/eictar/src/internal/codec"
	"github.com/philmalin/eictar/src/internal/crypt"
	"github.com/philmalin/eictar/src/internal/format"
	"github.com/philmalin/eictar/src/internal/testutil"
)

// Tests of dict.go that the tests of the dictionaries do not reach: the
// parts of the measurement of train=auto, the samples, and the checks of a
// dictionary that is read.

// jsonSamples are similar records, for which a dictionary pays.
func jsonSamples() (samples [][]byte, total int) {
	for i := range 400 {
		s := []byte(fmt.Sprintf(
			"{\"id\": %d, \"type\": \"order\", \"status\": \"%s\", \"items\": [{\"sku\": \"SKU-%06d\", \"quantity\": %d}], \"shipping\": {\"method\": \"ground\", \"country\": \"AU\"}}\n",
			i, []string{"pending", "paid", "shipped"}[i%3], i*7919%1000000, i%9))
		samples = append(samples, s)
		total += len(s)
	}
	return samples, total
}

// TestUseDictionaryBudget: the budget of the samples is a hundred times the
// size that train=SIZE gives, and a hundred times the largest size for
// train=auto. With no samples, the writer goes on without a dictionary, and
// says why.
func TestUseDictionaryBudget(t *testing.T) {
	for _, tc := range []struct {
		train  string
		budget int
		warn   string
	}{
		{"16K", sampleFactor * 16 << 10, "there are no files to learn from"},
		{"auto", sampleFactor * format.MaxDictSize, "saves less than its own size"},
	} {
		w := &Writer{codecName: "zstd", params: codec.Params{"train": tc.train}}
		budget := 0
		rep := &recordingReporter{}
		err := w.useDictionary(func(b int) ([][]byte, int, error) { budget = b; return nil, 0, nil }, rep.Warn)
		if err != nil || budget != tc.budget {
			t.Errorf("train=%s: %v, budget %d; want %d", tc.train, err, budget, tc.budget)
		}
		if len(rep.warnings) != 1 || !strings.Contains(rep.warnings[0], tc.warn) {
			t.Errorf("train=%s: warnings %q, want %q", tc.train, rep.warnings, tc.warn)
		}
		if len(w.index.Dicts) != 0 {
			t.Errorf("train=%s: dictionaries %+v", tc.train, w.index.Dicts)
		}
	}
}

// failingEncoder is an encoder whose Encode fails.
type failingEncoder struct{ codec.Encoder }

func (failingEncoder) Encode([]byte, []byte) ([]byte, error) {
	return nil, errors.New("the encoder failed")
}

// TestChooseDictSizeFaults: a fault of the encoder of the measurement stops
// the create with that fault, whether it builds the encoder, encodes the
// files, or encodes them with a candidate dictionary.
func TestChooseDictSizeFaults(t *testing.T) {
	samples, total := jsonSamples()
	saved := trialEncoder
	t.Cleanup(func() { trialEncoder = saved })
	for name, enc := range map[string]func(string, codec.Params, codec.EncoderOptions) (codec.Encoder, error){
		"build": func(string, codec.Params, codec.EncoderOptions) (codec.Encoder, error) {
			return nil, errors.New("the encoder failed")
		},
		"encode": func(n string, p codec.Params, o codec.EncoderOptions) (codec.Encoder, error) {
			e, err := saved(n, p, o)
			return failingEncoder{e}, err
		},
		"encode without a dictionary": func(n string, p codec.Params, o codec.EncoderOptions) (codec.Encoder, error) {
			e, err := saved(n, p, o)
			if o.Dict != nil {
				return e, err
			}
			return failingEncoder{e}, err
		},
		"encode with a dictionary": func(n string, p codec.Params, o codec.EncoderOptions) (codec.Encoder, error) {
			e, err := saved(n, p, o)
			if o.Dict == nil {
				return e, err
			}
			return failingEncoder{e}, err
		},
	} {
		trialEncoder = enc
		w := &Writer{codecName: "zstd", params: codec.Params{"train": "on"}, concurrency: 4}
		err := w.useDictionary(func(int) ([][]byte, int, error) { return samples, total, nil }, nil)
		if err == nil || !strings.Contains(err.Error(), "the encoder failed") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestTrialParts: the held-out samples, the candidate sizes and the net
// gain.
func TestTrialParts(t *testing.T) {
	var samples [][]byte
	for i := range 8 {
		samples = append(samples, []byte{byte(i)})
	}
	training, held := splitHeldOut(samples)
	if !slices.EqualFunc(held, [][]byte{{3}, {7}}, bytes.Equal) || len(training) != 6 || training[3][0] != 4 {
		t.Errorf("held out %v, training %v", held, training)
	}

	for _, tc := range []struct {
		total int
		want  []int
	}{
		{0, nil},
		{8<<10 - 1, nil},
		{8 << 10, []int{4 << 10}},
		{32<<10 - 1, []int{4 << 10, 8 << 10}},
		{1 << 30, []int{4 << 10, 8 << 10, 16 << 10, 32 << 10, 64 << 10, 128 << 10, 256 << 10, 512 << 10, 1 << 20}},
	} {
		if got := trialSizes(tc.total); !slices.Equal(got, tc.want) {
			t.Errorf("trialSizes(%d) = %v, want %v", tc.total, got, tc.want)
		}
	}

	// 100 bytes saved on 1,000 held-out bytes, which stand for 4,000.
	if got := netGain(500, 400, 50, 4000, 1000); got != 350 {
		t.Errorf("netGain = %v, want 350", got)
	}
}

// TestRunTrials: each candidate runs once, at most slots at once and at
// most trialLookahead places past the first that is not done. The first
// error stops the measurement.
func TestRunTrials(t *testing.T) {
	gain := func(i int) dictTrial { return dictTrial{size: 1 << i, net: float64(100 * (i + 1)), ok: true} }

	t.Run("all", func(t *testing.T) {
		var mu sync.Mutex
		var ran []int
		best, err := runTrials(5, 8, func(i int) (dictTrial, error) {
			mu.Lock()
			ran = append(ran, i)
			mu.Unlock()
			return gain(i), nil
		})
		slices.Sort(ran)
		if err != nil || best != 16 || !slices.Equal(ran, []int{0, 1, 2, 3, 4}) {
			t.Errorf("best %d, %v, ran %v", best, err, ran)
		}
	})

	// gated starts the trials, and lets each end when the test says.
	type gated struct {
		started chan int
		release [5]chan struct{}
	}
	start := func(slots int) (*gated, chan error) {
		g := &gated{started: make(chan int, 5)}
		for i := range g.release {
			g.release[i] = make(chan struct{})
		}
		done := make(chan error, 1)
		go func() {
			_, err := runTrials(5, slots, func(i int) (dictTrial, error) {
				g.started <- i
				<-g.release[i]
				return gain(i), nil
			})
			done <- err
		}()
		return g, done
	}
	none := func(t *testing.T, g *gated, what string) {
		t.Helper()
		select {
		case i := <-g.started:
			t.Errorf("%s: candidate %d started", what, i)
		case <-time.After(100 * time.Millisecond):
		}
	}
	finish := func(g *gated, done chan error) {
		for i := range g.release {
			select {
			case <-g.release[i]:
			default:
				close(g.release[i])
			}
		}
		<-done
	}

	t.Run("lookahead", func(t *testing.T) {
		g, done := start(8)
		defer finish(g, done)
		got := []int{<-g.started, <-g.started}
		slices.Sort(got)
		if !slices.Equal(got, []int{0, 1}) {
			t.Fatalf("started %v", got)
		}
		close(g.release[1]) // the first is not done: no more start
		none(t, g, "candidate 0 not done")
		close(g.release[0])
		got = []int{<-g.started, <-g.started}
		slices.Sort(got)
		if !slices.Equal(got, []int{2, 3}) {
			t.Errorf("then started %v", got)
		}
	})

	t.Run("slots", func(t *testing.T) {
		g, done := start(1)
		defer finish(g, done)
		if i := <-g.started; i != 0 {
			t.Fatalf("started %d", i)
		}
		none(t, g, "one slot, in use")
	})

	t.Run("errors", func(t *testing.T) {
		e0, e1 := errors.New("first"), errors.New("second")
		_, err := runTrials(5, 2, func(i int) (dictTrial, error) {
			switch i {
			case 0:
				return dictTrial{}, e0
			case 1:
				time.Sleep(100 * time.Millisecond) // after the first
				return dictTrial{}, e1
			}
			t.Errorf("candidate %d started after an error", i)
			return gain(i), nil
		})
		if err != e0 {
			t.Errorf("both fail: %v, want %v", err, e0)
		}
		_, err = runTrials(5, 1, func(i int) (dictTrial, error) {
			if i == 1 {
				return dictTrial{}, e1
			}
			return gain(i), nil
		})
		if err != e1 {
			t.Errorf("the second fails: %v, want %v", err, e1)
		}
	})
}

// TestBestTrialAtTheMargin: a larger size that adds exactly the margin does
// not win.
func TestBestTrialAtTheMargin(t *testing.T) {
	trials := []dictTrial{{size: 4, net: 50, ok: true}, {size: 8, net: 50 * (1 + trialMargin), ok: true}}
	if best, _ := bestTrial(trials); best != 4 {
		t.Errorf("best %d, want 4", best)
	}
}

// TestNewDictID: an id is outside the reserved range, and is not one that
// the archive has. A fault of the source of random bytes stops it.
func TestNewDictID(t *testing.T) {
	saved := dictIDSource
	t.Cleanup(func() { dictIDSource = saved })
	draws := [][]byte{{0, 0, 0, 0}, {0, 0, 0, 0}, {1, 0, 0, 0}}
	dictIDSource = func(b []byte) (int, error) {
		copy(b, draws[0])
		draws = draws[1:]
		return len(b), nil
	}
	w := &Writer{}
	if id, err := w.newDictID(); err != nil || id != 1<<15 {
		t.Errorf("zero bytes: %d, %v; want %d", id, err, 1<<15)
	}
	w.index.Dicts = []format.Dict{{ID: 1 << 15}}
	if id, err := w.newDictID(); err != nil || id != 1<<15|1 {
		t.Errorf("an id that is taken: %d, %v; want %d", id, err, 1<<15|1)
	}
	dictIDSource = func([]byte) (int, error) { return 0, errors.New("no random bytes") }
	if _, err := w.newDictID(); err == nil || !strings.Contains(err.Error(), "no random bytes") {
		t.Errorf("a fault: %v", err)
	}
}

// TestNewestDict: the latest generation wins, and of two in one
// generation, the later in the list.
func TestNewestDict(t *testing.T) {
	d := func(id uint32, gen uint64) format.Dict { return format.Dict{ID: id, Generation: gen} }
	for _, tc := range []struct {
		dicts []format.Dict
		want  uint32
	}{
		{[]format.Dict{d(1, 1), d(2, 2)}, 2},
		{[]format.Dict{d(1, 2), d(2, 1)}, 1},
		{[]format.Dict{d(1, 1), d(2, 1)}, 2},
	} {
		if got, ok := newestDict(tc.dicts); !ok || got.ID != tc.want {
			t.Errorf("%v: %d, %v; want %d", tc.dicts, got.ID, ok, tc.want)
		}
	}
	if _, ok := newestDict(nil); ok {
		t.Error("no dictionaries: want false")
	}
}

// TestTrainAtTheLimit: a dictionary of exactly the limit is kept, and one
// above it is not: the writer goes on without it, and says why.
func TestTrainAtTheLimit(t *testing.T) {
	tree := dictTree(t, "src", 60)
	saved := trainDict
	t.Cleanup(func() { trainDict = saved })
	for _, tc := range []struct {
		size  int
		dicts int
	}{{format.MaxDictSize, 1}, {format.MaxDictSize + 1, 0}} {
		// The content of a zstd dictionary is its end, which can be of any
		// length.
		trainDict = func(n string, p codec.Params, samples [][]byte, size int, id uint32) ([]byte, error) {
			d, err := saved(n, p, samples, size, id)
			return append(d, make([]byte, tc.size-len(d))...), err
		}
		rep := &recordingReporter{}
		archive := dictCreate(t, tree, false, trainParams, rep, "src")
		r := openDict(t, archive, false)
		if len(r.index.Dicts) != tc.dicts {
			t.Errorf("%d bytes: dictionaries %+v", tc.size, r.index.Dicts)
		}
		if tc.dicts == 0 && (len(rep.warnings) != 1 || !strings.Contains(rep.warnings[0], "above the")) {
			t.Errorf("%d bytes: warnings %q", tc.size, rep.warnings)
		}
		checkRoundTrip(t, archive, false, tree, "src")
	}
}

// TestLoadDictChecks: each check of a dictionary that is read. Each failure
// is its own error.
func TestLoadDictChecks(t *testing.T) {
	tree := dictTree(t, "src", 60)
	plain := openDict(t, dictCreate(t, tree, false, trainParams, nil, "src"), false)
	sealed := openDict(t, dictCreate(t, tree, true, trainParams, nil, "src"), true)
	pd, sd := plain.index.Dicts[0], sealed.index.Dicts[0]
	if _, err := loadDict(plain.f, nil, false, pd); err != nil {
		t.Fatal(err)
	}
	if _, err := loadDict(sealed.f, sealed.keys, true, sd); err != nil {
		t.Fatal(err)
	}

	short := sd
	short.Enc = &format.EncInfo{Salt: sd.Enc.Salt[:4]}
	size := pd
	size.Size++
	id := pd
	id.ID++
	for _, tc := range []struct {
		name string
		f    *Reader
		keys *crypt.Keys
		d    format.Dict
		want error
		text string
	}{
		{"sealed, no keys", sealed, nil, sd, nil, "no passphrase was supplied"},
		{"a salt of the wrong size", sealed, sealed.keys, short, format.ErrCorruptIndex, ""},
		{"the size", plain, nil, size, format.ErrCorruptIndex, ""},
		{"the id", plain, nil, id, format.ErrCorruptData, ""},
	} {
		_, err := loadDict(tc.f.f, tc.keys, tc.f.hdr.Encrypted(), tc.d)
		if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) || !strings.Contains(err.Error(), tc.text) {
			t.Errorf("%s: %v, want %v %q", tc.name, err, tc.want, tc.text)
		}
	}

	// A sealed dictionary that was changed fails its tag.
	raw := make([]byte, sd.Length)
	if _, err := sealed.f.ReadAt(raw, int64(sd.Offset)); err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 1
	moved := sd
	moved.Offset = 0
	if _, err := loadDict(bytes.NewReader(raw), sealed.keys, true, moved); !errors.Is(err, crypt.ErrAuthentication) {
		t.Errorf("a changed sealed dictionary: %v, want %v", err, crypt.ErrAuthentication)
	}
}

// TestDictForFindsItsID: of the dictionaries of the index, the reader loads
// the one that the codec names.
func TestDictForFindsItsID(t *testing.T) {
	tree := dictTree(t, "src", 60)
	r := openDict(t, dictCreate(t, tree, false, trainParams, nil, "src"), false)
	real := r.index.Dicts[0]
	other := real
	other.ID++ // its blob carries the id of the real one
	r.index.Dicts = []format.Dict{other, real}
	m := r.Members()[1]
	if m.Codec < 0 || r.index.Codecs[m.Codec].Dict != real.ID {
		t.Fatalf("member %s does not use the dictionary", m.Path)
	}
	if d, err := r.dictFor(&m); err != nil || len(d) != int(real.Size) {
		t.Errorf("%d bytes, %v", len(d), err)
	}
}

// sampleTreeOf makes the tree for the tests of sampleTree: four files of
// ten bytes, an empty file and a directory among them, and the old archive
// and the file that is being written in the same directory.
func sampleTreeOf(t *testing.T) (*testutil.Tree, *Writer, CreateConfig) {
	t.Helper()
	tree := testutil.NewTree(t)
	for _, n := range []string{"a", "b", "c", "d"} {
		tree.Text("s/"+n, 0o644, strings.Repeat(n, 10))
	}
	tree.Text("s/b0", 0o644, "")
	tree.Text("s/z/e", 0o644, "")
	tree.Text("s/out.ect", 0o644, "the old archive")
	cfg := CreateConfig{Archive: tree.Path("s/out.ect"), Paths: []string{"s"}, BaseDir: tree.Root}
	w, err := Create(cfg.Archive, Options{Codec: "zstd"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Abort() })
	return tree, w, cfg
}

// TestSampleTree: the samples are of the files with content, and not of the
// archive, old or new. Over the budget, every k-th file is read.
func TestSampleTree(t *testing.T) {
	_, w, cfg := sampleTreeOf(t)
	// The size from the open file: on Windows, a stat by path gives the size
	// that the directory has, which is behind while the file is open.
	if fi, err := w.f.Stat(); err != nil || fi.Size() == 0 {
		t.Fatalf("the file that is being written is empty (%v)", err)
	}
	// The same directory, by identity: Create resolves the path, and on
	// Windows that gives the long name of a directory of the short name.
	if !os.SameFile(mustStat(t, filepath.Dir(w.tmpPath)), mustStat(t, filepath.Dir(cfg.Archive))) {
		t.Fatalf("the file that is being written, %s, is not in the tree", w.tmpPath)
	}
	samples, total, err := sampleTree(w, cfg, 20)
	if err != nil || total != 40 || !slices.EqualFunc(samples, [][]byte{[]byte("aaaaaaaaaa"), []byte("cccccccccc")}, bytes.Equal) {
		t.Errorf("samples %q, total %d, %v; want a and c of 40 bytes", samples, total, err)
	}
}

// TestSampleTreeSkipsAFileThatFails: a file that does not read gives no
// sample, not an empty one.
func TestSampleTreeSkipsAFileThatFails(t *testing.T) {
	_, w, cfg := sampleTreeOf(t)
	var samples [][]byte
	err := withSrc(&faultFS{failOp: "read"}, &openSet{}, func() (err error) {
		samples, _, err = sampleTree(w, cfg, 20)
		return err
	})
	if err != nil || !slices.EqualFunc(samples, [][]byte{[]byte("cccccccccc")}, bytes.Equal) {
		t.Errorf("samples %q, %v; want c alone", samples, err)
	}
}

// TestSampleMembers: the samples of a recompression are of the members
// with content.
func TestSampleMembers(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Text("s/a", 0o644, "alpha")
	tree.Text("s/empty", 0o644, "")
	tree.Text("s/z/b", 0o644, "bravo")
	r := openDict(t, mkArchive(t, tree, false, "s"), false)
	samples, total, err := sampleMembers(r, r.Members(), 1<<20)
	if err != nil || total != 10 || !slices.EqualFunc(samples, [][]byte{[]byte("alpha"), []byte("bravo")}, bytes.Equal) {
		t.Errorf("samples %q, total %d, %v", samples, total, err)
	}
}

// TestSampleWriter: the writer keeps its capacity of bytes, and stops the
// decode when it is full, also when a write fills it exactly.
func TestSampleWriter(t *testing.T) {
	s := &sampleWriter{buf: make([]byte, 0, 5)}
	if n, err := s.Write([]byte("abc")); n != 3 || err != nil {
		t.Errorf("first write: %d, %v", n, err)
	}
	if n, err := s.Write([]byte("defgh")); n != 2 || err != errEnoughSample || string(s.buf) != "abcde" {
		t.Errorf("past the capacity: %d, %v, %q", n, err, s.buf)
	}
	s = &sampleWriter{buf: make([]byte, 0, 2)}
	if n, err := s.Write([]byte("ab")); n != 2 || err != errEnoughSample || string(s.buf) != "ab" {
		t.Errorf("exactly full: %d, %v, %q", n, err, s.buf)
	}
}

// TestChooseDictSizeWithNothingHeldOut: with fewer than heldOut samples,
// none is held out, and there is nothing to measure: no candidate is
// trained.
func TestChooseDictSizeWithNothingHeldOut(t *testing.T) {
	saved := trainDict
	t.Cleanup(func() { trainDict = saved })
	trained := 0
	trainDict = func(n string, p codec.Params, samples [][]byte, size int, id uint32) ([]byte, error) {
		trained++
		return saved(n, p, samples, size, id)
	}
	samples, _ := jsonSamples()
	w := &Writer{codecName: "zstd", params: codec.Params{"train": "on"}, concurrency: 1}
	if size, err := w.chooseDictSize(samples[:heldOut-1], 1<<20); size != 0 || err != nil || trained != 0 {
		t.Errorf("%d, %v, %d candidates trained; want none", size, err, trained)
	}
}

// TestTrainIDFault: a fault of the id costs the dictionary, and the
// writer says so.
func TestTrainIDFault(t *testing.T) {
	saved := dictIDSource
	t.Cleanup(func() { dictIDSource = saved })
	dictIDSource = func([]byte) (int, error) { return 0, errors.New("no random bytes") }
	samples, total := jsonSamples()
	w := &Writer{codecName: "zstd", params: codec.Params{"train": "16K"}}
	rep := &recordingReporter{}
	err := w.useDictionary(func(int) ([][]byte, int, error) { return samples, total, nil }, rep.Warn)
	if err != nil || len(w.index.Dicts) != 0 || len(rep.warnings) != 1 || !strings.Contains(rep.warnings[0], "no random bytes") {
		t.Errorf("%v, dictionaries %+v, warnings %q", err, w.index.Dicts, rep.warnings)
	}
}
