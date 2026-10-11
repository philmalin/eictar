package pipeline

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/philmalin/eictar/src/internal/codec"
	"github.com/philmalin/eictar/src/internal/crypt"
	"github.com/philmalin/eictar/src/internal/format"
)

// faults counts the operations of a build that can fail - each operation on
// a spill file, and each call to the encoder, to NewSealer and to Emit - and
// makes operation failAt fail (doc/design.md 13.5, step 3).
type faults struct {
	mu     sync.Mutex
	n      int
	failAt int
	failed string
	open   map[*faultSpill]bool
	// sticky makes each operation on a spill file after failAt fail too, as
	// a disk that is full stays full.
	sticky bool
}

func (fl *faults) step(op string) error {
	fl.mu.Lock()
	defer fl.mu.Unlock()
	fl.n++
	switch {
	case fl.failAt == 0 || fl.n < fl.failAt:
		return nil
	case fl.n > fl.failAt && !(fl.sticky && strings.HasPrefix(op, "spill ")):
		return nil
	}
	if fl.failed == "" {
		fl.failed = fmt.Sprintf("%s (operation %d)", op, fl.n)
	}
	errno := syscall.EIO
	if op == "spill write" {
		errno = syscall.ENOSPC
	}
	return fmt.Errorf("%s: %w", op, errno)
}

// faultSpill is a spill file of a faults.
type faultSpill struct {
	f  spillFile
	fl *faults
}

func (s *faultSpill) Read(p []byte) (int, error) {
	if err := s.fl.step("spill read"); err != nil {
		return 0, err
	}
	return s.f.Read(p)
}

// Write writes half of p before it fails, as a full disk does.
func (s *faultSpill) Write(p []byte) (int, error) {
	if err := s.fl.step("spill write"); err != nil {
		n, _ := s.f.Write(p[:len(p)/2])
		return n, err
	}
	return s.f.Write(p)
}

func (s *faultSpill) Seek(off int64, whence int) (int64, error) {
	if err := s.fl.step("spill seek"); err != nil {
		return 0, err
	}
	return s.f.Seek(off, whence)
}

func (s *faultSpill) Close() error {
	s.fl.mu.Lock()
	delete(s.fl.open, s)
	s.fl.mu.Unlock()
	err := s.fl.step("spill close")
	if cerr := s.f.Close(); err == nil {
		err = cerr
	}
	return err
}

type faultEncoder struct {
	codec.Encoder
	fl *faults
}

func (e faultEncoder) Encode(dst, src []byte) ([]byte, error) {
	if err := e.fl.step("encode"); err != nil {
		return nil, err
	}
	return e.Encoder.Encode(dst, src)
}

// faultMembers are the members of a faulted build: empty, one short chunk,
// several chunks, one that spills past the threshold, and chunks that do not
// compress and are stored.
func faultMembers() map[string][]byte {
	rng := rand.New(rand.NewPCG(1, 2))
	noise := make([]byte, 43000)
	for i := range noise {
		noise[i] = byte(rng.Uint32())
	}
	return map[string][]byte{
		"empty":  nil,
		"short":  []byte("one short chunk"),
		"chunks": []byte(strings.Repeat("several chunks of text. ", 200)),
		// Noise does not compress, so its spool grows past the threshold,
		// and fills a small budget.
		"spills": noise[3000:],
		"noise":  noise[:3000],
	}
}

const faultChunk = 1024

var faultKey = bytes.Repeat([]byte{7}, 32)

// faultRun is what a build gave.
type faultRun struct {
	addErr    map[string]error
	finishErr error
	emitted   map[string][][]byte // the chunks of each emitted member
	members   map[string]format.Member
	inUse     int64
}

// buildWithFaults builds the members of faultMembers with fl as the source of
// faults.
func buildWithFaults(t *testing.T, fl *faults, contents map[string][]byte, budgetSize int64) faultRun {
	t.Helper()
	enc, err := codec.NewEncoder("zstd", nil, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()

	newSpillFile = func(dir string) (spillFile, error) {
		if err := fl.step("spill create"); err != nil {
			return nil, err
		}
		f, err := createSpillFile(dir)
		if err != nil {
			return nil, err
		}
		s := &faultSpill{f: f, fl: fl}
		fl.mu.Lock()
		if fl.open == nil {
			fl.open = map[*faultSpill]bool{}
		}
		fl.open[s] = true
		fl.mu.Unlock()
		return s, nil
	}
	defer func() {
		newSpillFile = func(dir string) (spillFile, error) {
			f, err := createSpillFile(dir)
			if err != nil {
				return nil, err
			}
			return f, nil
		}
	}()

	run := faultRun{addErr: map[string]error{}, emitted: map[string][][]byte{}, members: map[string]format.Member{}}
	var mu sync.Mutex
	budget := NewBudget(budgetSize)
	b := New(Config{
		Workers: 3, ChunkSize: faultChunk, Budget: budget,
		SpillThreshold: 8 * faultChunk, SpillDir: t.TempDir(),
		Encoder: faultEncoder{enc, fl},
		NewSealer: func(m *format.Member) (*crypt.MemberSealer, error) {
			if err := fl.step("new sealer"); err != nil {
				return nil, err
			}
			return crypt.NewMemberSealer(faultKey, m.ID)
		},
		Emit: func(m *format.Member, payload io.WriterTo) error {
			if err := fl.step("emit"); err != nil {
				return err
			}
			var buf bytes.Buffer
			if payload != nil {
				if _, err := payload.WriteTo(&buf); err != nil {
					return err
				}
			}
			var chunks [][]byte
			rest := buf.Bytes()
			for _, n := range m.Chunks {
				if int(n) > len(rest) {
					t.Errorf("fault %s: %s was emitted with a chunk table longer than its payload", fl.failed, m.Path)
					return fmt.Errorf("%s: the chunk table is longer than the payload", m.Path)
				}
				chunks, rest = append(chunks, rest[:n]), rest[n:]
			}
			if len(rest) != 0 {
				t.Errorf("fault %s: %s was emitted with %d bytes after its last chunk", fl.failed, m.Path, len(rest))
				return fmt.Errorf("%s: %d bytes after the last chunk", m.Path, len(rest))
			}
			mu.Lock()
			defer mu.Unlock()
			if _, twice := run.emitted[m.Path]; twice {
				t.Errorf("%s was emitted two times", m.Path)
			}
			run.emitted[m.Path] = chunks
			run.members[m.Path] = *m
			return nil
		},
	})
	b.Start()

	done := make(chan struct{})
	go func() {
		defer close(done)
		var id uint64
		id++
		run.addErr["dir"] = b.AddMeta(format.Member{ID: id, Path: "dir", Type: format.TypeDir})
		for _, name := range []string{"empty", "short", "chunks", "spills", "noise"} {
			id++
			run.addErr[name] = b.AddFile(format.Member{ID: id, Path: name}, bytes.NewReader(contents[name]), sha256.New())
		}
		run.finishErr = b.Finish()
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatalf("fault %s: the build hung", fl.failed)
	}
	run.inUse = budget.InUse()
	return run
}

// payloadOf turns the emitted chunks of a member back into its content: each
// chunk is unsealed, and decompressed unless it has the length of its
// plaintext (doc/format.md 5).
func payloadOf(m format.Member, chunks [][]byte) ([]byte, error) {
	sealer, err := crypt.NewMemberSealer(faultKey, m.ID)
	if err != nil {
		return nil, err
	}
	dec, err := codec.NewDecoder("zstd", faultChunk)
	if err != nil {
		return nil, err
	}
	defer dec.Close()
	var out []byte
	for i, c := range chunks {
		plain, err := sealer.Open(nil, c, uint64(i), i == len(chunks)-1)
		if err != nil {
			return nil, err
		}
		want := faultChunk
		if i == len(chunks)-1 {
			want = int(m.Size) - i*faultChunk
		}
		if len(plain) != want {
			if plain, err = dec.Decode(nil, plain, want); err != nil {
				return nil, err
			}
		}
		out = append(out, plain...)
	}
	return out, nil
}

// TestPipelineFaults makes each operation of a build that can fail fail in
// turn. The build must not hang, must give back all its budget and close
// each spill file. A member whose AddFile failed is never emitted, and each
// member that is emitted has its exact content. A build that reports no
// error emits every member.
//
// It runs with a budget so small that the reader moves spools to disk, and
// with one so large that only the threshold does. A fault is one failed
// operation, or a disk that stays full: each operation on a spill file after
// it fails too.
func TestPipelineFaults(t *testing.T) {
	contents := faultMembers()
	members := len(contents) + 1 // and the directory
	for _, budget := range []int64{6 * faultChunk, 1 << 20} {
		for _, sticky := range []bool{false, true} {
			t.Run(fmt.Sprintf("budget=%d, sticky=%v", budget, sticky), func(t *testing.T) {
				count := &faults{}
				run := buildWithFaults(t, count, contents, budget)
				if run.finishErr != nil || len(run.emitted) != members {
					t.Fatalf("with no fault: %v, %d members emitted", run.finishErr, len(run.emitted))
				}
				t.Logf("%d operations", count.n)
				for k := 1; k <= count.n; k++ {
					fl := &faults{failAt: k, sticky: sticky}
					checkFaultRun(t, fl, buildWithFaults(t, fl, contents, budget), contents, members)
				}
			})
		}
	}
}

func checkFaultRun(t *testing.T, fl *faults, run faultRun, contents map[string][]byte, members int) {
	t.Helper()
	what := fl.failed
	if what == "" {
		what = fmt.Sprintf("%d (it did not occur)", fl.failAt)
	}
	if run.inUse != 0 {
		t.Errorf("fault %s: %d bytes of budget stay held", what, run.inUse)
	}
	if len(fl.open) != 0 {
		t.Errorf("fault %s: %d spill files stay open", what, len(fl.open))
	}
	allOK := run.finishErr == nil && run.addErr["dir"] == nil
	for name, content := range contents {
		chunks, emitted := run.emitted[name]
		if run.addErr[name] != nil {
			allOK = false
			if emitted {
				t.Errorf("fault %s: %s was emitted, but its AddFile failed: %v", what, name, run.addErr[name])
			}
			continue
		}
		if !emitted {
			continue
		}
		m := run.members[name]
		got, err := payloadOf(m, chunks)
		digest := sha256.Sum256(content)
		if err != nil || !bytes.Equal(got, content) || m.Size != uint64(len(content)) || !bytes.Equal(m.Digest, digest[:]) {
			t.Errorf("fault %s: %s was emitted with the wrong content (%d bytes, size %d, want %d): %v",
				what, name, len(got), m.Size, len(content), err)
		}
	}
	if allOK && len(run.emitted) != members {
		t.Errorf("fault %s: the build reported no error, but emitted %d members of %d", what, len(run.emitted), members)
	}
	if !allOK && fl.failed == "" {
		t.Errorf("fault %s: an error with no fault: %v", what, run.finishErr)
	}
}

// TestEmitFailsDuringARead: when Emit fails for one member while another is
// read, the build stops. The member being read must give an error, and must
// not be emitted after the failure.
func TestEmitFailsDuringARead(t *testing.T) {
	failed := errors.New("emit failed")
	var emitted []string
	reading := make(chan struct{})
	budget := NewBudget(1 << 20)
	b := New(Config{
		Workers: 2, ChunkSize: 512, Budget: budget, SpillThreshold: 1 << 20, SpillDir: t.TempDir(), Stored: true,
		Emit: func(m *format.Member, _ io.WriterTo) error {
			emitted = append(emitted, m.Path)
			if m.Path == "first" {
				<-reading // the failure comes while the second member is read
				return failed
			}
			return nil
		},
	})
	b.Start()
	if err := b.AddFile(format.Member{Path: "first"}, strings.NewReader("small"), nil); err != nil {
		t.Fatal(err)
	}
	// The first member is emitted, and fails, while this one is read.
	err := b.AddFile(format.Member{Path: "second"}, &signalReader{r: &pacedReader{chunk: 512, left: 40}, first: reading}, nil)
	if !errors.Is(err, failed) {
		t.Errorf("the member read during the failure: %v, want the error of Emit", err)
	}
	if err := b.Finish(); !errors.Is(err, failed) {
		t.Errorf("Finish: %v, want the error of Emit", err)
	}
	if len(emitted) != 1 || budget.InUse() != 0 {
		t.Errorf("emitted %v, %d bytes of budget held", emitted, budget.InUse())
	}
}

// signalReader closes first at its first Read.
type signalReader struct {
	r     io.Reader
	first chan struct{}
	once  sync.Once
}

func (s *signalReader) Read(p []byte) (int, error) {
	s.once.Do(func() { close(s.first) })
	return s.r.Read(p)
}

// gateReader gives a full chunk and then a short one. Its first Read waits
// until the build has failed, so that both chunks are submitted after the
// failure.
type gateReader struct {
	b       *Builder
	reading chan struct{}
	reads   int
}

func (g *gateReader) Read(p []byte) (int, error) {
	g.reads++
	switch g.reads {
	case 1:
		close(g.reading)
		for g.b.Err() == nil {
			time.Sleep(time.Millisecond)
		}
		return len(p), nil
	case 2:
		return 100, io.EOF
	}
	return 0, io.EOF
}

// TestNoChunkAfterTheBuildStopped: once the build has failed, no chunk is
// submitted, so a member read during the failure always gets the error, and
// is never emitted. A select chose at random between the queue and the stop,
// and with two chunks to submit, one run in four took the queue both times.
func TestNoChunkAfterTheBuildStopped(t *testing.T) {
	failed := errors.New("emit failed")
	for range 40 {
		var b *Builder
		var emitted []string
		gate := &gateReader{reading: make(chan struct{})}
		b = New(Config{
			Workers: 2, ChunkSize: 512, Budget: NewBudget(1 << 20), SpillThreshold: 1 << 20, SpillDir: t.TempDir(), Stored: true,
			Emit: func(m *format.Member, _ io.WriterTo) error {
				emitted = append(emitted, m.Path)
				if m.Path == "first" {
					<-gate.reading
					return failed
				}
				return nil
			},
		})
		gate.b = b
		b.Start()
		if err := b.AddFile(format.Member{Path: "first"}, strings.NewReader("small"), nil); err != nil {
			t.Fatal(err)
		}
		if err := b.AddFile(format.Member{Path: "second"}, gate, nil); !errors.Is(err, failed) {
			t.Fatalf("the member read during the failure: %v, want the error of Emit", err)
		}
		b.Finish()
		if len(emitted) != 1 {
			t.Fatalf("emitted %v after the failure", emitted)
		}
	}
}
