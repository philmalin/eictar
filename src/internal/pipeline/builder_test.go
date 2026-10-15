package pipeline

import (
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/philmalin/eictar/src/internal/codec"
	"github.com/philmalin/eictar/src/internal/format"
)

// failingReader gives limit bytes, then an I/O error.
type failingReader struct{ n, limit int }

var errDisk = errors.New("input/output error")

func (f *failingReader) Read(p []byte) (int, error) {
	if f.n >= f.limit {
		return 0, errDisk
	}
	p = p[:min(len(p), f.limit-f.n)]
	for i := range p {
		p[i] = byte(f.n + i)
	}
	f.n += len(p)
	return len(p), nil
}

// slowEncoder keeps chunks in the workers long enough for the reader to
// fail while they are still there.
type slowEncoder struct{ codec.Encoder }

func (s slowEncoder) Encode(dst, src []byte) ([]byte, error) {
	time.Sleep(10 * time.Millisecond)
	return s.Encoder.Encode(dst, src)
}

// TestReadErrorWithChunksInFlight: a read that fails after some chunks are
// already in the workers must fail the member, not crash the process. The
// abandoned member's spool used to be set to nil under the workers, and the
// next chunk to land dereferenced it.
func TestReadErrorWithChunksInFlight(t *testing.T) {
	enc, err := codec.NewEncoder("zstd", nil, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()

	var emitted atomic.Int32
	budget := NewBudget(1 << 20)
	b := New(Config{
		Workers: 4, ChunkSize: 1024, Budget: budget, SpillThreshold: 1 << 20,
		Encoder: slowEncoder{enc},
		Emit: func(m *format.Member, _ io.WriterTo) error {
			emitted.Add(1)
			return nil
		},
	})
	b.Start()

	for range 20 {
		err := b.AddFile(format.Member{Path: "x"}, &failingReader{limit: 8 * 1024}, nil)
		if !errors.Is(err, errDisk) {
			t.Fatalf("AddFile = %v, want the read error", err)
		}
	}
	if err := b.Finish(); err != nil {
		t.Fatalf("Finish = %v; a failed member is the caller's to report", err)
	}
	if n := emitted.Load(); n != 0 {
		t.Errorf("%d failed members were emitted", n)
	}
	if n := budget.InUse(); n != 0 {
		t.Errorf("%d bytes of budget still held after the run", n)
	}
}

// pacedReader gives one chunk for each Read, after a pause, so that the
// workers have finished and spooled every earlier chunk before the next one
// is read. That makes the order of events the same on every run.
type pacedReader struct {
	chunk, left int
}

func (p *pacedReader) Read(b []byte) (int, error) {
	if p.left == 0 {
		return 0, io.EOF
	}
	time.Sleep(5 * time.Millisecond)
	n := min(len(b), p.chunk)
	for i := range b[:n] {
		b[i] = byte(i)
	}
	p.left--
	return n, nil
}

// addWithin runs AddFile and Finish, and fails the test if they have not
// returned in time or give an error: the failure it looks for is a hang.
func addWithin(t *testing.T, b *Builder, r io.Reader) {
	t.Helper()
	if err := addOrFail(t, b, r); err != nil {
		t.Fatal(err)
	}
}

// addOrFail runs AddFile and Finish, and returns the first error. It fails
// the test if they have not returned in time.
func addOrFail(t *testing.T, b *Builder, r io.Reader) error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		err := b.AddFile(format.Member{Path: "f"}, r, nil)
		if ferr := b.Finish(); err == nil {
			err = ferr
		}
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(20 * time.Second):
		t.Fatal("the builder hung: the reader is waiting for budget that only its own member can give back")
		return nil
	}
}

// TestReaderDoesNotWaitOnItsOwnSpool: the finished chunks of the member being
// read sit in its spool and hold budget. When they fill the budget, the
// reader used to wait for them, and they for the reader, for ever. It hung a
// create with 2 workers and 512-byte chunks; with the defaults, a file of 24
// to 32 MiB on a two-CPU machine could hang the same way.
func TestReaderDoesNotWaitOnItsOwnSpool(t *testing.T) {
	const chunk = 512
	var got int64
	b := New(Config{
		Workers: 2, ChunkSize: chunk, Budget: NewBudget(4 * chunk),
		SpillThreshold: 1 << 20, // large: only budget pressure can move the spool to disk
		SpillDir:       t.TempDir(),
		Stored:         true,
		Emit: func(m *format.Member, payload io.WriterTo) error {
			n, err := payload.WriteTo(io.Discard)
			got = n
			return err
		},
	})
	b.Start()
	addWithin(t, b, &pacedReader{chunk: chunk, left: 40})
	if got != 40*chunk {
		t.Errorf("emitted %d bytes, want %d", got, 40*chunk)
	}
}

// TestMemberCompletesInEitherOrder: a member is complete when the reader has
// dropped its claim and every chunk is in the spool. Either one can come
// last. In a build, the last chunk usually settles after the reader is done,
// so a fault in release showed only by chance of timing: a mutant of the
// check in release survived one run of make mutate, and no other.
func TestMemberCompletesInEitherOrder(t *testing.T) {
	for _, readerLast := range []bool{true, false} {
		mb := &memberBuild{
			spool:   NewSpool(NewBudget(1<<20), 1<<20, t.TempDir()),
			pending: map[int][]byte{},
			left:    3, // the reader's claim, and two chunks
		}
		done := make(chan *memberBuild, 1)
		mb.settle(1, []byte("b"), done) // early: it waits for chunk 0
		if readerLast {
			mb.settle(0, []byte("a"), done)
			mb.release(done)
		} else {
			mb.release(done)
			mb.settle(0, []byte("a"), done)
		}
		select {
		case got := <-done:
			if got != mb || len(mb.lengths) != 2 {
				t.Errorf("reader last %v: the member completed with %d chunks", readerLast, len(mb.lengths))
			}
		default:
			t.Errorf("reader last %v: the member never completed", readerLast)
		}
		mb.close()
	}
}

// TestFailedSpillDoesNotHang: when the budget is full, the reader moves its
// member's spool to disk, and then waits for budget. If the spill fails, the
// spool keeps its budget, and the wait never ends. A spill fails on a full
// disk, and failed every spill on Windows: the run hung, with no error.
func TestFailedSpillDoesNotHang(t *testing.T) {
	const chunk = 512
	budget := NewBudget(4 * chunk)
	b := New(Config{
		Workers: 2, ChunkSize: chunk, Budget: budget,
		SpillThreshold: 1 << 20, // large: only budget pressure can move the spool to disk
		SpillDir:       filepath.Join(t.TempDir(), "missing"),
		Stored:         true,
		Emit:           func(*format.Member, io.WriterTo) error { return nil },
	})
	b.Start()
	err := addOrFail(t, b, &pacedReader{chunk: chunk, left: 40})
	if err == nil || !strings.Contains(err.Error(), "spill") {
		t.Fatalf("err = %v, want the failure of the spill", err)
	}
	if n := budget.InUse(); n != 0 {
		t.Errorf("%d bytes of budget still held", n)
	}
}

// TestBudgetBelowTwoChunks: the reader holds one chunk while it waits for the
// next, so a budget below two chunks can never be met. It is raised to two.
func TestBudgetBelowTwoChunks(t *testing.T) {
	const chunk = 512
	budget := NewBudget(chunk + chunk/2)
	b := New(Config{
		Workers: 2, ChunkSize: chunk, Budget: budget, SpillThreshold: 1 << 20,
		SpillDir: t.TempDir(), Stored: true,
		Emit: func(*format.Member, io.WriterTo) error { return nil },
	})
	b.Start()
	addWithin(t, b, &pacedReader{chunk: chunk, left: 5})
	if n := budget.InUse(); n != 0 {
		t.Errorf("%d bytes of budget still held", n)
	}
}

// sameLengthEncoder gives an output as long as its input.
type sameLengthEncoder struct{ codec.Encoder }

func (sameLengthEncoder) Encode(dst, src []byte) ([]byte, error) {
	return append(dst, bytes.Repeat([]byte{0xff}, len(src))...), nil
}

// TestCompressionMustBeShorter: a reader takes a chunk of the length of its
// plaintext as stored (doc/format.md 5). So a compressed chunk that is not
// shorter must not be kept: the plaintext goes in its place.
func TestCompressionMustBeShorter(t *testing.T) {
	plain := []byte(strings.Repeat("x", 1000))
	var got bytes.Buffer
	b := New(Config{
		ChunkSize: 1024, Encoder: sameLengthEncoder{},
		Emit: func(_ *format.Member, payload io.WriterTo) error {
			_, err := payload.WriteTo(&got)
			return err
		},
	})
	b.Start()
	if err := b.AddFile(format.Member{Path: "f"}, bytes.NewReader(plain), nil); err != nil {
		t.Fatal(err)
	}
	if err := b.Finish(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), plain) {
		t.Error("a compressed chunk as long as its plaintext was kept")
	}
}

// TestNewDefaults: no workers means one, and no budget means an unlimited
// one.
func TestNewDefaults(t *testing.T) {
	var n int
	b := New(Config{ChunkSize: 512, Stored: true, Emit: func(m *format.Member, _ io.WriterTo) error {
		n++
		return nil
	}})
	if b.cfg.Workers != 1 || b.cfg.Budget == nil {
		t.Fatalf("workers %d, budget %v", b.cfg.Workers, b.cfg.Budget)
	}
	b.Start()
	if err := b.AddFile(format.Member{Path: "f"}, strings.NewReader("content"), nil); err != nil {
		t.Fatal(err)
	}
	if err := b.Finish(); err != nil || n != 1 {
		t.Fatalf("Finish: %v, %d members", err, n)
	}
}

// TestSparseFileThatChanged: the data map of a sparse file says how many
// bytes the read gives. Another number means that the file changed while it
// was read, and the member is refused, not stored with a map that does not
// describe it.
func TestSparseFileThatChanged(t *testing.T) {
	for _, data := range []string{"short", strings.Repeat("too long ", 200)} {
		emitted := 0
		budget := NewBudget(1 << 20)
		b := New(Config{
			Workers: 2, ChunkSize: 512, Budget: budget, Stored: true,
			Emit: func(*format.Member, io.WriterTo) error { emitted++; return nil },
		})
		b.Start()
		m := format.Member{Path: "sparse", Size: 1 << 20,
			Sparse: []format.SparseSegment{{Offset: 0, Length: 100}, {Offset: 1 << 19, Length: 100}}}
		err := b.AddFile(m, strings.NewReader(data), nil)
		if err == nil || !strings.Contains(err.Error(), "changed while it was read") {
			t.Errorf("%d bytes for a map of 200: got %v", len(data), err)
		}
		if err := b.Finish(); err != nil {
			t.Errorf("Finish: %v; a refused member is the caller's to report", err)
		}
		if emitted != 0 || budget.InUse() != 0 {
			t.Errorf("%d members emitted, %d bytes of budget held", emitted, budget.InUse())
		}
	}
}
