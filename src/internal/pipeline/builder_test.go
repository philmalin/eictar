package pipeline

import (
	"errors"
	"io"
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
// returned in time: the failure it looks for is a hang.
func addWithin(t *testing.T, b *Builder, r io.Reader) {
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
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the builder hung: the reader is waiting for budget that only its own member can give back")
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
