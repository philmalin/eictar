package pipeline

import (
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"eictar/src/internal/codec"
	"eictar/src/internal/format"
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
