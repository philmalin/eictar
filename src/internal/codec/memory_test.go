package codec

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestZstdWindowFitsTheChunk: a window larger than a chunk holds nothing, so
// the encoder caps it at the chunk, rounded up to a power of 2. At long=27
// that saves 260 MB for each state (doc/design.md 8.2). The test measures
// the memory of one state, which is what the cap is for.
func TestZstdWindowFitsTheChunk(t *testing.T) {
	src := make([]byte, 100<<10)
	allocated := func(o EncoderOptions) uint64 {
		runtime.GC()
		var a, b runtime.MemStats
		runtime.ReadMemStats(&a)
		enc, err := NewEncoderWith("zstd", Params{"level": "12", "long": "27"}, o)
		if err != nil {
			t.Fatal(err)
		}
		enc.Encode(nil, src)
		runtime.ReadMemStats(&b)
		enc.Close()
		return b.TotalAlloc - a.TotalAlloc
	}
	capped := allocated(EncoderOptions{Concurrency: 1, MaxChunk: 4 << 20})
	full := allocated(EncoderOptions{Concurrency: 1})
	if capped > 100<<20 || full < 200<<20 {
		t.Errorf("one state at long=27: %d MB with 4 MiB chunks, %d MB with no chunk size; want under 100 and over 200",
			capped>>20, full>>20)
	}

	// The result does not change: the chunk is inside the window either way.
	chunk := make([]byte, 1<<20)
	for i := range chunk {
		chunk[i] = byte(i * 7 % 251)
	}
	dec, _ := NewDecoder("zstd", 1<<20)
	defer dec.Close()
	for _, o := range []EncoderOptions{{MaxChunk: 1 << 20}, {}} {
		enc, _ := NewEncoderWith("zstd", Params{"long": "27"}, o)
		out, _ := enc.Encode(nil, chunk)
		enc.Close()
		if got, err := dec.Decode(nil, out, len(chunk)); err != nil || len(got) != len(chunk) {
			t.Errorf("%+v: %v", o, err)
		}
	}
}

func TestEncodeMemory(t *testing.T) {
	const chunk = 4 << 20
	for _, tc := range []struct {
		name string
		p    Params
		want int64
	}{
		{"zstd", nil, 44 << 20},                  // level 12: 36 MB and two 4 MiB windows
		{"zstd", Params{"level": "3"}, 10 << 20}, // 2 MB and two windows
		{"zstd", Params{"long": "27"}, 44 << 20}, // the window capped at the chunk
		{"xz", nil, 7*chunk + 2<<20},             // 30 MB
		{"none", nil, 0},
	} {
		got, err := EncodeMemory(tc.name, tc.p, chunk)
		if err != nil || got != tc.want {
			t.Errorf("%s %v: %d, %v; want %d", tc.name, tc.p, got, err, tc.want)
		}
	}
	if got, _ := EncodeMemory("zstd", Params{"long": "27"}, 128<<20); got != 36<<20+2<<27 {
		t.Errorf("long=27 with 128 MiB chunks: %d", got)
	}
}

// slow is an encoder that counts the calls in progress.
type slow struct{ now, most atomic.Int32 }

func (s *slow) Encode(dst, src []byte) ([]byte, error) {
	n := s.now.Add(1)
	for m := s.most.Load(); n > m && !s.most.CompareAndSwap(m, n); m = s.most.Load() {
	}
	time.Sleep(5 * time.Millisecond)
	s.now.Add(-1)
	return append(dst, src...), nil
}
func (s *slow) Resolved() map[string]any { return nil }
func (s *slow) Close() error             { return nil }

// TestLimitedBoundsTheCalls: with 2 slots, 8 callers never have more than 2
// calls in progress.
func TestLimitedBoundsTheCalls(t *testing.T) {
	s := &slow{}
	enc := &limited{Encoder: s, slots: make(chan struct{}, 2)}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); enc.Encode(nil, []byte("x")) }()
	}
	wg.Wait()
	if m := s.most.Load(); m != 2 {
		t.Errorf("at most %d calls at once, want 2", m)
	}
}
