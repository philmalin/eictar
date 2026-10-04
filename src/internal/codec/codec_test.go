package codec

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// The conformance suite runs against every registered codec. Adding a codec
// means it is covered here automatically, which is the point: a new
// algorithm must satisfy the same contract as the ones already trusted.

const testChunk = 1 << 20

func eachCodec(t *testing.T, fn func(t *testing.T, f Factory)) {
	t.Helper()
	for _, name := range Names() {
		f, err := Lookup(name)
		if err != nil {
			t.Fatalf("Lookup(%q): %v", name, err)
		}
		t.Run(name, func(t *testing.T) { fn(t, f) })
	}
}

// payloads covers the shapes that break compressors: empty, tiny,
// incompressible, highly compressible, and exactly at a boundary.
func payloads(t *testing.T) map[string][]byte {
	t.Helper()

	rnd := rand.New(rand.NewSource(1))
	random := make([]byte, 64<<10)
	rnd.Read(random)

	return map[string][]byte{
		"empty":          {},
		"one byte":       {0x42},
		"text":           []byte(strings.Repeat("the quick brown fox. ", 500)),
		"zeroes":         make([]byte, 128<<10),
		"incompressible": random,
		"binary":         {0x00, 0xff, 0x00, 0xff, 0x7f, 0x80},
		"chunk exactly":  bytes.Repeat([]byte("x"), testChunk),
	}
}

func TestRoundTrip(t *testing.T) {
	eachCodec(t, func(t *testing.T, f Factory) {
		for name, want := range payloads(t) {
			t.Run(name, func(t *testing.T) {
				enc, err := f.NewEncoder(nil, 1)
				if err != nil {
					t.Fatalf("NewEncoder: %v", err)
				}
				defer enc.Close()

				compressed, err := enc.Encode(nil, want)
				if err != nil {
					t.Fatalf("Encode: %v", err)
				}

				dec, err := f.NewDecoder(testChunk)
				if err != nil {
					t.Fatalf("NewDecoder: %v", err)
				}
				defer dec.Close()

				got, err := dec.Decode(nil, compressed, len(want))
				if err != nil {
					t.Fatalf("Decode: %v", err)
				}
				if !bytes.Equal(got, want) {
					t.Errorf("round trip changed %d bytes of %q", len(want), name)
				}
			})
		}
	})
}

// TestEncodeAppends pins the append contract: the pipeline writes chunks into
// a shared buffer, so an encoder that ignores dst would corrupt the member.
func TestEncodeAppends(t *testing.T) {
	eachCodec(t, func(t *testing.T, f Factory) {
		enc, err := f.NewEncoder(nil, 1)
		if err != nil {
			t.Fatalf("NewEncoder: %v", err)
		}
		defer enc.Close()

		prefix := []byte("PREFIX")
		out, err := enc.Encode(append([]byte(nil), prefix...), []byte("payload"))
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		if !bytes.HasPrefix(out, prefix) {
			t.Fatalf("Encode did not append to dst: got %q", out)
		}

		dec, err := f.NewDecoder(testChunk)
		if err != nil {
			t.Fatalf("NewDecoder: %v", err)
		}
		defer dec.Close()

		got, err := dec.Decode(nil, out[len(prefix):], len("payload"))
		if err != nil {
			t.Fatalf("Decode: %v", err)
		}
		if string(got) != "payload" {
			t.Errorf("got %q, want %q", got, "payload")
		}
	})
}

// TestDecodeRejectsWrongSize is the defence against a lying index: a chunk
// that does not decode to the promised size must be refused, not returned.
func TestDecodeRejectsWrongSize(t *testing.T) {
	eachCodec(t, func(t *testing.T, f Factory) {
		enc, err := f.NewEncoder(nil, 1)
		if err != nil {
			t.Fatalf("NewEncoder: %v", err)
		}
		defer enc.Close()

		payload := []byte("exactly twenty chars")
		compressed, err := enc.Encode(nil, payload)
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}

		dec, err := f.NewDecoder(testChunk)
		if err != nil {
			t.Fatalf("NewDecoder: %v", err)
		}
		defer dec.Close()

		for _, claimed := range []int{0, 1, len(payload) - 1, len(payload) + 1, 1 << 15} {
			if _, err := dec.Decode(nil, compressed, claimed); err == nil {
				t.Errorf("Decode accepted a claimed size of %d for a %d-byte chunk",
					claimed, len(payload))
			}
		}
	})
}

// TestDecodeRejectsOverBound is the decompression-bomb guard.
func TestDecodeRejectsOverBound(t *testing.T) {
	eachCodec(t, func(t *testing.T, f Factory) {
		enc, err := f.NewEncoder(nil, 1)
		if err != nil {
			t.Fatalf("NewEncoder: %v", err)
		}
		defer enc.Close()

		const bound = 4096
		big := make([]byte, bound*16) // compresses to almost nothing
		compressed, err := enc.Encode(nil, big)
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}

		dec, err := f.NewDecoder(bound)
		if err != nil {
			t.Fatalf("NewDecoder: %v", err)
		}
		defer dec.Close()

		if _, err := dec.Decode(nil, compressed, len(big)); err == nil {
			t.Error("Decode accepted a chunk larger than the decoder's bound")
		}
	})
}

// uncheckedCodecs have no integrity check inside their format.
var uncheckedCodecs = map[string]bool{"s2": true, "flate": true}

func TestDecodeRejectsCorruptInput(t *testing.T) {
	eachCodec(t, func(t *testing.T, f Factory) {
		if f.Name() == "none" {
			// Stored content has no structure to corrupt; the size check in
			// TestDecodeRejectsWrongSize is its equivalent.
			t.Skip("codec none stores content verbatim")
		}

		enc, err := f.NewEncoder(nil, 1)
		if err != nil {
			t.Fatalf("NewEncoder: %v", err)
		}
		defer enc.Close()

		payload := bytes.Repeat([]byte("compress me. "), 100)
		good, err := enc.Encode(nil, payload)
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}

		dec, err := f.NewDecoder(testChunk)
		if err != nil {
			t.Fatalf("NewDecoder: %v", err)
		}
		defer dec.Close()

		for _, tc := range []struct {
			name string
			in   []byte
		}{
			{"empty", nil},
			{"truncated", good[:len(good)/2]},
			{"flipped byte", func() []byte {
				b := bytes.Clone(good)
				b[len(b)/2] ^= 0xff
				return b
			}()},
			{"random", []byte("this is not compressed data at all")},
		} {
			t.Run(tc.name, func(t *testing.T) {
				got, err := dec.Decode(nil, tc.in, len(payload))
				if err != nil {
					return
				}
				// s2 and raw DEFLATE carry no checksum of their own: a changed
				// literal decodes to wrong bytes of the right length. The
				// member's BLAKE3 digest is what catches that, after
				// decoding. Every other case must fail here.
				if tc.name == "flipped byte" && uncheckedCodecs[f.Name()] && !bytes.Equal(got, payload) {
					return
				}
				t.Error("Decode accepted corrupt input")
			})
		}
	})
}

// TestEncoderIsConcurrencySafe matters from M3 on, when the worker pool
// shares one encoder across chunks. Run under -race for it to mean anything.
func TestEncoderIsConcurrencySafe(t *testing.T) {
	eachCodec(t, func(t *testing.T, f Factory) {
		const callers = 8
		enc, err := f.NewEncoder(nil, callers)
		if err != nil {
			t.Fatalf("NewEncoder: %v", err)
		}
		defer enc.Close()

		payload := bytes.Repeat([]byte("concurrent chunk "), 1000)

		var wg sync.WaitGroup
		errs := make([]error, 8)
		outs := make([][]byte, 8)
		for i := range outs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				outs[i], errs[i] = enc.Encode(nil, payload)
			}()
		}
		wg.Wait()

		for i, err := range errs {
			if err != nil {
				t.Fatalf("goroutine %d: %v", i, err)
			}
			if !bytes.Equal(outs[i], outs[0]) {
				t.Errorf("goroutine %d produced different output from goroutine 0", i)
			}
		}
	})
}

func TestUnknownCodec(t *testing.T) {
	if _, err := NewEncoder("nonesuch", nil, 1); !errors.Is(err, ErrUnknownCodec) {
		t.Errorf("error = %v, want ErrUnknownCodec", err)
	}
	if _, err := NewDecoder("nonesuch", testChunk); !errors.Is(err, ErrUnknownCodec) {
		t.Errorf("error = %v, want ErrUnknownCodec", err)
	}
	// The message must list what is available, or the user is left guessing.
	_, err := NewEncoder("zsdt", nil, 1)
	if err == nil || !strings.Contains(err.Error(), "zstd") {
		t.Errorf("error = %v, want it to suggest the known codecs", err)
	}
}

// TestUnknownParamIsRejected is the typo guard: "levle=19" must not silently
// produce a default-level archive.
func TestUnknownParamIsRejected(t *testing.T) {
	eachCodec(t, func(t *testing.T, f Factory) {
		if _, err := f.NewEncoder(Params{"nonesuch": "1"}, 1); err == nil {
			t.Error("NewEncoder accepted an unknown parameter")
		}
	})
}

func TestZstdParams(t *testing.T) {
	f, err := Lookup("zstd")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}

	t.Run("resolved defaults", func(t *testing.T) {
		enc, err := f.NewEncoder(nil, 1)
		if err != nil {
			t.Fatalf("NewEncoder: %v", err)
		}
		defer enc.Close()

		if got := enc.Resolved()["level"]; got != zstdLevelDefault {
			t.Errorf("resolved level = %v, want %v", got, zstdLevelDefault)
		}
		if _, ok := enc.Resolved()["long"]; ok {
			t.Error("long should be absent unless asked for")
		}
	})

	t.Run("resolved explicit", func(t *testing.T) {
		enc, err := f.NewEncoder(Params{"level": "19", "long": "27"}, 1)
		if err != nil {
			t.Fatalf("NewEncoder: %v", err)
		}
		defer enc.Close()

		if got := enc.Resolved()["level"]; got != 19 {
			t.Errorf("resolved level = %v, want 19", got)
		}
		if got := enc.Resolved()["long"]; got != 27 {
			t.Errorf("resolved long = %v, want 27", got)
		}
	})

	t.Run("out of range", func(t *testing.T) {
		for _, p := range []Params{
			{"level": "0"}, {"level": "23"}, {"level": "-1"},
			{"level": "high"}, {"long": "9"}, {"long": "31"},
		} {
			if _, err := f.NewEncoder(p, 1); err == nil {
				t.Errorf("NewEncoder(%v) succeeded, want a range error", p)
			}
		}
	})

	t.Run("higher level compresses at least as well", func(t *testing.T) {
		payload := bytes.Repeat([]byte("the quick brown fox jumps. "), 2000)

		size := func(level string) int {
			enc, err := f.NewEncoder(Params{"level": level}, 1)
			if err != nil {
				t.Fatalf("NewEncoder: %v", err)
			}
			defer enc.Close()
			out, err := enc.Encode(nil, payload)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			return len(out)
		}
		if lo, hi := size("1"), size("19"); hi > lo {
			t.Errorf("level 19 produced %d bytes, level 1 produced %d", hi, lo)
		}
	})
}

func TestDescribe(t *testing.T) {
	specs := Describe()
	if len(specs) != len(Names()) {
		t.Fatalf("Describe returned %d specs for %d codecs", len(specs), len(Names()))
	}
	for _, s := range specs {
		if s.Name == "" || s.Description == "" {
			t.Errorf("codec %q is missing a name or description", s.Name)
		}
		for _, p := range s.Params {
			if p.Name == "" || p.Description == "" {
				t.Errorf("codec %s: parameter %q is missing a name or description", s.Name, p.Name)
			}
		}
	}
}

// TestSharedEncoderRunsInParallel guards a trap that costs everything and
// shows up as nothing: klauspost's zstd encoder keeps a pool of per-caller
// states sized by WithEncoderConcurrency, and EncodeAll takes one for the
// duration of the call. An encoder built with a concurrency of 1 and shared
// by a worker pool is therefore correct, race-free, and completely serial -
// the pool runs, and one worker compresses at a time.
//
// The test compares wall time for the same work done by one goroutine and by
// several sharing an encoder built for them. It needs real cores to mean
// anything, so it skips where there are not enough.
func TestSharedEncoderRunsInParallel(t *testing.T) {
	if runtime.NumCPU() < 4 {
		t.Skip("needs at least 4 cores to distinguish parallel from serial")
	}

	f, err := Lookup("zstd")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}

	// Compressible but not trivially so, and large enough that a chunk costs
	// real time at this level.
	rnd := rand.New(rand.NewSource(5))
	words := make([][]byte, 500)
	for i := range words {
		words[i] = []byte(fmt.Sprintf(" word%04d", i))
	}
	var payload []byte
	for len(payload) < 4<<20 {
		payload = append(payload, words[rnd.Intn(len(words))]...)
	}

	const callers = 4
	timeWith := func(concurrency, goroutines int) time.Duration {
		enc, err := f.NewEncoder(Params{"level": "12"}, concurrency)
		if err != nil {
			t.Fatalf("NewEncoder: %v", err)
		}
		defer enc.Close()

		start := time.Now()
		var wg sync.WaitGroup
		for range goroutines {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range callers / goroutines {
					if _, err := enc.Encode(nil, payload); err != nil {
						t.Errorf("Encode: %v", err)
					}
				}
			}()
		}
		wg.Wait()
		return time.Since(start)
	}

	// A generous bound: on four cores the parallel run should be far faster.
	// A serial encoder takes as long as one goroutine, in every attempt. A
	// loaded machine can miss the bound once: the virtual machine of the
	// OpenBSD job took 0.83 of the serial time in one run. Thus the test
	// passes when one of three attempts meets the bound.
	var tries []string
	for range 3 {
		serial := timeWith(1, 1)
		parallel := timeWith(callers, callers)
		t.Logf("serial %v, parallel %v", serial, parallel)
		if parallel <= serial*3/4 {
			return
		}
		tries = append(tries, fmt.Sprintf("%v against %v", parallel, serial))
	}
	t.Errorf("sharing an encoder across %d goroutines took %s serial, in each attempt; "+
		"the encoder is probably serialising on a state pool of one",
		callers, strings.Join(tries, ", "))
}

// TestRepetitiveInputIsFast: a chunk of one repeated byte is the worst case
// for some match finders; the binary tree of the xz library takes hours on
// 4 MiB of zeroes. Every codec must handle it quickly at its strongest
// setting.
func TestRepetitiveInputIsFast(t *testing.T) {
	strongest := map[string]Params{
		"zstd": {"level": "19"}, "flate": {"level": "9"}, "gzip": {"level": "9"},
		"s2": {"mode": "best"}, "xz": {"preset": "9"},
	}
	src := make([]byte, 4<<20)
	eachCodec(t, func(t *testing.T, f Factory) {
		enc, err := f.NewEncoder(strongest[f.Name()], 1)
		if err != nil {
			t.Fatal(err)
		}
		defer enc.Close()
		start := time.Now()
		if _, err := enc.Encode(nil, src); err != nil {
			t.Fatal(err)
		}
		if d := time.Since(start); d > 10*time.Second {
			t.Errorf("4 MiB of zeroes took %v", d)
		}
	})
}

// TestGzipChunkHasNoTime: a gzip member records no modification time, so
// that one chunk always encodes to the same bytes.
func TestGzipChunkHasNoTime(t *testing.T) {
	enc, err := NewEncoder("gzip", nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()
	for range 2 { // the second time, from a writer that the pool reset
		out, err := enc.Encode(nil, []byte("hello"))
		if err != nil {
			t.Fatal(err)
		}
		if mtime := out[4:8]; !bytes.Equal(mtime, []byte{0, 0, 0, 0}) {
			t.Errorf("gzip MTIME = % x, want 0", mtime)
		}
	}
}
