package codec

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// Tests of the parts of the package that the conformance suite does not
// reach: the functions that take a codec by name, the edges of the
// parameters, and the estimates of memory.

// TestDecodeAppends: a decode appends to what dst holds, whether dst has
// room for the chunk or not.
func TestDecodeAppends(t *testing.T) {
	payload := []byte(strings.Repeat("payload ", 100))
	eachCodec(t, func(t *testing.T, f Factory) {
		enc, err := f.NewEncoder(nil, 1)
		if err != nil {
			t.Fatal(err)
		}
		defer enc.Close()
		src, err := enc.Encode(nil, payload)
		if err != nil {
			t.Fatal(err)
		}
		dec, err := f.NewDecoder(testChunk)
		if err != nil {
			t.Fatal(err)
		}
		defer dec.Close()
		for name, dst := range map[string][]byte{
			"no room":     []byte("hello"),
			"little room": append(make([]byte, 0, 5+len(payload)/2), "hello"...),
			// A long prefix: the room is too little, but the room and the
			// prefix together are more than the chunk.
			"a long prefix": append(make([]byte, 0, 2*len(payload)), strings.Repeat("h", 3*len(payload)/2)...),
			"exactly room":  append(make([]byte, 0, 5+len(payload)), "hello"...),
		} {
			got, err := dec.Decode(dst, src, len(payload))
			prefix := dst[:len(dst):len(dst)]
			if err != nil || !bytes.Equal(got, append(append([]byte(nil), prefix...), payload...)) {
				t.Errorf("%s: %q..., %v", name, got[:min(len(got), 12)], err)
			}
		}
	})
}

// TestDecodeAtTheBound: a chunk of exactly the bound decodes. One byte more
// does not, and a bound of 0 is refused.
func TestDecodeAtTheBound(t *testing.T) {
	payload := []byte(strings.Repeat("x", 1000))
	eachCodec(t, func(t *testing.T, f Factory) {
		enc, err := f.NewEncoder(nil, 1)
		if err != nil {
			t.Fatal(err)
		}
		defer enc.Close()
		src, err := enc.Encode(nil, payload)
		if err != nil {
			t.Fatal(err)
		}
		dec, err := NewDecoder(f.Name(), len(payload))
		if err != nil {
			t.Fatal(err)
		}
		defer dec.Close()
		if got, err := dec.Decode(nil, src, len(payload)); err != nil || !bytes.Equal(got, payload) {
			t.Errorf("at the bound: %v", err)
		}
		if _, err := dec.Decode(nil, src, len(payload)+1); err == nil {
			t.Error("past the bound: no error")
		}
		if _, err := NewDecoder(f.Name(), 0); err == nil {
			t.Error("a bound of 0: no error")
		}
	})
}

// TestDecodeOfAShortStream: a stream that ends before the size that the
// index gives says so, for each codec whose decoder is a reader.
func TestDecodeOfAShortStream(t *testing.T) {
	payload := []byte(strings.Repeat("abcdefgh", 1000))
	for _, name := range []string{"flate", "gzip", "xz"} {
		enc, err := NewEncoder(name, nil, 1)
		if err != nil {
			t.Fatal(err)
		}
		src, err := enc.Encode(nil, payload)
		enc.Close()
		if err != nil {
			t.Fatal(err)
		}
		dec, err := NewDecoder(name, 2*len(payload))
		if err != nil {
			t.Fatal(err)
		}
		_, err = dec.Decode(nil, src, len(payload)+10)
		dec.Close()
		if err == nil || !strings.Contains(err.Error(), "decoded to") {
			t.Errorf("%s: %v, want the size that it decoded to", name, err)
		}
	}
}

// TestDecodeOfBytesAfterTheStream: a chunk is one stream (doc/format.md 6),
// so bytes after the end of the stream are refused, also when the stream
// decodes to the right content. The suffixes are ones that a decoder stops
// before without an error: an empty final block after the final block of
// flate, a byte after the gzip member, a second end marker of LZMA2, and a
// second frame after the zstd frame: zstd decodes each frame that it finds.
// The stress tester found the fault: a flipped bit made a block final, and
// eictar took the chunk while the second reader refused it.
func TestDecodeOfBytesAfterTheStream(t *testing.T) {
	payload := []byte(strings.Repeat("abcdefgh", 1000))
	for name, suffixes := range map[string][][]byte{
		"flate": {{0x03, 0x00}, {0x00}},
		"gzip":  {{0x00}, {0x1f, 0x8b}},
		"xz":    {{0x00}, {0xff}},
		// An empty frame, and a skippable frame of one byte.
		"zstd": {{0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x00, 0x01, 0x00, 0x00}, {0x50, 0x2a, 0x4d, 0x18, 0x01, 0x00, 0x00, 0x00, 0xaa}},
	} {
		enc, err := NewEncoder(name, nil, 1)
		if err != nil {
			t.Fatal(err)
		}
		src, err := enc.Encode(nil, payload)
		enc.Close()
		if err != nil {
			t.Fatal(err)
		}
		dec, err := NewDecoder(name, len(payload))
		if err != nil {
			t.Fatal(err)
		}
		if got, err := dec.Decode(nil, src, len(payload)); err != nil || !bytes.Equal(got, payload) {
			t.Errorf("%s: the chunk as written: %v", name, err)
		}
		for _, suffix := range suffixes {
			chunk := append(append([]byte(nil), src...), suffix...)
			if _, err := dec.Decode(nil, chunk, len(payload)); err == nil ||
				!strings.Contains(err.Error(), fmt.Sprintf(": %d bytes after the compressed stream", len(suffix))) {
				t.Errorf("%s: %x after the stream: %v, want a refusal", name, suffix, err)
			}
		}
		dec.Close()
	}
}

// TestS2DecodeFaults: a block whose length does not parse, and one whose
// length is right and whose content is not.
func TestS2DecodeFaults(t *testing.T) {
	dec, err := NewDecoder("s2", testChunk)
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Close()
	if _, err := dec.Decode(nil, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 10); err == nil {
		t.Error("a length that does not parse: no error")
	}
	enc, err := NewEncoder("s2", nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()
	src, err := enc.Encode(nil, []byte(strings.Repeat("abcdefgh", 100)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dec.Decode(nil, src, 801); err == nil || !strings.Contains(err.Error(), "decodes to 800") {
		t.Errorf("another length: %v", err)
	}
	bad := append([]byte(nil), src...)
	for i := len(bad) / 2; i < len(bad); i++ {
		bad[i] = 0xff
	}
	if _, err := dec.Decode(nil, bad, 800); err == nil {
		t.Error("a broken block: no error")
	}
}

// TestByNameRefusals: each function that takes a codec by name refuses a
// name that is not one, and parameters that are not valid.
func TestByNameRefusals(t *testing.T) {
	bad := Params{"level": ""}
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"EncodeMemory", func() error { _, err := EncodeMemory("nope", nil, 1); return err }()},
		{"EncodeMemory, params", func() error { _, err := EncodeMemory("zstd", bad, 1); return err }()},
		{"TrainSize", func() error { _, err := TrainSize("nope", nil); return err }()},
		{"TrainSize, params", func() error { _, err := TrainSize("zstd", bad); return err }()},
		{"TrainDict", func() error { _, err := TrainDict("nope", nil, nil, 4096, 1<<15); return err }()},
		{"TrainDict, params", func() error { _, err := TrainDict("zstd", bad, nil, 4096, 1<<15); return err }()},
		{"DictID", func() error { _, err := DictID("nope", nil); return err }()},
		{"WindowBeyondChunk", func() error { _, _, err := WindowBeyondChunk("nope", nil, 1); return err }()},
		{"WindowBeyondChunk, params", func() error { _, _, err := WindowBeyondChunk("zstd", bad, 1); return err }()},
		{"WindowBeyondChunk, long", func() error { _, _, err := WindowBeyondChunk("zstd", Params{"long": "x"}, 1); return err }()},
		{"WindowBeyondChunk, preset", func() error { _, _, err := WindowBeyondChunk("xz", Params{"preset": "x"}, 1); return err }()},
		{"EncodeMemory, xz preset", func() error { _, err := EncodeMemory("xz", Params{"preset": "x"}, 1); return err }()},
		{"EncodeMemory, zstd level", func() error { _, err := EncodeMemory("zstd", Params{"level": "x"}, 1); return err }()},
		{"EncodeMemory, zstd long", func() error { _, err := EncodeMemory("zstd", Params{"long": "x"}, 1); return err }()},
		{"xz preset", func() error { _, err := NewEncoder("xz", Params{"preset": "x"}, 1); return err }()},
		{"zstd long", func() error { _, err := NewEncoder("zstd", Params{"long": "x"}, 1); return err }()},
		{"flate, unknown", func() error { _, err := NewEncoder("flate", Params{"x": "1"}, 1); return err }()},
		{"zstd, a dictionary that is not one", func() error {
			_, err := NewEncoderWith("zstd", nil, EncoderOptions{Concurrency: 1, Dict: []byte("not a dictionary")})
			return err
		}()},
		{"train, a size that is not one", func() error { _, err := TrainSize("zstd", Params{"train": "lots"}); return err }()},
		{"train, no samples", func() error { _, err := TrainDict("zstd", nil, nil, 4096, 1<<15); return err }()},
		{"zstd train", func() error { _, err := NewEncoder("zstd", Params{"train": "lots"}, 1); return err }()},
		{"flate level", func() error { _, err := NewEncoder("flate", Params{"level": "x"}, 1); return err }()},
		{"TrainDict, params, with samples", func() error { _, err := TrainDict("zstd", bad, sourceLike(200), 16<<10, 1<<15); return err }()},
		{"TrainDict, level, with samples", func() error {
			_, err := TrainDict("zstd", Params{"level": "x"}, sourceLike(200), 16<<10, 1<<15)
			return err
		}()},
	} {
		if tc.err == nil {
			t.Errorf("%s: no error", tc.name)
		}
	}
	if err := checkParams(Params{"x": "1"}, Spec{Name: "none"}); err == nil || !strings.Contains(err.Error(), "takes no parameters") {
		t.Errorf("none with a parameter: %v", err)
	}
}

// TestWindowBeyondChunk: the zstd window and the xz dictionary that the
// parameters set, against the chunk, at its edge, and when not set.
func TestWindowBeyondChunk(t *testing.T) {
	for _, tc := range []struct {
		name  string
		p     Params
		chunk int
		size  int
		what  string
	}{
		{"s2", nil, 1, 0, ""},
		{"zstd", nil, 1, 0, ""},
		{"zstd", Params{"long": "27"}, 4 << 20, 128 << 20, "window"},
		{"zstd", Params{"long": "22"}, 4 << 20, 0, ""}, // exactly the chunk
		{"zstd", Params{"long": "23"}, 4 << 20, 8 << 20, "window"},
		{"xz", nil, 1, 0, ""},
		{"xz", Params{"preset": "9"}, 4 << 20, 64 << 20, "dictionary"},
		{"xz", Params{"preset": "3"}, 4 << 20, 0, ""},
	} {
		size, what, err := WindowBeyondChunk(tc.name, tc.p, tc.chunk)
		if err != nil || size != tc.size || what != tc.what {
			t.Errorf("%s %v, chunk %d: %d %q, %v; want %d %q", tc.name, tc.p, tc.chunk, size, what, err, tc.size, tc.what)
		}
	}
}

// TestXzPresetDictionaries: the dictionary of each preset, as xz(1) gives
// it.
func TestXzPresetDictionaries(t *testing.T) {
	want := []int{256 << 10, 1 << 20, 2 << 20, 4 << 20, 4 << 20, 8 << 20, 8 << 20, 16 << 20, 32 << 20, 64 << 20}
	for preset, w := range want {
		size, _, err := (xzFactory{}).window(Params{"preset": string(rune('0' + preset))})
		if err != nil || size != w {
			t.Errorf("preset %d: %d, %v; want %d", preset, size, err, w)
		}
	}
}

// TestEncodeMemoryEdges: the estimate for each speed of zstd, a long window
// of exactly the chunk, the default of xz with no chunk, and the codecs
// without a measurement of their own.
func TestEncodeMemoryEdges(t *testing.T) {
	const mib = 1 << 20
	for _, tc := range []struct {
		name  string
		p     Params
		chunk int
		want  int64
	}{
		{"zstd", Params{"level": "1"}, 4 * mib, 1*mib + 2*4*mib},
		{"zstd", Params{"level": "3"}, 4 * mib, 2*mib + 2*4*mib},
		{"zstd", Params{"level": "7"}, 4 * mib, 5*mib + 2*4*mib},
		{"zstd", Params{"level": "19"}, 0, 36*mib + 2*8*mib},
		{"zstd", Params{"level": "3", "long": "27"}, 4 * mib, 2*mib + 2*4*mib},
		{"xz", nil, 0, 7*8*mib + 2*mib},
		{"s2", nil, 4 * mib, 2*4*mib + mib},
		{"s2", nil, 64 << 10, 2*mib + mib},
		{"flate", nil, 4 * mib, 4*mib + 2*mib},
	} {
		if got, err := EncodeMemory(tc.name, tc.p, tc.chunk); err != nil || got != tc.want {
			t.Errorf("%s %v, chunk %d: %d, %v; want %d", tc.name, tc.p, tc.chunk, got, err, tc.want)
		}
	}
}

// TestTrainSizeEdges: the limits of train are in range, and one byte past
// each is not.
func TestTrainSizeEdges(t *testing.T) {
	for raw, ok := range map[string]bool{
		"4096": true, "4095": false, "1M": true, "1048577": false,
	} {
		_, err := TrainSize("zstd", Params{"train": raw})
		if (err == nil) != ok {
			t.Errorf("train=%s: %v", raw, err)
		}
	}
}

// TestParseSizeEdges: a 0 among the digits, and the bound against a shift
// that wraps.
func TestParseSizeEdges(t *testing.T) {
	for in, want := range map[string]int{"10K": 10 << 10, "1099511627776": 1 << 40, "100": 100} {
		if got, err := parseSize(in); err != nil || got != want {
			t.Errorf("parseSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"1099511627777", "2000000000000", "K"} {
		if _, err := parseSize(in); err == nil {
			t.Errorf("parseSize(%q): no error", in)
		}
	}
}

// TestDictIDOfEightBytes: the magic and the id are all that dictID reads.
func TestDictIDOfEightBytes(t *testing.T) {
	d := binary.LittleEndian.AppendUint32(binary.LittleEndian.AppendUint32(nil, zstdDictMagic), 1234)
	if id, err := DictID("zstd", d); err != nil || id != 1234 {
		t.Errorf("%d, %v; want 1234", id, err)
	}
	if _, err := DictID("zstd", d[:7]); err == nil {
		t.Error("seven bytes: no error")
	}
}

// TestGzipIsFramed: gzip has its header, and flate has none.
func TestGzipIsFramed(t *testing.T) {
	for name, framed := range map[string]bool{"gzip": true, "flate": false} {
		enc, err := NewEncoder(name, nil, 1)
		if err != nil {
			t.Fatal(err)
		}
		out, err := enc.Encode(nil, []byte("x"))
		enc.Close()
		if err != nil || bytes.HasPrefix(out, []byte{0x1f, 0x8b}) != framed {
			t.Errorf("%s: %x, %v", name, out, err)
		}
		f, _ := Lookup(name)
		if strings.Contains(f.Describe().Description, "gzip") != framed {
			t.Errorf("%s: %q", name, f.Describe().Description)
		}
	}
}

// TestIntParamEmpty: an empty value is the default.
func TestIntParamEmpty(t *testing.T) {
	if v, err := intParam(Params{"level": ""}, "level", 5, 1, 9); v != 5 || err != nil {
		t.Errorf("%d, %v; want 5", v, err)
	}
}

// TestZstdFrameLen: the length of a frame comes from the headers of its
// blocks. A frame cut in a block header, in a block or in its checksum is
// refused, and so are a block of the reserved type and a skippable frame.
// An RLE block holds one byte on disk.
func TestZstdFrameLen(t *testing.T) {
	enc, err := NewEncoder("zstd", nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := enc.Encode(nil, []byte(strings.Repeat("a frame of some length, ", 40)))
	enc.Close()
	if err != nil {
		t.Fatal(err)
	}
	if n, err := zstdFrameLen(frame); err != nil || n != len(frame) {
		t.Fatalf("the frame: %d, %v, want %d", n, err, len(frame))
	}
	var h zstd.Header
	if err := h.Decode(frame); err != nil || !h.HasCheckSum || h.FirstBlock.CompressedSize < 2 {
		t.Fatalf("the test needs a checksum and a block of 2 bytes or more: %+v, %v", h, err)
	}
	for _, tc := range []struct {
		cut  int
		want string
	}{
		{h.HeaderSize + 2, "the frame ends in a block header"},
		{h.HeaderSize + 4, "the frame ends in a block"},
		// Near the end of the one block: fewer bytes are left than its
		// size, but more than its size less the bytes before it.
		{len(frame) - 5, "the frame ends in a block"},
		{len(frame) - 1, "the frame ends in its checksum"},
	} {
		if _, err := zstdFrameLen(frame[:tc.cut]); err == nil || err.Error() != tc.want {
			t.Errorf("cut at %d of %d: %v, want %q", tc.cut, len(frame), err, tc.want)
		}
	}
	if _, err := zstdFrameLen([]byte("not a frame")); !errors.Is(err, zstd.ErrMagicMismatch) {
		t.Errorf("not a frame: %v, want the error of the header", err)
	}
	reserved := append([]byte(nil), frame...)
	reserved[h.HeaderSize] |= 3 << 1
	if _, err := zstdFrameLen(reserved); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Errorf("a block of the reserved type: %v", err)
	}
	// Decode gives the error of the frame, not only its length.
	zdec, err := NewDecoder("zstd", 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer zdec.Close()
	if _, err := zdec.Decode(nil, reserved, 960); err == nil || !strings.Contains(err.Error(), "zstd: a block of the reserved type") {
		t.Errorf("decode of a block of the reserved type: %v", err)
	}
	if _, err := zstdFrameLen([]byte{0x50, 0x2a, 0x4d, 0x18, 0x01, 0x00, 0x00, 0x00, 0xaa}); err == nil ||
		!strings.Contains(err.Error(), "skippable") {
		t.Errorf("a skippable frame: %v", err)
	}

	// A single segment of 5 bytes, without a checksum, in one RLE block of
	// "a": the block header is last, type 1, size 5.
	rle := []byte{0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x05, 5<<3 | 1<<1 | 1, 0x00, 0x00, 'a'}
	if n, err := zstdFrameLen(rle); err != nil || n != len(rle) {
		t.Errorf("an RLE block: %d, %v, want %d", n, err, len(rle))
	}
	dec, err := NewDecoder("zstd", 5)
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Close()
	if got, err := dec.Decode(nil, rle, 5); err != nil || string(got) != "aaaaa" {
		t.Errorf("an RLE block decodes to %q, %v", got, err)
	}
	if _, err := dec.Decode(nil, append(rle, 'a'), 5); err == nil {
		t.Error("a byte after an RLE block: no error")
	}
}

// TestZstdDecoderWithASmallBound: the library needs a window of memory, so
// a bound smaller than 1 MiB still decodes a small chunk.
func TestZstdDecoderWithASmallBound(t *testing.T) {
	enc, err := NewEncoder("zstd", nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()
	payload := bytes.Repeat([]byte("abc"), 300)
	src, err := enc.Encode(nil, payload)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := NewDecoder("zstd", len(payload))
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Close()
	if got, err := dec.Decode(nil, src, len(payload)); err != nil || !bytes.Equal(got, payload) {
		t.Errorf("%v", err)
	}
}
