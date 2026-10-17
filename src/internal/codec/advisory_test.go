package codec

import (
	"bytes"
	"slices"
	"testing"
)

// zstdHuffWeightsFrames are the input of TestDecoderHuffWeightsTableLog in
// klauspost/compress v1.20.2 (GHSA-fpmh-frq8-7rj8): one frame with two
// blocks, and the same blocks in two frames. v1.20.1 and earlier panic on
// them. The first block leaves state in a table that the library keeps for
// the next block, and for the next frame too.
func zstdHuffWeightsFrames() (oneFrame []byte, twoFrames [2][]byte) {
	oneFrame = slices.Concat(
		[]byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x38, 0x74, 0x06, 0x00, 0x42, 0xb8, 0x32, 0x0d, 0x1a, 0x00, 0x00, 0x00, 0x90, 0xaf, 0xfa, 0xff, 0x03, 0x00, 0x80, 0xff, 0x7f},
		bytes.Repeat([]byte{0xa5, 0x94, 0x52, 0x4a, 0x29}, 37),
		[]byte{0xa5, 0x94, 0x12, 0x00, 0xad, 0x56, 0x03, 0xee, 0xff, 0xdf, 0xb3, 0x1a, 0x1c, 0x1a, 0x00, 0xe0, 0xff, 0x1f, 0x0f, 0xb1, 0x9c, 0x5a, 0xcf, 0x4d, 0xe4, 0x1d, 0x7b, 0xab, 0x99, 0x5e, 0x01, 0x51, 0xa4, 0x73, 0xd8, 0xb1, 0xf3, 0x39, 0x4b, 0x67, 0xf6, 0xab, 0x1a, 0xab, 0x1a, 0xab, 0x1a},
		bytes.Repeat([]byte{0x8c, 0x31, 0xc6, 0x18, 0x63}, 1365),
		[]byte{0x8c, 0x31},
		bytes.Repeat([]byte{0x63, 0x8c, 0x31, 0xc6, 0x18}, 1365),
		[]byte{0x63, 0x2c},
		bytes.Repeat([]byte{0x31, 0xc6, 0x18, 0x63, 0x8c}, 1365),
		[]byte{0x31, 0x46},
		bytes.Repeat([]byte{0x31, 0xc6, 0x18, 0x63, 0x8c}, 1365),
		[]byte{0x31, 0x06, 0x00},
	)
	// The first block marked last, in its own frame, then the second block.
	twoFrames[0] = slices.Concat(oneFrame[:6], []byte{0x75, 0x06, 0x00}, oneFrame[9:215])
	twoFrames[1] = slices.Concat(oneFrame[:6], oneFrame[215:])
	return oneFrame, twoFrames
}

// TestZstdHuffWeightsAdvisory: a crafted chunk is damage, not a panic, also
// when the bad state comes from the chunk before it in the same decoder
// (GHSA-fpmh-frq8-7rj8). The reader uses a decoder again for the next chunk
// (doc/design.md 8.3).
func TestZstdHuffWeightsAdvisory(t *testing.T) {
	oneFrame, twoFrames := zstdHuffWeightsFrames()
	dec, err := NewDecoder("zstd", 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Close()
	if _, err := dec.Decode(nil, oneFrame, 1<<20); err == nil {
		t.Error("one frame: no error")
	}
	dec.Decode(nil, twoFrames[0], 1<<20) // the first block alone can decode
	if _, err := dec.Decode(nil, twoFrames[1], 1<<20); err == nil {
		t.Error("the second of two frames: no error")
	}
}
