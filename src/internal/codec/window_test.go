package codec

import (
	"math/rand/v2"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// TestZstdFramesStayInTheWindowBound: each frame that the writer makes asks
// for a window of at most max(1 MiB, the chunk size), so the readers, which
// refuse a larger one, read every archive that eictar writes (doc/format.md
// 6). A frame that is a single segment has no window of its own: its
// content size takes the place of the window.
func TestZstdFramesStayInTheWindowBound(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	text := make([]byte, 5<<20)
	for i := range text {
		text[i] = "abcdefgh  \n"[rng.IntN(11)]
	}
	for _, p := range []Params{{"level": "1"}, {"level": "3"}, {"level": "12"}, {"level": "19"}, {"long": "27"}} {
		for _, chunk := range []int{512, 1000, 1024, 1025, 3 << 20, 5 << 20} {
			if chunk > 1<<20 && (p["level"] == "12" || p["level"] == "19") {
				continue // slow, and level 1 makes the same frames: larger than the window
			}
			for _, maxChunk := range []int{chunk, 0} {
				enc, err := NewEncoderWith("zstd", p, EncoderOptions{Concurrency: 1, MaxChunk: maxChunk})
				if err != nil {
					t.Fatal(err)
				}
				for _, n := range []int{1, 1000, 1024, 1025, chunk - 1, chunk} {
					if n < 1 || n > chunk {
						continue
					}
					frame, err := enc.Encode(nil, text[:n])
					if err != nil {
						t.Fatal(err)
					}
					var h zstd.Header
					if err := h.Decode(frame); err != nil {
						t.Fatal(err)
					}
					window := h.WindowSize
					if h.SingleSegment {
						window = h.FrameContentSize
					}
					if window > max(1<<20, uint64(chunk)) {
						t.Errorf("%v, chunk %d, MaxChunk %d, %d bytes: a window of %d bytes",
							p, chunk, maxChunk, n, window)
					}
				}
				enc.Close()
			}
		}
	}
}
