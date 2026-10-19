package codec

import (
	"bytes"
	"os"
	"testing"
)

// BenchmarkCodecs measures the codecs alone: the encode and the decode of
// one chunk of the default size, with no archive and no file system. It
// also gives the size of the result in percent of the input. A change of
// a compression library shows here first; the benchmarks of the archive
// package spend most of their time in the file system.
//
// EICTAR_CODEC_DATA names a file of real data: its first 4 MiB are the
// chunk. Without it, the chunk is generated source, which compresses much
// better than real files.
//
//	EICTAR_CODEC_DATA=file go test -run - -bench Codecs ./src/internal/codec/
func BenchmarkCodecs(b *testing.B) {
	const chunk = 4 << 20
	var src []byte
	if name := os.Getenv("EICTAR_CODEC_DATA"); name != "" {
		data, err := os.ReadFile(name)
		if err != nil {
			b.Fatal(err)
		}
		src = data[:min(len(data), chunk)]
	} else {
		src = bytes.Join(sourceLike(3000), nil)[:chunk]
	}
	for _, tc := range []struct {
		name, codec string
		p           Params
	}{
		{"zstd:level=3", "zstd", Params{"level": "3"}},
		{"zstd:level=12", "zstd", Params{"level": "12"}},
		{"zstd:level=19", "zstd", Params{"level": "19"}},
		{"gzip", "gzip", nil},
		{"s2", "s2", nil},
	} {
		enc, err := NewEncoder(tc.codec, tc.p, 1)
		if err != nil {
			b.Fatal(err)
		}
		packed, err := enc.Encode(nil, src)
		if err != nil {
			b.Fatal(err)
		}
		ratio := 100 * float64(len(packed)) / float64(len(src))
		b.Run("encode/"+tc.name, func(b *testing.B) {
			b.SetBytes(int64(len(src)))
			var out []byte
			for b.Loop() {
				if out, err = enc.Encode(out[:0], src); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(ratio, "%size")
		})
		enc.Close()
		b.Run("decode/"+tc.name, func(b *testing.B) {
			dec, err := NewDecoder(tc.codec, chunk)
			if err != nil {
				b.Fatal(err)
			}
			defer dec.Close()
			b.SetBytes(int64(len(src)))
			var out []byte
			for b.Loop() {
				if out, err = dec.Decode(out[:0], packed, len(src)); err != nil {
					b.Fatal(err)
				}
			}
			if !bytes.Equal(out, src) {
				b.Fatal("decoded content differs")
			}
		})
	}
}

// BenchmarkDictSmallChunks encodes many small chunks with a zstd dictionary,
// as zstd:train does for small files (doc/design.md 15.2, "Dictionaries at
// the best speed"). At level 10 and above, the library copies its tables
// from the dictionary at the start of each chunk, and the copy costs more
// than the compression.
func BenchmarkDictSmallChunks(b *testing.B) {
	files := sourceLike(400)
	dict, err := TrainDict("zstd", nil, files[:200], 32<<10, 40000)
	if err != nil {
		b.Fatal(err)
	}
	var total int64
	for _, f := range files[200:] {
		total += int64(len(f))
	}
	for _, level := range []string{"3", "9", "12"} {
		b.Run("zstd:level="+level, func(b *testing.B) {
			enc, err := NewEncoderWith("zstd", Params{"level": level}, EncoderOptions{Concurrency: 1, Dict: dict})
			if err != nil {
				b.Fatal(err)
			}
			defer enc.Close()
			b.SetBytes(total)
			var out []byte
			for b.Loop() {
				for _, f := range files[200:] {
					if out, err = enc.Encode(out[:0], f); err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}
