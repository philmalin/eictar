package codec

import (
	"bytes"
	"testing"
)

// BenchmarkDecoderSetup compares a decoder made for each chunk, as the reader
// makes one for each member, with one decoder that decodes every chunk
// (doc/design.md 15.2, "A decoder for each worker"). The chunk is a small
// source file, so the cost of the setup is as large as it can be, compared
// with the decode. maxPlain is the default chunk size, as in the reader.
//
//	go test -run - -bench DecoderSetup ./src/internal/codec/
func BenchmarkDecoderSetup(b *testing.B) {
	const maxPlain = 4 << 20
	files := sourceLike(200)
	src := files[17]
	dict, err := TrainDict("zstd", nil, files, 16<<10, 40000)
	if err != nil {
		b.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		dict []byte
	}{
		{"zstd", nil}, {"zstd+dict", dict}, {"gzip", nil}, {"s2", nil}, {"xz", nil},
	} {
		codecName := tc.name
		if tc.dict != nil {
			codecName = "zstd"
		}
		enc, err := NewEncoderWith(codecName, nil, EncoderOptions{Concurrency: 1, Dict: tc.dict})
		if err != nil {
			b.Fatal(err)
		}
		packed, err := enc.Encode(nil, src)
		enc.Close()
		if err != nil {
			b.Fatal(err)
		}
		check := func(b *testing.B, out []byte) {
			if !bytes.Equal(out, src) {
				b.Fatal("decoded content differs")
			}
		}

		b.Run(tc.name+"/new", func(b *testing.B) {
			b.SetBytes(int64(len(src)))
			b.ReportAllocs()
			var out []byte
			for b.Loop() {
				dec, err := NewDecoderWithDict(codecName, maxPlain, tc.dict)
				if err != nil {
					b.Fatal(err)
				}
				if out, err = dec.Decode(out[:0], packed, len(src)); err != nil {
					b.Fatal(err)
				}
				dec.Close()
			}
			check(b, out)
		})
		b.Run(tc.name+"/reused", func(b *testing.B) {
			b.SetBytes(int64(len(src)))
			b.ReportAllocs()
			dec, err := NewDecoderWithDict(codecName, maxPlain, tc.dict)
			if err != nil {
				b.Fatal(err)
			}
			defer dec.Close()
			var out []byte
			for b.Loop() {
				if out, err = dec.Decode(out[:0], packed, len(src)); err != nil {
					b.Fatal(err)
				}
			}
			check(b, out)
		})
	}
}
