package format

import (
	"fmt"
	"testing"
)

// benchIndex is an index of n regular files, as a tree of small files makes
// them: each with an owner, times, a digest and one chunk.
func benchIndex(n int) *Index {
	ix := &Index{Version: IndexVersion, Generation: 1,
		Codecs: []CodecSpec{{Name: "zstd", Params: map[string]any{"level": 3}}}}
	for i := range n {
		digest := make([]byte, DigestSize)
		for k := range digest {
			digest[k] = byte(i*31 + k)
		}
		size := uint64(500 + i%6000)
		ix.Members = append(ix.Members, Member{
			ID: uint64(i + 1), Generation: 1, Type: TypeReg, Mode: 0o644,
			Path: fmt.Sprintf("src/%03d/f%05d.go", i%200, i),
			UID:  OwnerID(1000), GID: OwnerID(1000), Uname: "user", Gname: "user",
			MTimeNanos: 1_790_000_000_000_000_000 + int64(i), Size: size,
			Digest: digest, Codec: 0, ChunkSize: 4 << 20,
			Offset: uint64(64 + i*2000), Length: size / 3, Chunks: []uint32{uint32(size / 3)},
		})
	}
	return ix
}

// BenchmarkDecodeIndex measures the decode of an index of 20000 members,
// which every operation does when it opens an archive.
//
//	go test -run - -bench DecodeIndex ./src/internal/format/
func BenchmarkDecodeIndex(b *testing.B) {
	enc, err := benchIndex(20000).Encode(EncodeOptions{Compress: true})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := DecodeIndex(enc.Bytes, enc.Flags, nil); err != nil {
			b.Fatal(err)
		}
	}
}
