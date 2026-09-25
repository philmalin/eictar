package format

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"lukechampine.com/blake3"
)

// sampleIndex builds an index exercising every member type and most optional
// fields, so a round-trip test actually covers the schema rather than a happy
// path through it.
func sampleIndex() *Index {
	return &Index{
		Version:    IndexVersion,
		Generation: 3,
		Codecs: []CodecSpec{
			{Name: "zstd", Params: map[string]any{"level": uint64(19), "long": uint64(27)}},
			{Name: "xz", Params: map[string]any{"preset": uint64(6)}},
		},
		Members: []Member{
			{
				ID: 1, Generation: 1, Path: "src/main.go", Type: TypeReg,
				Mode: 0o644, UID: OwnerID(1000), GID: OwnerID(1000), Uname: "psm", Gname: "psm",
				MTimeNanos: 1758326400123456789,
				ATimeNanos: 1758326400000000000,
				Size:       4096,
				Digest:     bytes.Repeat([]byte{0xab}, DigestSize),
				Codec:      0,
				ChunkSize:  2048, // 4096 bytes of plaintext = 2 chunks
				Offset:     64, Length: 1200,
				Chunks: []uint32{1000, 200},
			},
			{
				ID: 2, Generation: 1, Path: "src", Type: TypeDir,
				Mode: 0o755, MTimeNanos: 1, Codec: NoCodec,
			},
			{
				ID: 3, Generation: 1, Path: "link", Type: TypeSymlink,
				Mode: 0o777, LinkTarget: "../elsewhere/target", Codec: NoCodec,
			},
			{
				ID: 4, Generation: 2, Path: "same-inode", Type: TypeHardlink,
				Mode: 0o644, HardlinkTo: 1, Codec: NoCodec,
			},
			{
				ID: 5, Generation: 2, Path: "dev/null", Type: TypeCharDev,
				Mode: 0o666, RDev: []uint32{1, 3}, Codec: NoCodec,
			},
			{
				ID: 6, Generation: 2, Path: "sparse.img", Type: TypeReg,
				// 1 GiB logical, of which 12 KiB is data: one chunk of payload.
				Mode: 0o600, Size: 1 << 30, Codec: 1, ChunkSize: 1 << 20,
				Sparse: []SparseSegment{{Offset: 0, Length: 4096}, {Offset: 1 << 29, Length: 8192}},
				Xattrs: map[string][]byte{
					"user.comment":            []byte("hello"),
					"system.posix_acl_access": {0x02, 0x00, 0x00, 0x00},
					"user.binary":             {0xde, 0xad, 0xbe, 0xef, 0x00, 0xff},
				},
				Digest: bytes.Repeat([]byte{0x11}, DigestSize),
				Offset: 4096, Length: 400,
				Chunks: []uint32{400},
			},
			{
				ID: 7, Generation: 3, Path: "deleted.txt", Type: TypeReg,
				Mode: 0o644, Codec: NoCodec, Dead: true, Size: 10, ChunkSize: 4 << 20,
				Digest: bytes.Repeat([]byte{0x22}, DigestSize),
				Offset: 9000, Length: 10, Chunks: []uint32{10},
			},
			{
				ID: 8, Generation: 3, Path: "encrypted.bin", Type: TypeReg,
				Mode: 0o600, Size: 10, Codec: NoCodec, ChunkSize: 4 << 20,
				Digest: bytes.Repeat([]byte{0x33}, DigestSize),
				Enc:    &EncInfo{Salt: bytes.Repeat([]byte{0x5a}, 16)},
				Offset: 9100, Length: 26, Chunks: []uint32{26},
			},
			{
				// A POSIX filename is a byte sequence, not text. This one is
				// Latin-1 "caf\xe9.txt", which is not valid UTF-8 and must
				// survive the index unchanged.
				ID: 12, Generation: 3, Path: "caf\xe9.txt", Type: TypeReg,
				Mode: 0o644, Codec: NoCodec, Size: 3, ChunkSize: 4 << 20,
				Digest: bytes.Repeat([]byte{0x44}, DigestSize),
				Offset: 9200, Length: 3, Chunks: []uint32{3},
			},
			{
				// Newline and quote in a name, which shell-oriented tools
				// routinely mangle.
				ID: 13, Generation: 3, Path: "odd\n\"name\t.txt", Type: TypeReg,
				Mode: 0o644, Codec: NoCodec, Size: 1, ChunkSize: 4 << 20,
				Digest: bytes.Repeat([]byte{0x55}, DigestSize),
				Offset: 9300, Length: 1, Chunks: []uint32{1},
			},
			{
				ID: 9, Generation: 3, Path: "fifo", Type: TypeFIFO,
				Mode: 0o600, Codec: NoCodec,
			},
			{
				ID: 10, Generation: 3, Path: "sock", Type: TypeSocket,
				Mode: 0o600, Codec: NoCodec,
			},
			{
				ID: 11, Generation: 3, Path: "dev/sda", Type: TypeBlockDev,
				Mode: 0o660, RDev: []uint32{8, 0}, Codec: NoCodec,
			},
		},
	}
}

func TestIndexRoundTrip(t *testing.T) {
	for _, compress := range []bool{false, true} {
		t.Run(fmt.Sprintf("compress=%v", compress), func(t *testing.T) {
			want := sampleIndex()

			enc, err := want.Encode(EncodeOptions{Compress: compress})
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			if compress != (enc.Flags&FlagIndexCompressed != 0) {
				t.Errorf("flags = %#x, compress = %v", enc.Flags, compress)
			}
			if enc.Flags&FlagIndexEncrypted != 0 {
				t.Error("unsealed index must not carry the encrypted flag")
			}

			got, err := DecodeIndex(enc.Bytes, enc.Flags, nil)
			if err != nil {
				t.Fatalf("DecodeIndex: %v", err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("round trip changed the index:\n got %+v\nwant %+v", got, want)
			}
		})
	}
}

// TestIndexSealRoundTrip uses a stand-in sealer. The real one arrives in M4;
// what is being tested here is that the pipeline calls it in the right order
// and sets the right flag.
func TestIndexSealRoundTrip(t *testing.T) {
	const marker = "SEALED:"

	seal := func(p []byte) ([]byte, error) { return append([]byte(marker), p...), nil }
	open := func(c []byte) ([]byte, error) {
		if !bytes.HasPrefix(c, []byte(marker)) {
			return nil, errors.New("bad seal")
		}
		return c[len(marker):], nil
	}

	want := sampleIndex()
	enc, err := want.Encode(EncodeOptions{Compress: true, Seal: seal})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if enc.Flags&FlagIndexEncrypted == 0 {
		t.Fatal("sealed index must carry the encrypted flag")
	}
	if !bytes.HasPrefix(enc.Bytes, []byte(marker)) {
		t.Fatal("seal must be the outermost layer, applied after compression")
	}

	got, err := DecodeIndex(enc.Bytes, enc.Flags, open)
	if err != nil {
		t.Fatalf("DecodeIndex: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Error("sealed round trip changed the index")
	}
}

func TestIndexDecodeSealMismatch(t *testing.T) {
	ix := sampleIndex()
	enc, err := ix.Encode(EncodeOptions{Compress: true})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Sealed flag, no opener.
	if _, err := DecodeIndex(enc.Bytes, enc.Flags|FlagIndexEncrypted, nil); err == nil {
		t.Error("decoding a sealed index without an opener should fail")
	}
	// Opener, but the index is not sealed: silently decoding would be worse.
	open := func(c []byte) ([]byte, error) { return c, nil }
	if _, err := DecodeIndex(enc.Bytes, enc.Flags, open); err == nil {
		t.Error("supplying an opener for an unsealed index should fail")
	}
}

func TestIndexDigestCoversOnDiskBytes(t *testing.T) {
	ix := sampleIndex()
	enc, err := ix.Encode(EncodeOptions{Compress: true})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// The trailer digest must cover exactly what is written, so that a
	// verifier can check it without decompressing or decrypting anything.
	again, err := sampleIndex().Encode(EncodeOptions{Compress: true})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if enc.Digest != again.Digest {
		t.Error("encoding the same index twice produced different digests")
	}
	if !bytes.Equal(enc.Bytes, again.Bytes) {
		t.Error("encoding the same index twice produced different bytes")
	}

	enc.Bytes[len(enc.Bytes)/2] ^= 0x01
	if d := blake3.Sum256(enc.Bytes); d == enc.Digest {
		t.Error("digest did not change when the bytes did")
	}
}

func TestIndexLiveAndCount(t *testing.T) {
	ix := sampleIndex()

	live := ix.Live()
	if got, want := uint64(len(live)), ix.LiveCount(); got != want {
		t.Errorf("Live() returned %d members, LiveCount() says %d", got, want)
	}
	if got, want := ix.LiveCount(), uint64(len(ix.Members)-1); got != want {
		t.Errorf("LiveCount = %d, want %d (one tombstone in the fixture)", got, want)
	}
	for _, m := range live {
		if m.Dead {
			t.Errorf("Live() returned tombstoned member %d", m.ID)
		}
	}
}

func TestIndexValidateRejects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(ix *Index)
	}{
		{"duplicate id", func(ix *Index) { ix.Members[1].ID = ix.Members[0].ID }},
		{"empty path", func(ix *Index) { ix.Members[0].Path = "" }},
		{"unknown type", func(ix *Index) { ix.Members[0].Type = MemberType("wormhole") }},
		{"codec out of range", func(ix *Index) { ix.Members[0].Codec = len(ix.Codecs) }},
		{"codec below NoCodec", func(ix *Index) { ix.Members[0].Codec = -2 }},
		{"short digest", func(ix *Index) { ix.Members[0].Digest = []byte{1, 2, 3} }},
		{"rdev with one component", func(ix *Index) { ix.Members[4].RDev = []uint32{1} }},
		{"chunks do not sum to length", func(ix *Index) { ix.Members[0].Chunks[0]++ }},
		{"chunk table with no chunk size", func(ix *Index) { ix.Members[0].ChunkSize = 0 }},
		{"chunks too few for the size", func(ix *Index) { ix.Members[0].ChunkSize = 4 }},
		{"chunks too many for the size", func(ix *Index) { ix.Members[0].ChunkSize = 1 << 20 }},
		{"size with no chunks", func(ix *Index) {
			ix.Members[0].Chunks = nil
			ix.Members[0].Length = 0
		}},
		{"blob range overflows", func(ix *Index) {
			ix.Members[0].Offset = ^uint64(0) - 1
			ix.Members[0].Length = 1200
		}},
		{"symlink claiming content", func(ix *Index) { ix.Members[2].Size = 10 }},
		{"chunk size above the limit", func(ix *Index) { ix.Members[0].ChunkSize = MaxChunkSize + 1 }},

		// M5: each field belongs to its type.
		{"mode with file-type bits", func(ix *Index) { ix.Members[0].Mode = 0o100644 }},
		{"hardlink with no target", func(ix *Index) { ix.Members[3].HardlinkTo = 0 }},
		{"hardlink to a missing member", func(ix *Index) { ix.Members[3].HardlinkTo = 999 }},
		{"hardlink to a directory", func(ix *Index) { ix.Members[3].HardlinkTo = 2 }},
		{"hardlink to a hardlink", func(ix *Index) { ix.Members[3].HardlinkTo = 4 }},
		{"hardlink target on a file", func(ix *Index) { ix.Members[0].HardlinkTo = 1 }},
		{"symlink with no target", func(ix *Index) { ix.Members[2].LinkTarget = "" }},
		{"link target on a file", func(ix *Index) { ix.Members[0].LinkTarget = "/etc/passwd" }},
		{"device with no rdev", func(ix *Index) { ix.Members[4].RDev = nil }},
		{"rdev on a directory", func(ix *Index) { ix.Members[1].RDev = []uint32{1, 3} }},
		{"sparse map on a directory", func(ix *Index) {
			ix.Members[1].Sparse = []SparseSegment{{Offset: 0, Length: 1}}
		}},
		{"sparse segment past the end", func(ix *Index) {
			ix.Members[5].Sparse[1].Offset = 1 << 30
		}},
		{"sparse segments overlapping", func(ix *Index) {
			ix.Members[5].Sparse[1].Offset = 100
		}},
		{"sparse segments out of order", func(ix *Index) {
			ix.Members[5].Sparse[0], ix.Members[5].Sparse[1] = ix.Members[5].Sparse[1], ix.Members[5].Sparse[0]
		}},
		{"empty sparse segment", func(ix *Index) { ix.Members[5].Sparse[0].Length = 0 }},
		{"sparse payload the chunks cannot hold", func(ix *Index) {
			ix.Members[5].Sparse[1].Length = 4 << 20
		}},
		{"xattr name too long", func(ix *Index) {
			ix.Members[5].Xattrs[strings.Repeat("u", MaxXattrName+1)] = []byte("x")
		}},
		{"xattr value too large", func(ix *Index) {
			ix.Members[5].Xattrs["user.big"] = make([]byte, MaxXattrValue+1)
		}},
		{"empty xattr name", func(ix *Index) { ix.Members[5].Xattrs[""] = []byte("x") }},
		{"regular file with no digest", func(ix *Index) { ix.Members[0].Digest = nil }},
		{"directory with a payload", func(ix *Index) {
			ix.Members[1].Length = 10
			ix.Members[1].Chunks = []uint32{10}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ix := sampleIndex()
			tc.mutate(ix)

			if err := ix.Validate(); !errors.Is(err, ErrCorruptIndex) {
				t.Errorf("Validate error = %v, want ErrCorruptIndex", err)
			}
			// Encode must refuse too: our own bug should never reach the disk.
			if _, err := ix.Encode(EncodeOptions{Compress: true}); err == nil {
				t.Error("Encode accepted an invalid index")
			}
		})
	}
}

// TestIndexDecodeRejectsCorruptBytes feeds decode the kinds of damage a real
// archive suffers, rather than only structured mutations.
func TestIndexDecodeRejectsCorruptBytes(t *testing.T) {
	enc, err := sampleIndex().Encode(EncodeOptions{Compress: true})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"truncated", enc.Bytes[:len(enc.Bytes)/2]},
		{"flipped byte", func() []byte {
			b := bytes.Clone(enc.Bytes)
			b[len(b)/2] ^= 0xff
			return b
		}()},
		{"random", bytes.Repeat([]byte{0x5a}, 128)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeIndex(tc.in, FlagIndexCompressed, nil); err == nil {
				t.Error("decode accepted corrupt input")
			}
		})
	}
}

func TestIndexDecodeRejectsWrongSchemaVersion(t *testing.T) {
	ix := sampleIndex()
	ix.Version = IndexVersion + 1

	// Validate does not police the version, so encode by hand.
	enc, err := ix.Encode(EncodeOptions{Compress: false})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if _, err := DecodeIndex(enc.Bytes, enc.Flags, nil); !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("error = %v, want ErrUnsupportedVersion", err)
	}
}

// TestIndexDecompressionBomb is the decode-side limit: a tiny input that
// inflates without bound must be refused, not allocated.
func TestIndexDecompressionBomb(t *testing.T) {
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
	if err != nil {
		t.Fatalf("zstd writer: %v", err)
	}
	bomb := enc.EncodeAll(make([]byte, MaxIndexSize+(1<<20)), nil)
	if err := enc.Close(); err != nil {
		t.Fatalf("zstd close: %v", err)
	}
	t.Logf("bomb is %d bytes compressed, %d decompressed", len(bomb), MaxIndexSize+(1<<20))

	if _, err := DecodeIndex(bomb, FlagIndexCompressed, nil); err == nil {
		t.Fatal("decode accepted a decompression bomb")
	} else if !errors.Is(err, ErrIndexTooLarge) && !errors.Is(err, ErrCorruptIndex) {
		t.Errorf("error = %v, want ErrIndexTooLarge or ErrCorruptIndex", err)
	}
}

func TestIndexEncodeDefaultsVersion(t *testing.T) {
	ix := &Index{Members: []Member{{ID: 1, Path: "a", Type: TypeDir, Codec: NoCodec}}}
	if _, err := ix.Encode(EncodeOptions{}); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if ix.Version != IndexVersion {
		t.Errorf("Version = %d, want %d", ix.Version, IndexVersion)
	}
}

func TestIndexEmptyArchive(t *testing.T) {
	ix := &Index{Version: IndexVersion, Generation: 1, Members: []Member{}}

	enc, err := ix.Encode(EncodeOptions{Compress: true})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := DecodeIndex(enc.Bytes, enc.Flags, nil)
	if err != nil {
		t.Fatalf("DecodeIndex: %v", err)
	}
	if got.LiveCount() != 0 {
		t.Errorf("LiveCount = %d, want 0", got.LiveCount())
	}
}

// TestIndexWithManyChunks is a regression test for the decoder's array bound.
//
// The bound is derived from the encoded length, so it has to assume the
// smallest an array element can be. A chunk length is a small integer that
// encodes in one to five bytes, and a single large member puts thousands of
// them in an otherwise tiny index: one member, one path, one huge chunk
// table. Assume too much per element and a valid archive stops decoding.
func TestIndexWithManyChunks(t *testing.T) {
	for _, chunks := range []int{48, 1000, 100_000} {
		t.Run(fmt.Sprintf("chunks=%d", chunks), func(t *testing.T) {
			const chunkSize = 4 << 20

			m := Member{
				ID: 1, Generation: 1, Path: "big.img", Type: TypeReg,
				Mode: 0o644, Codec: NoCodec, ChunkSize: chunkSize,
				Digest: bytes.Repeat([]byte{0x66}, DigestSize),
				Size:   uint64(chunkSize) * uint64(chunks),
				Offset: 64,
			}
			for range chunks {
				m.Chunks = append(m.Chunks, chunkSize)
				m.Length += chunkSize
			}

			ix := &Index{Version: IndexVersion, Generation: 1, Members: []Member{m}}
			enc, err := ix.Encode(EncodeOptions{Compress: true})
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			t.Logf("%d chunks -> %d bytes on disk", chunks, len(enc.Bytes))

			got, err := DecodeIndex(enc.Bytes, enc.Flags, nil)
			if err != nil {
				t.Fatalf("DecodeIndex: %v", err)
			}
			if len(got.Members[0].Chunks) != chunks {
				t.Errorf("decoded %d chunks, want %d", len(got.Members[0].Chunks), chunks)
			}
		})
	}
}

// TestPayloadSize: a sparse member stores only its data segments, so the
// chunk table is measured against those, not against the logical size.
func TestPayloadSize(t *testing.T) {
	dense := Member{Size: 1000}
	if got := dense.PayloadSize(); got != 1000 {
		t.Errorf("dense payload = %d, want 1000", got)
	}
	sparse := Member{Size: 1 << 30, Sparse: []SparseSegment{{0, 10}, {1 << 20, 20}}}
	if got := sparse.PayloadSize(); got != 30 {
		t.Errorf("sparse payload = %d, want 30", got)
	}
}

// TestOwnerIsOptional: --no-owner must be distinguishable from uid 0, or a
// reader with --preserve-owner would make every file root's.
func TestOwnerIsOptional(t *testing.T) {
	ix := sampleIndex()
	ix.Members[0].UID, ix.Members[0].GID = nil, nil

	enc, err := ix.Encode(EncodeOptions{Compress: true})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := DecodeIndex(enc.Bytes, enc.Flags, nil)
	if err != nil {
		t.Fatalf("DecodeIndex: %v", err)
	}
	if got.Members[0].UID != nil || got.Members[0].GID != nil {
		t.Error("an unrecorded owner came back as a value")
	}

	ix.Members[0].UID = OwnerID(0)
	enc, _ = ix.Encode(EncodeOptions{Compress: true})
	got, _ = DecodeIndex(enc.Bytes, enc.Flags, nil)
	if got.Members[0].UID == nil || *got.Members[0].UID != 0 {
		t.Error("uid 0 did not survive as a recorded root owner")
	}
}
