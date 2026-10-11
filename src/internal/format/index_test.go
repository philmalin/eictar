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
			{Name: "zstd", Params: map[string]any{"level": uint64(19)}, Dict: 40000},
		},
		Dicts: []Dict{
			{ID: 40000, Generation: 2, Size: 1000, Digest: bytes.Repeat([]byte{0x44}, DigestSize), Offset: 20000, Length: 1000},
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
				// A copy of src/main.go: it shares that member's blob
				// (doc/design.md 4.3).
				ID: 20, Generation: 3, Path: "copy/main.go", Type: TypeReg,
				Mode: 0o644, Size: 4096, Codec: NoCodec, Data: 1,
				Digest: bytes.Repeat([]byte{0xab}, DigestSize),
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

// TestIndexValidateRejects: each case breaks one rule, and the error must
// name that rule. Without the name, a later check that refuses the same index
// for another reason hides a check that is gone (doc/design.md 13.5).
func TestIndexValidateRejects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		want   string // a part of the error message
		mutate func(ix *Index)
	}{
		{"duplicate id", "duplicate member id", func(ix *Index) { ix.Members[1].ID = ix.Members[0].ID }},
		{"empty path", "empty path", func(ix *Index) { ix.Members[0].Path = "" }},
		{"unknown type", "unknown type", func(ix *Index) { ix.Members[0].Type = MemberType("wormhole") }},
		{"unknown type with no content", "unknown type", func(ix *Index) { ix.Members[1].Type = MemberType("wormhole") }},
		{"codec out of range", "references codec", func(ix *Index) { ix.Members[0].Codec = len(ix.Codecs) }},
		{"codec below NoCodec", "references codec", func(ix *Index) { ix.Members[0].Codec = -2 }},
		{"short digest", "3-byte digest", func(ix *Index) { ix.Members[0].Digest = []byte{1, 2, 3} }},
		{"short digest on a directory", "3-byte digest", func(ix *Index) { ix.Members[1].Digest = []byte{1, 2, 3} }},
		{"rdev with one component", "1 rdev components", func(ix *Index) { ix.Members[4].RDev = []uint32{1} }},
		{"chunks do not sum to length", "chunks total", func(ix *Index) { ix.Members[0].Chunks[0]++ }},
		{"chunk table with no chunk size", "no chunk size", func(ix *Index) { ix.Members[0].ChunkSize = 0 }},
		{"chunks too few for the size", "cannot fill", func(ix *Index) { ix.Members[0].ChunkSize = 4 }},
		{"chunks too many for the size", "cannot fill", func(ix *Index) { ix.Members[0].ChunkSize = 1 << 20 }},
		{"empty last chunk", "cannot fill", func(ix *Index) {
			// 4096 bytes need two chunks of 2048, not three.
			ix.Members[0].Chunks = append(ix.Members[0].Chunks, 0)
		}},
		{"payload of exactly n-1 chunks, of three", "cannot fill", func(ix *Index) {
			ix.Members[0].Chunks = []uint32{1000, 100, 100}
		}},
		{"one chunk for an empty payload", "cannot fill", func(ix *Index) {
			m := &ix.Members[7]
			m.Size, m.Digest, m.Chunks, m.Length = 0, bytes.Repeat([]byte{0x33}, DigestSize), []uint32{16}, 16
		}},
		{"chunk size and no chunks", "a chunk size of 4194304 but no chunks", func(ix *Index) {
			m := &ix.Members[7]
			m.Size, m.Chunks, m.Length = 0, nil, 0
		}},
		{"size with no chunks", "payload of 4096 bytes but no chunks", func(ix *Index) {
			ix.Members[0].Chunks = nil
			ix.Members[0].Length = 0
		}},
		{"blob range overflows", "overflows", func(ix *Index) {
			ix.Members[0].Offset = ^uint64(0) - 1
			ix.Members[0].Length = 1200
		}},
		{"chunk size above the limit", "claims a chunk size", func(ix *Index) { ix.Members[0].ChunkSize = MaxChunkSize + 1 }},
		{"chunk size above the limit, one chunk", "claims a chunk size", func(ix *Index) {
			// One chunk of 10 bytes fits any chunk size: only the limit refuses it.
			ix.Members[7].ChunkSize = MaxChunkSize + 1
		}},

		// Only a regular file has content (doc/format.md 8.3).
		{"symlink claiming content", "a symlink with content", func(ix *Index) { ix.Members[2].Size = 10 }},
		{"directory with a payload", "a dir with content", func(ix *Index) {
			ix.Members[1].Length = 10
			ix.Members[1].Chunks = []uint32{10}
		}},
		{"directory with a blob and a chunk size", "a dir with content", func(ix *Index) {
			ix.Members[1].Length, ix.Members[1].Chunks, ix.Members[1].ChunkSize = 10, []uint32{10}, 16
		}},
		{"directory with only a size", "a dir with content", func(ix *Index) { ix.Members[1].Size = 10 }},
		{"directory with only a length", "a dir with content", func(ix *Index) { ix.Members[1].Length = 10 }},
		{"directory with only chunks", "a dir with content", func(ix *Index) { ix.Members[1].Chunks = []uint32{10} }},
		{"directory with only a chunk size", "a dir with content", func(ix *Index) { ix.Members[1].ChunkSize = 4096 }},

		// M5: each field belongs to its type.
		{"mode with file-type bits", "carries bits", func(ix *Index) { ix.Members[0].Mode = 0o100644 }},
		{"hardlink with no target", "hardlink with no target member", func(ix *Index) { ix.Members[3].HardlinkTo = 0 }},
		{"hardlink to a missing member", "which does not exist", func(ix *Index) { ix.Members[3].HardlinkTo = 999 }},
		{"hardlink to a directory", "which is a dir", func(ix *Index) { ix.Members[3].HardlinkTo = 2 }},
		{"hardlink to a hardlink", "which is a hardlink", func(ix *Index) { ix.Members[3].HardlinkTo = 4 }},
		{"hardlink target on a file", "hardlink target on a member", func(ix *Index) { ix.Members[0].HardlinkTo = 1 }},
		{"symlink with no target", "symlink with no target", func(ix *Index) { ix.Members[2].LinkTarget = "" }},
		{"link target on a file", "link target on a member", func(ix *Index) { ix.Members[0].LinkTarget = "/etc/passwd" }},
		{"device with no rdev", "0 rdev components", func(ix *Index) { ix.Members[4].RDev = nil }},
		{"rdev on a directory", "device number on a member", func(ix *Index) { ix.Members[1].RDev = []uint32{1, 3} }},
		{"sparse map on a directory", "sparse map on a member", func(ix *Index) {
			ix.Members[1].Sparse = []SparseSegment{{Offset: 0, Length: 1}}
		}},
		{"sparse segment past the end", "past the file size", func(ix *Index) {
			ix.Members[5].Sparse[1].Offset = 1 << 30
		}},
		{"sparse segments overlapping", "overlaps", func(ix *Index) {
			ix.Members[5].Sparse[1].Offset = 100
		}},
		{"sparse segments out of order", "out of order", func(ix *Index) {
			ix.Members[5].Sparse[0], ix.Members[5].Sparse[1] = ix.Members[5].Sparse[1], ix.Members[5].Sparse[0]
		}},
		{"sparse segment overflows", "sparse segment 1 overflows", func(ix *Index) {
			// The end wraps round to 4096, inside the file: only the overflow
			// check refuses it. The payload stays 12 KiB, as the chunks say.
			ix.Members[5].Sparse[1].Offset = ^uint64(0) - 4095
		}},
		{"empty sparse segment", "is empty", func(ix *Index) { ix.Members[5].Sparse[0].Length = 0 }},
		{"sparse payload the chunks cannot hold", "cannot fill", func(ix *Index) {
			ix.Members[5].Sparse[1].Length = 4 << 20
		}},
		{"too many xattrs", "extended attributes, above", func(ix *Index) {
			for i := range MaxXattrs + 1 {
				ix.Members[5].Xattrs[fmt.Sprintf("user.%d", i)] = nil
			}
		}},
		{"xattr name too long", "256-byte name", func(ix *Index) {
			ix.Members[5].Xattrs[strings.Repeat("u", MaxXattrName+1)] = []byte("x")
		}},
		{"xattr value too large", "is 65537 bytes", func(ix *Index) {
			ix.Members[5].Xattrs["user.big"] = make([]byte, MaxXattrValue+1)
		}},
		{"empty xattr name", "0-byte name", func(ix *Index) { ix.Members[5].Xattrs[""] = []byte("x") }},
		{"regular file with no digest", "regular file with no digest", func(ix *Index) { ix.Members[0].Digest = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ix := sampleIndex()
			tc.mutate(ix)

			err := ix.Validate()
			if !errors.Is(err, ErrCorruptIndex) {
				t.Fatalf("Validate error = %v, want ErrCorruptIndex", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Validate error = %v, want one that says %q", err, tc.want)
			}
			// Encode must refuse too: our own bug should never reach the disk.
			if _, err := ix.Encode(EncodeOptions{Compress: true}); err == nil {
				t.Error("Encode accepted an invalid index")
			}
			// And a reader must refuse it when an archive holds it.
			raw, err := encMode.Marshal(ix)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeIndex(raw, 0, nil); !errors.Is(err, ErrCorruptIndex) {
				t.Errorf("DecodeIndex error = %v, want ErrCorruptIndex", err)
			}
		})
	}
}

// TestIndexValidateAcceptsEdges: shapes at the edge of each rule that a
// writer makes, and that a reader must accept. A refused archive is lost data
// too.
func TestIndexValidateAcceptsEdges(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(ix *Index)
	}{
		{"empty file", func(ix *Index) {
			m := &ix.Members[7]
			m.Size, m.Offset, m.Length, m.Chunks, m.ChunkSize, m.Enc = 0, 0, 0, nil, 0, nil
		}},
		{"payload one byte into its last chunk", func(ix *Index) {
			// 2049 bytes in chunks of 2048: the second chunk has one byte.
			ix.Members[0].Size, ix.Members[8].Size = 2049, 2049
		}},
		{"payload of exactly n chunks", func(ix *Index) {
			ix.Members[0].Size, ix.Members[8].Size = 4096, 4096
		}},
		{"one-byte file", func(ix *Index) {
			m := &ix.Members[7]
			m.Size, m.Length, m.Chunks = 1, 17, []uint32{17}
		}},
		{"sparse segments that touch", func(ix *Index) {
			ix.Members[5].Sparse[1].Offset = 4096
		}},
		{"sparse segment that ends at the size", func(ix *Index) {
			ix.Members[5].Sparse[1].Offset = 1<<30 - 8192
		}},
		// A member with no blob has no off, but eictar 1.1.0 and earlier
		// wrote one there, and a reader accepts it (doc/format.md 8.3).
		{"an offset on a directory", func(ix *Index) { ix.Members[1].Offset = 64 }},
		{"an offset on an empty file", func(ix *Index) {
			m := &ix.Members[7]
			m.Size, m.Offset, m.Length, m.Chunks, m.ChunkSize, m.Enc = 0, 64, 0, nil, 0, nil
		}},

		// Each limit at its exact value: the value one more is refused above.
		{"chunk size at the limit", func(ix *Index) { ix.Members[7].ChunkSize = MaxChunkSize }},
		{"xattrs at the limit", func(ix *Index) {
			for i := len(ix.Members[5].Xattrs); i < MaxXattrs; i++ {
				ix.Members[5].Xattrs[fmt.Sprintf("user.%d", i)] = nil
			}
		}},
		{"xattr name at the limit", func(ix *Index) {
			ix.Members[5].Xattrs[strings.Repeat("u", MaxXattrName)] = []byte("x")
		}},
		{"xattr value at the limit", func(ix *Index) {
			ix.Members[5].Xattrs["user.big"] = make([]byte, MaxXattrValue)
		}},
		{"dictionaries at the limit", func(ix *Index) {
			for i := len(ix.Dicts); i < MaxDicts; i++ {
				d := ix.Dicts[0]
				d.ID = uint32(50000 + i)
				ix.Dicts = append(ix.Dicts, d)
			}
		}},
		{"dictionary at the size limit", func(ix *Index) {
			ix.Dicts[0].Size, ix.Dicts[0].Length = MaxDictSize, MaxDictSize
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ix := sampleIndex()
			tc.mutate(ix)
			if err := ix.Validate(); err != nil {
				t.Errorf("Validate refused a valid index: %v", err)
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
			if _, err := DecodeIndex(tc.in, FlagIndexCompressed, nil); !errors.Is(err, ErrCorruptIndex) {
				// Damage is not ErrIndexTooLarge: that error is for an index
				// that expands too far.
				t.Errorf("decode error = %v, want ErrCorruptIndex", err)
			}
		})
	}

	// Bytes after the CBOR map are damage too. A decoder that stops at the
	// end of the map and returns what it has hides it.
	plain, err := sampleIndex().Encode(EncodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeIndex(append(plain.Bytes, 0x00), 0, nil); !errors.Is(err, ErrCorruptIndex) {
		t.Errorf("extra bytes after the index: got %v, want ErrCorruptIndex", err)
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

// TestIndexValidateRejectsDicts: a dictionary that no reader could trust, or
// a catalog entry that names one the index does not hold.
func TestIndexValidateRejectsDicts(t *testing.T) {
	for _, tc := range []struct {
		name string
		mod  func(ix *Index)
	}{
		{"id 0", func(ix *Index) { ix.Dicts[0].ID = 0 }},
		{"duplicate id", func(ix *Index) { ix.Dicts = append(ix.Dicts, ix.Dicts[0]) }},
		{"empty", func(ix *Index) { ix.Dicts[0].Size = 0 }},
		{"too large", func(ix *Index) { ix.Dicts[0].Size, ix.Dicts[0].Length = MaxDictSize+1, MaxDictSize+1 }},
		{"short digest", func(ix *Index) { ix.Dicts[0].Digest = []byte{1} }},
		{"blob shorter than the dictionary", func(ix *Index) { ix.Dicts[0].Length = 10 }},
		{"blob range overflows", func(ix *Index) { ix.Dicts[0].Offset = ^uint64(0) - 5 }},
		{"catalog names a missing dictionary", func(ix *Index) { ix.Codecs[2].Dict = 40001 }},
		{"dictionary on xz", func(ix *Index) { ix.Codecs[1].Dict = 40000 }},
		{"too many", func(ix *Index) {
			for i := 0; i <= MaxDicts; i++ {
				d := ix.Dicts[0]
				d.ID = uint32(50000 + i)
				ix.Dicts = append(ix.Dicts, d)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ix := sampleIndex()
			tc.mod(ix)
			if err := ix.Validate(); err == nil {
				t.Error("accepted")
			}
		})
	}
	if s := sampleIndex().Codecs[2].String(); s != "zstd:level=19,dict" {
		t.Errorf("String() = %q", s)
	}
	if s := (CodecSpec{Name: "zstd", Dict: 5}).String(); s != "zstd:dict" {
		t.Errorf("String() = %q", s)
	}
	if s := (CodecSpec{Name: "none"}).String(); s != "none" {
		t.Errorf("String() = %q, want the name alone", s)
	}
}

// TestIndexValidateRejectsSharing: a member that shares content must name an
// owner with a blob and the same payload, and must have no blob itself.
func TestIndexValidateRejectsSharing(t *testing.T) {
	sharer := func(ix *Index) *Member {
		for i := range ix.Members {
			if ix.Members[i].Data != 0 {
				return &ix.Members[i]
			}
		}
		panic("no sharer in sampleIndex")
	}
	for _, tc := range []struct {
		name string
		mod  func(ix *Index)
	}{
		{"no owner", func(ix *Index) { sharer(ix).Data = 999 }},
		{"owner without a blob", func(ix *Index) { sharer(ix).Data = 2 }}, // a directory
		{"a chain", func(ix *Index) { ix.Members[0].Data = 8 }},           // the owner shares too
		{"another size", func(ix *Index) { sharer(ix).Size = 4097 }},
		{"another digest", func(ix *Index) { sharer(ix).Digest = bytes.Repeat([]byte{1}, DigestSize) }},
		{"another sparse map", func(ix *Index) { sharer(ix).Sparse = []SparseSegment{{0, 10}} }},
		{"another sparse map of the same length", func(ix *Index) {
			// The holes are in other places, so the member reads other content.
			ix.Members[0].Sparse = []SparseSegment{{0, 4096}}
			sharer(ix).Sparse = []SparseSegment{{1, 4095}}
		}},
		{"an empty owner", func(ix *Index) {
			// The owner is a regular file without a blob: an empty file.
			o := &ix.Members[7]
			o.Size, o.Offset, o.Length, o.Chunks, o.ChunkSize, o.Enc = 0, 0, 0, nil, 0, nil
			s := sharer(ix)
			s.Data, s.Size, s.Digest = o.ID, 0, o.Digest
		}},
		{"a blob of its own", func(ix *Index) { sharer(ix).Offset, sharer(ix).Length, sharer(ix).Chunks = 64, 10, []uint32{10} }},
		// Each field of a blob alone, so that no other check refuses it.
		{"an offset", func(ix *Index) { sharer(ix).Offset = 64 }},
		{"a length", func(ix *Index) { sharer(ix).Length = 10 }},
		{"chunks", func(ix *Index) { sharer(ix).Chunks = []uint32{0} }},
		{"a chunk size", func(ix *Index) { sharer(ix).ChunkSize = 2048 }},
		{"a codec", func(ix *Index) { sharer(ix).Codec = 0 }},
		{"a key", func(ix *Index) { sharer(ix).Enc = &EncInfo{Salt: make([]byte, 16)} }},
		{"on a directory", func(ix *Index) { ix.Members[1].Data = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ix := sampleIndex()
			tc.mod(ix)
			if err := ix.Validate(); err == nil {
				t.Error("accepted")
			}
		})
	}
}

// TestIndexExpansionIsBounded: a small index may not decode to a large one.
// A plain archive of a few KiB made a listing allocate 1 GiB before the
// ratio (doc/Security_Audit.md, finding 6).
func TestIndexExpansionIsBounded(t *testing.T) {
	enc, _ := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
	bomb := enc.EncodeAll(make([]byte, 100<<20), nil) // 100 MiB of zeros
	enc.Close()
	if len(bomb)*MaxIndexRatio >= MinIndexLimit {
		t.Fatalf("the bomb is %d bytes; the test needs it smaller", len(bomb))
	}
	_, err := DecodeIndex(bomb, FlagIndexCompressed, nil)
	if !errors.Is(err, ErrIndexTooLarge) {
		t.Errorf("a %d-byte index that expands to 100 MiB: %v, want ErrIndexTooLarge", len(bomb), err)
	}
	if got := indexLimit(1 << 20); got != 200<<20 {
		t.Errorf("the limit of a 1 MiB index is %d", got)
	}
	if got := indexLimit(100 << 20); got != MaxIndexSize {
		t.Errorf("the limit of a 100 MiB index is %d, want the 1 GiB cap", got)
	}
}

// TestIndexDigestUsesTheKey: the digest that the trailer records comes from
// the caller's function when there is one. That is the keyed digest of an
// encrypted archive (doc/design.md 6.4). The plain hash in its place lets an
// attacker rewrite the metadata and compute a new digest.
func TestIndexDigestUsesTheKey(t *testing.T) {
	mark := [DigestSize]byte{0x6b, 0x65, 0x79}
	var seen []byte
	keyed := func(b []byte) [DigestSize]byte {
		seen = bytes.Clone(b)
		return mark
	}
	enc, err := sampleIndex().Encode(EncodeOptions{Compress: true, Digest: keyed})
	if err != nil {
		t.Fatal(err)
	}
	if enc.Digest != mark {
		t.Errorf("the digest is %x, not the one of the caller's function", enc.Digest)
	}
	if !bytes.Equal(seen, enc.Bytes) {
		t.Error("the caller's function did not get the bytes on disk")
	}
}

// TestIndexDecodeKeepsTheOpenerError: the error of the opener reaches the
// caller. It tells a wrong key from a damaged index, and the two have
// different exit codes.
func TestIndexDecodeKeepsTheOpenerError(t *testing.T) {
	wrongKey := errors.New("wrong key")
	open := func([]byte) ([]byte, error) { return nil, wrongKey }
	if _, err := DecodeIndex([]byte("sealed"), FlagIndexEncrypted, open); !errors.Is(err, wrongKey) {
		t.Errorf("got %v, want the opener's error", err)
	}
}

// TestSameCodec: two entries are the same codec when their encodings are the
// same. A parameter decoded from an index is a uint64, and one from the
// command line is an int: they are the same value.
func TestSameCodec(t *testing.T) {
	a := CodecSpec{Name: "zstd", Params: map[string]any{"level": uint64(19)}}
	for _, tc := range []struct {
		b    CodecSpec
		want bool
	}{
		{CodecSpec{Name: "zstd", Params: map[string]any{"level": 19}}, true},
		{CodecSpec{Name: "zstd", Params: map[string]any{"level": 3}}, false},
		{CodecSpec{Name: "xz", Params: map[string]any{"level": 19}}, false},
		{CodecSpec{Name: "zstd", Params: map[string]any{"level": 19}, Dict: 7}, false},
		{CodecSpec{Name: "zstd"}, false},
		// A value that CBOR cannot encode is never the same as another.
		{CodecSpec{Name: "zstd", Params: map[string]any{"level": make(chan int)}}, false},
	} {
		if got := SameCodec(a, tc.b); got != tc.want {
			t.Errorf("SameCodec(%v, %v) = %v, want %v", a, tc.b, got, tc.want)
		}
	}
	bad := CodecSpec{Name: "zstd", Params: map[string]any{"x": make(chan int)}}
	if SameCodec(bad, bad) {
		t.Error("an entry that does not encode is the same as itself")
	}
}

// TestIndexEncodeErrors: when encoding or sealing fails, Encode returns the
// error and no bytes. A seal that fails must never let the index reach the
// disk as plaintext.
func TestIndexEncodeErrors(t *testing.T) {
	ix := sampleIndex()
	ix.Codecs[0].Params["bad"] = make(chan int)
	if enc, err := ix.Encode(EncodeOptions{}); err == nil {
		t.Errorf("a parameter that CBOR cannot encode gave %d bytes", len(enc.Bytes))
	}

	failed := errors.New("seal failed")
	seal := func([]byte) ([]byte, error) { return nil, failed }
	if enc, err := sampleIndex().Encode(EncodeOptions{Compress: true, Seal: seal}); !errors.Is(err, failed) {
		t.Errorf("a failed seal: %v, %v; want the seal's error", enc, err)
	}
}

// TestIndexMapPairsAreCapped: the decoder takes a map of up to
// maxIndexMapPairs pairs, and refuses a larger one. The codec parameters
// have no other limit.
func TestIndexMapPairsAreCapped(t *testing.T) {
	for _, tc := range []struct {
		pairs int
		ok    bool
	}{
		{maxIndexMapPairs, true},
		{maxIndexMapPairs + 1, false},
	} {
		ix := sampleIndex()
		ix.Codecs[1].Params = map[string]any{}
		for i := range tc.pairs {
			ix.Codecs[1].Params[fmt.Sprint(i)] = uint64(1)
		}
		raw, err := encMode.Marshal(ix)
		if err != nil {
			t.Fatal(err)
		}
		_, err = DecodeIndex(raw, 0, nil)
		if tc.ok && err != nil {
			t.Errorf("%d pairs: %v", tc.pairs, err)
		}
		if !tc.ok && !errors.Is(err, ErrCorruptIndex) {
			t.Errorf("%d pairs: got %v, want ErrCorruptIndex", tc.pairs, err)
		}
	}
}
