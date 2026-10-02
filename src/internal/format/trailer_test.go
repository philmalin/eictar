package format

import (
	"encoding/binary"
	"errors"
	"testing"
)

func sampleTrailer() Trailer {
	t := Trailer{
		VersionMajor:    VersionMajor,
		VersionMinor:    VersionMinor,
		Flags:           FlagIndexCompressed,
		Generation:      7,
		IndexOffset:     4096,
		IndexLength:     512,
		PrevIndexOffset: 2048,
		LiveMembers:     42,
	}
	for i := range t.IndexDigest {
		t.IndexDigest[i] = byte(i)
	}
	return t
}

func mustMarshalTrailer(t *testing.T, tr Trailer) []byte {
	t.Helper()
	b, err := tr.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if len(b) != TrailerSize {
		t.Fatalf("trailer is %d bytes, want %d", len(b), TrailerSize)
	}
	return b
}

func TestTrailerRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		tr   Trailer
	}{
		{"typical", sampleTrailer()},
		{"first generation", func() Trailer {
			tr := sampleTrailer()
			tr.Generation = 1
			tr.PrevIndexOffset = 0
			return tr
		}()},
		{"empty archive", Trailer{
			VersionMajor: VersionMajor, VersionMinor: VersionMinor,
			Generation: 1, IndexOffset: HeaderSize,
		}},
		{"encrypted index", func() Trailer {
			tr := sampleTrailer()
			tr.Flags = FlagIndexCompressed | FlagIndexEncrypted
			return tr
		}()},
		{"large offsets", func() Trailer {
			tr := sampleTrailer()
			tr.IndexOffset = 1 << 62
			tr.IndexLength = 1 << 30
			tr.LiveMembers = 1 << 40
			return tr
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := mustMarshalTrailer(t, tc.tr)

			var got Trailer
			if err := got.UnmarshalBinary(b); err != nil {
				t.Fatalf("UnmarshalBinary: %v", err)
			}
			if got != tc.tr {
				t.Errorf("round trip changed the trailer:\n got %+v\nwant %+v", got, tc.tr)
			}
		})
	}
}

// TestTrailerUnmarshalTakesTail is the contract that lets a reader pass the
// whole tail of a file without doing arithmetic.
func TestTrailerUnmarshalTakesTail(t *testing.T) {
	want := sampleTrailer()
	b := append([]byte("...leading archive bytes..."), mustMarshalTrailer(t, want)...)

	var got Trailer
	if err := got.UnmarshalBinary(b); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}
	if got != want {
		t.Errorf("trailer decoded from a tail differs:\n got %+v\nwant %+v", got, want)
	}
}

func TestTrailerRejects(t *testing.T) {
	good := mustMarshalTrailer(t, sampleTrailer())

	corrupt := func(fn func(b []byte)) []byte {
		b := make([]byte, TrailerSize)
		copy(b, good)
		fn(b)
		return b
	}

	for _, tc := range []struct {
		name string
		in   []byte
		want error
	}{
		{"empty", nil, ErrTruncated},
		{"short", good[:TrailerSize-1], ErrTruncated},
		{"bad magic", corrupt(func(b []byte) { b[3] ^= 0xff }), ErrBadMagic},
		{"flipped digest byte", corrupt(func(b []byte) { b[60] ^= 0x01 }), ErrChecksum},
		{"flipped offset byte", corrupt(func(b []byte) { b[24] ^= 0x01 }), ErrChecksum},
		{"reserved set", corrupt(func(b []byte) { b[90] = 9 }), ErrChecksum},
		{"future major", corrupt(func(b []byte) {
			binary.LittleEndian.PutUint16(b[8:10], VersionMajor+3)
			binary.LittleEndian.PutUint32(b[92:96], crc32c(b[0:92]))
		}), ErrUnsupportedVersion},
		{"unknown flag", corrupt(func(b []byte) {
			binary.LittleEndian.PutUint32(b[12:16], uint32(FlagIndexCompressed|1<<7))
			binary.LittleEndian.PutUint32(b[92:96], crc32c(b[0:92]))
		}), ErrUnsupportedVersion},
		{"reserved byte with a valid crc", corrupt(func(b []byte) {
			b[88] = 1
			binary.LittleEndian.PutUint32(b[92:96], crc32c(b[0:92]))
		}), ErrUnsupportedVersion},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var tr Trailer
			if err := tr.UnmarshalBinary(tc.in); !errors.Is(err, tc.want) {
				t.Errorf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestTrailerValidateAgainst covers the checks that stop a structurally valid
// trailer from steering a reader into a bad seek or a wild allocation. Every
// case here is reachable by an attacker who hands us a crafted archive.
func TestTrailerValidateAgainst(t *testing.T) {
	const fileSize = 8192

	plainHeader := Header{VersionMajor: VersionMajor, VersionMinor: VersionMinor}
	encHeader := Header{
		VersionMajor: VersionMajor, VersionMinor: VersionMinor,
		Flags: FlagEncrypted, CryptoHeaderLen: 128,
	}

	base := func() Trailer {
		return Trailer{
			VersionMajor: VersionMajor, VersionMinor: VersionMinor,
			Generation: 1, IndexOffset: 1024, IndexLength: 256,
		}
	}

	for _, tc := range []struct {
		name    string
		h       Header
		mutate  func(tr *Trailer)
		wantErr error
	}{
		{"valid", plainHeader, nil, nil},
		{"valid encrypted", encHeader, func(tr *Trailer) {
			tr.Flags = FlagIndexEncrypted
		}, nil},
		{"index ends exactly at the trailer", plainHeader, func(tr *Trailer) {
			tr.IndexOffset = fileSize - TrailerSize - 256
			tr.IndexLength = 256
		}, nil},
		{"empty index at body start", plainHeader, func(tr *Trailer) {
			tr.IndexOffset = HeaderSize
			tr.IndexLength = 0
		}, nil},

		{"minor version mismatch", plainHeader, func(tr *Trailer) {
			tr.VersionMinor = VersionMinor + 1
		}, ErrVersionMismatch},
		{"index before the body", plainHeader, func(tr *Trailer) {
			tr.IndexOffset = 8
		}, ErrCorruptIndex},
		{"index before the crypto header ends", encHeader, func(tr *Trailer) {
			tr.Flags = FlagIndexEncrypted
			tr.IndexOffset = HeaderSize + 1 // inside the crypto header
		}, ErrCorruptIndex},
		{"index overlaps the trailer", plainHeader, func(tr *Trailer) {
			tr.IndexOffset = fileSize - TrailerSize - 10
			tr.IndexLength = 100
		}, ErrCorruptIndex},
		{"index past end of file", plainHeader, func(tr *Trailer) {
			tr.IndexOffset = fileSize * 2
		}, ErrCorruptIndex},
		{"index length overflows", plainHeader, func(tr *Trailer) {
			tr.IndexLength = 1 << 63
		}, ErrCorruptIndex},
		{"prev index past end", plainHeader, func(tr *Trailer) {
			tr.PrevIndexOffset = fileSize * 4
		}, ErrCorruptIndex},
		{"encrypted index in a plaintext archive", plainHeader, func(tr *Trailer) {
			tr.Flags = FlagIndexEncrypted
		}, ErrCorruptIndex},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := base()
			if tc.mutate != nil {
				tc.mutate(&tr)
			}
			err := tr.ValidateAgainst(&tc.h, fileSize)
			switch {
			case tc.wantErr == nil && err != nil:
				t.Errorf("unexpected error: %v", err)
			case tc.wantErr != nil && !errors.Is(err, tc.wantErr):
				t.Errorf("error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestTrailerFlagAccessors(t *testing.T) {
	var tr Trailer
	if tr.IndexCompressed() || tr.IndexEncrypted() {
		t.Error("a zero trailer should report no flags")
	}
	tr.Flags = FlagIndexCompressed | FlagIndexEncrypted
	if !tr.IndexCompressed() || !tr.IndexEncrypted() {
		t.Error("both flags should report set")
	}
}
