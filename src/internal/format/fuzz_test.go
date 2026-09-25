package format

import (
	"testing"
)

// The fuzz targets exist to prove one property: arbitrary bytes produce an
// error, never a panic and never an unbounded allocation (doc/design.md
// 10.1). Anything a target accepts must also survive a round trip, so a
// crafted input cannot decode into something we would then re-encode
// differently.

func FuzzHeaderUnmarshal(f *testing.F) {
	h := sampleHeader()
	b, err := h.MarshalBinary()
	if err != nil {
		f.Fatalf("seed: %v", err)
	}
	f.Add(b)
	f.Add(b[:HeaderSize-1])
	f.Add([]byte{})

	enc := sampleHeader()
	enc.Flags = FlagEncrypted
	enc.CryptoHeaderLen = 128
	if eb, err := enc.MarshalBinary(); err == nil {
		f.Add(eb)
	}

	f.Fuzz(func(t *testing.T, in []byte) {
		var got Header
		if err := got.UnmarshalBinary(in); err != nil {
			return
		}

		// Accepted: re-encoding must reproduce the same bytes, or the decoder
		// is reading fields the encoder does not write.
		out, err := got.MarshalBinary()
		if err != nil {
			t.Fatalf("accepted a header that will not re-encode: %v", err)
		}
		if string(out) != string(in[:HeaderSize]) {
			t.Fatalf("header round trip is not stable:\n in %x\nout %x", in[:HeaderSize], out)
		}
	})
}

func FuzzTrailerUnmarshal(f *testing.F) {
	tr := sampleTrailer()
	b, err := tr.MarshalBinary()
	if err != nil {
		f.Fatalf("seed: %v", err)
	}
	f.Add(b)
	f.Add(b[:TrailerSize-1])
	f.Add(append([]byte("prefix"), b...))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, in []byte) {
		var got Trailer
		if err := got.UnmarshalBinary(in); err != nil {
			return
		}

		out, err := got.MarshalBinary()
		if err != nil {
			t.Fatalf("accepted a trailer that will not re-encode: %v", err)
		}
		tail := in[len(in)-TrailerSize:]
		if string(out) != string(tail) {
			t.Fatalf("trailer round trip is not stable:\n in %x\nout %x", tail, out)
		}

		// ValidateAgainst must never panic on a decoded trailer, whatever the
		// header and file size say.
		h := sampleHeader()
		for _, size := range []int64{0, HeaderSize, TrailerSize, 1 << 20, 1<<63 - 1} {
			_ = got.ValidateAgainst(&h, size)
		}
	})
}

func FuzzDecodeIndex(f *testing.F) {
	for _, compress := range []bool{false, true} {
		enc, err := sampleIndex().Encode(EncodeOptions{Compress: compress})
		if err != nil {
			f.Fatalf("seed: %v", err)
		}
		f.Add(enc.Bytes, uint32(enc.Flags))
		f.Add(enc.Bytes[:len(enc.Bytes)/2], uint32(enc.Flags))
	}
	f.Add([]byte{}, uint32(0))
	f.Add([]byte{0xa0}, uint32(0))                                                 // empty CBOR map
	f.Add([]byte{0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, uint32(0)) // huge array claim

	// The corpus carries the flags as a plain uint32: the fuzzing engine
	// accepts only a fixed set of basic types, so a named type cannot be a
	// fuzz argument. Convert at the boundary instead.
	f.Fuzz(func(t *testing.T, in []byte, raw uint32) {
		flags := TrailerFlags(raw)

		// The sealed path needs an opener; exercise it with one that passes
		// the bytes through, so the fuzzer reaches the decoder either way.
		var open Opener
		if flags&FlagIndexEncrypted != 0 {
			open = func(c []byte) ([]byte, error) { return c, nil }
		}

		ix, err := DecodeIndex(in, flags, open)
		if err != nil {
			return
		}
		if ix == nil {
			t.Fatal("DecodeIndex returned a nil index and a nil error")
		}

		// Anything accepted must satisfy the invariants the rest of the
		// program relies on, and must re-encode.
		if err := ix.Validate(); err != nil {
			t.Fatalf("accepted an index that fails Validate: %v", err)
		}
		if _, err := ix.Encode(EncodeOptions{Compress: true}); err != nil {
			t.Fatalf("accepted an index that will not re-encode: %v", err)
		}
		if ix.LiveCount() > uint64(len(ix.Members)) {
			t.Fatalf("LiveCount %d exceeds member count %d", ix.LiveCount(), len(ix.Members))
		}
	})
}

// FuzzUnmarshalCryptoHeader covers the newest attacker-reachable decoder. It
// runs before any key exists, on bytes the archive supplies, and its output
// decides how much memory and time key derivation will be asked to spend.
func FuzzUnmarshalCryptoHeader(f *testing.F) {
	good := &CryptoHeader{
		Version: CryptoHeaderVersion,
		KDF:     KDFArgon2id,
		Salt:    make([]byte, CryptoSaltSize),
		Time:    3, Memory: 256 * 1024, Threads: 4,
		AEAD:  AEADXChaCha20,
		Check: make([]byte, CryptoCheckSize),
	}
	b, err := good.Marshal()
	if err != nil {
		f.Fatalf("seed: %v", err)
	}
	f.Add(b)
	f.Add(b[:len(b)/2])
	f.Add([]byte{})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff}) // claims 4 GiB

	f.Fuzz(func(t *testing.T, in []byte) {
		ch, err := UnmarshalCryptoHeader(in)
		if err != nil {
			return
		}
		// Anything accepted must be within the limits key derivation relies on.
		if ch.Memory > MaxKDFMemoryKiB || ch.Time > MaxKDFTime || ch.Time == 0 || ch.Threads == 0 {
			t.Fatalf("accepted out-of-range KDF parameters: %+v", ch)
		}
		if len(ch.Salt) != CryptoSaltSize || len(ch.Check) != CryptoCheckSize {
			t.Fatalf("accepted a malformed salt or check: %+v", ch)
		}
		if _, err := ch.Marshal(); err != nil {
			t.Fatalf("accepted a header that will not re-encode: %v", err)
		}
	})
}
