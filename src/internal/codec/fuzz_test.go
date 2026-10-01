package codec

import (
	"testing"
)

// FuzzDecoders feeds arbitrary bytes to every decoder. A chunk comes from the
// archive, so an attacker chooses it: a decoder must return an error, and
// never panic, hang, or allocate more than the bound.
//
//	make fuzz
func FuzzDecoders(f *testing.F) {
	for _, name := range Names() {
		enc, err := NewEncoder(name, nil, 1)
		if err != nil {
			f.Fatal(err)
		}
		good, err := enc.Encode(nil, []byte("seed content for the fuzzer, seed content"))
		enc.Close()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(good, uint16(41))
	}
	f.Fuzz(func(t *testing.T, chunk []byte, plainSize uint16) {
		const bound = 1 << 16
		for _, name := range Names() {
			dec, err := NewDecoder(name, bound)
			if err != nil {
				t.Fatal(err)
			}
			out, err := dec.Decode(nil, chunk, int(plainSize))
			dec.Close()
			if err == nil && len(out) != int(plainSize) {
				t.Fatalf("%s: decoded %d bytes without an error, want %d", name, len(out), plainSize)
			}
		}
	})
}

// FuzzZstdDictionary feeds arbitrary dictionaries, and chunks to decode with
// them, along the reader's path: the id check, the decoder built from the
// dictionary, then the decode. A plain archive can hold any bytes as a
// dictionary with a correct unkeyed digest (doc/Security_Audit.md 5), so the
// parser of the dictionary sees what an attacker chooses: it must return an
// error, and never panic, hang, or decode past the bound.
//
//	make fuzz
func FuzzZstdDictionary(f *testing.F) {
	files := sourceLike(60)
	dict, err := TrainDict("zstd", nil, files, 16<<10, 40000)
	if err != nil {
		f.Fatal(err)
	}
	enc, err := NewEncoderWith("zstd", nil, EncoderOptions{Concurrency: 1, Dict: dict})
	if err != nil {
		f.Fatal(err)
	}
	chunk, err := enc.Encode(nil, files[3])
	enc.Close()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(dict, chunk, uint16(len(files[3])))
	// The magic and an id alone, and a dictionary cut short.
	f.Add(dict[:8], chunk, uint16(len(files[3])))
	f.Add(dict[:len(dict)/2], chunk, uint16(len(files[3])))

	f.Fuzz(func(t *testing.T, dict, chunk []byte, plainSize uint16) {
		const bound = 1 << 16
		if _, err := DictID("zstd", dict); err != nil {
			return // the reader refuses it here
		}
		dec, err := NewDecoderWithDict("zstd", bound, dict)
		if err != nil {
			return
		}
		defer dec.Close()
		out, err := dec.Decode(nil, chunk, int(plainSize))
		if err == nil && len(out) != int(plainSize) {
			t.Fatalf("decoded %d bytes without an error, want %d", len(out), plainSize)
		}
	})
}
