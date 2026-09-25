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
