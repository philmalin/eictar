package ect

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"strings"
	"testing"

	"github.com/klauspost/compress/s2"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz/lzma"
)

// compressors for the tests: the libraries themselves, not eictar.
var compressors = map[string]func(t *testing.T, b []byte) []byte{
	"zstd": func(t *testing.T, b []byte) []byte {
		enc, err := zstd.NewWriter(nil, zstd.WithEncoderCRC(true))
		if err != nil {
			t.Fatal(err)
		}
		defer enc.Close()
		return enc.EncodeAll(b, nil)
	},
	"flate": func(t *testing.T, b []byte) []byte {
		var out bytes.Buffer
		w, _ := flate.NewWriter(&out, 6)
		w.Write(b)
		w.Close()
		return out.Bytes()
	},
	"gzip": func(t *testing.T, b []byte) []byte {
		var out bytes.Buffer
		w := gzip.NewWriter(&out)
		w.Write(b)
		w.Close()
		return out.Bytes()
	},
	"s2": func(t *testing.T, b []byte) []byte { return s2.Encode(nil, b) },
	"xz": func(t *testing.T, b []byte) []byte {
		var out bytes.Buffer
		w, err := lzma.Writer2Config{DictCap: max(4096, len(b))}.NewWriter2(&out)
		if err != nil {
			t.Fatal(err)
		}
		w.Write(b)
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return out.Bytes()
	},
}

// TestCodecs decodes a chunk of each codec. A chunk decodes to exactly its
// expected length, and has nothing after its stream (doc/format.md 6).
func TestCodecs(t *testing.T) {
	a := &Archive{}
	plain := []byte(strings.Repeat("the content of a chunk. ", 400))
	for name, compress := range compressors {
		c := Codec{Name: name}
		z := compress(t, plain)
		got, err := a.decode(c, z, uint64(len(plain)))
		if err != nil || !bytes.Equal(got, plain) {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := a.decode(c, z, uint64(len(plain))-1); err == nil {
			t.Errorf("%s: a chunk that decodes to one byte more is accepted", name)
		}
		if _, err := a.decode(c, z, uint64(len(plain))+1); err == nil {
			t.Errorf("%s: a chunk that decodes to one byte less is accepted", name)
		}
		if name == "zstd" || name == "s2" {
			continue
		}
		if _, err := a.decode(c, append(bytes.Clone(z), z...), uint64(len(plain))); err == nil {
			t.Errorf("%s: a second stream after the first is accepted", name)
		}
	}
	if _, err := a.decode(Codec{Name: "lz4"}, []byte{1}, 1); !isRefusal(err, "not known") {
		t.Errorf("a codec that is not known: %v", err)
	}
	// A frame that names a dictionary, for a codec with none.
	z := compressors["zstd"](t, plain)
	frame := bytes.Clone(z[:4])
	frame = append(frame, z[4]|1, 0x40) // a dictionary id of one byte
	frame = append(frame, z[5:]...)
	if _, err := a.decode(Codec{Name: "zstd"}, frame, uint64(len(plain))); err == nil || !strings.Contains(err.Error(), "another dictionary") {
		t.Errorf("a frame with a dictionary: %v", err)
	}
	if _, err := a.decode(Codec{Name: "zstd"}, []byte{0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0}, 0); err == nil || !strings.Contains(err.Error(), "skippable") {
		t.Errorf("a skippable frame: %v", err)
	}
}
