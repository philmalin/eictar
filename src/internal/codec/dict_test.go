package codec

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// sourceLike makes n small files that share most of their text, as the files
// of a source tree do.
func sourceLike(n int) [][]byte {
	var out [][]byte
	for i := 0; i < n; i++ {
		var b strings.Builder
		b.WriteString("// Copyright 2026 The Example Authors. All rights reserved.\n")
		b.WriteString("// Use of this source code is governed by a BSD-style license.\n\n")
		fmt.Fprintf(&b, "package pkg%d\n\nimport (\n\t\"fmt\"\n\t\"io\"\n\t\"strings\"\n)\n\n", i%7)
		for j := 0; j < 5+i%4; j++ {
			fmt.Fprintf(&b, "func helper%d_%d(w io.Writer, s string) error {\n\t_, err := fmt.Fprintf(w, \"%%s\\n\", strings.TrimSpace(s))\n\treturn err\n}\n\n", i, j)
		}
		out = append(out, []byte(b.String()))
	}
	return out
}

func TestKeyAloneAndOff(t *testing.T) {
	enc, err := NewEncoder("zstd", Params{"long": On}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if got := enc.Resolved()["long"]; got != 27 {
		t.Errorf("long alone resolved to %v, want 27", got)
	}
	enc.Close()
	enc, err = NewEncoder("zstd", Params{"long": Off, "train": Off}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := enc.Resolved()["long"]; ok {
		t.Error("long=off still set a window")
	}
	enc.Close()
	for _, p := range []Params{
		{"level": On},     // level has no form alone
		{"level": Off},    // and cannot be off
		{"level": ""},     // an empty value
		{"train": "2K"},   // below 4 KiB
		{"train": "2M"},   // above 1 MiB
		{"train": "lots"}, // not a size
		{"train": "99999999999999999M"},
	} {
		if enc, err := NewEncoder("zstd", p, 1); err == nil {
			enc.Close()
			t.Errorf("%v: accepted", p)
		}
	}
	// Only zstd has train.
	if enc, err := NewEncoder("gzip", Params{"train": On}, 1); err == nil {
		enc.Close()
		t.Error("gzip accepted train")
	}
}

func TestTrainSize(t *testing.T) {
	for _, tc := range []struct {
		p    Params
		want int
	}{
		{nil, 0},
		{Params{"train": Off}, 0},
		{Params{"train": On}, 112 << 10},
		{Params{"train": "64KiB"}, 64 << 10},
		{Params{"train": "8192"}, 8192},
	} {
		got, err := TrainSize("zstd", tc.p)
		if err != nil || got != tc.want {
			t.Errorf("TrainSize(%v) = %d, %v; want %d", tc.p, got, err, tc.want)
		}
	}
	if n, err := TrainSize("xz", nil); n != 0 || err != nil {
		t.Errorf("xz: %d, %v", n, err)
	}
}

// TestDictionaryRoundTrip: a trained dictionary makes small, similar files
// smaller, and a frame decodes only with the dictionary that made it.
func TestDictionaryRoundTrip(t *testing.T) {
	files := sourceLike(200)
	dict, err := TrainDict("zstd", nil, files, 16<<10, 40000)
	if err != nil {
		t.Fatal(err)
	}
	if id, err := DictID("zstd", dict); err != nil || id != 40000 {
		t.Fatalf("DictID = %d, %v", id, err)
	}
	plain, _ := NewEncoder("zstd", nil, 1)
	withDict, err := NewEncoderWithDict("zstd", nil, 1, dict)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := NewDecoderWithDict("zstd", 1<<20, dict)
	if err != nil {
		t.Fatal(err)
	}
	var sizePlain, sizeDict int
	var sample []byte
	for _, f := range files {
		a, _ := plain.Encode(nil, f)
		b, _ := withDict.Encode(nil, f)
		sizePlain, sizeDict = sizePlain+len(a), sizeDict+len(b)
		got, err := dec.Decode(nil, b, len(f))
		if err != nil || !bytes.Equal(got, f) {
			t.Fatalf("round trip: %v", err)
		}
		sample = b
	}
	if sizeDict >= sizePlain*3/4 {
		t.Errorf("with a dictionary %d bytes, without %d: want a clear gain", sizeDict, sizePlain)
	}

	// Without the dictionary, or with another one, the frame is refused.
	noDict, _ := NewDecoder("zstd", 1<<20)
	if _, err := noDict.Decode(nil, sample, len(files[len(files)-1])); err == nil {
		t.Error("a frame made with a dictionary decoded without it")
	}
	other, err := TrainDict("zstd", nil, files, 16<<10, 40001)
	if err != nil {
		t.Fatal(err)
	}
	wrong, _ := NewDecoderWithDict("zstd", 1<<20, other)
	if _, err := wrong.Decode(nil, sample, len(files[len(files)-1])); err == nil {
		t.Error("a frame decoded with another dictionary")
	}
	for _, c := range []interface{ Close() error }{plain, withDict, dec, noDict, wrong} {
		c.Close()
	}
}

// TestTrainingFailsCleanly: too little input is an error, never a panic.
func TestTrainingFailsCleanly(t *testing.T) {
	for _, samples := range [][][]byte{nil, {[]byte("x")}, {bytes.Repeat([]byte{0}, 10)}} {
		if _, err := TrainDict("zstd", nil, samples, 16<<10, 40000); err == nil {
			t.Errorf("%d samples: trained a dictionary", len(samples))
		}
	}
	if _, err := TrainDict("gzip", nil, sourceLike(10), 16<<10, 40000); err == nil {
		t.Error("gzip trained a dictionary")
	}
	if _, err := DictID("zstd", []byte("not a dictionary")); err == nil {
		t.Error("DictID accepted text")
	}
}

// TestTrainedDictionaryFitsItsSize: train=SIZE bounds the whole dictionary,
// its header and entropy tables too. The trainer's own size is the content
// only, and at train=1M the result was above the 1 MiB limit of the format.
// At 4 KiB the first result is 4160 bytes, so the retry runs here too.
func TestTrainedDictionaryFitsItsSize(t *testing.T) {
	files := sourceLike(3000)
	for _, size := range []int{4 << 10, 8 << 10} {
		d, err := TrainDict("zstd", nil, files, size, 40000)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if len(d) > size {
			t.Errorf("asked for %d bytes, got %d", size, len(d))
		}
	}
}
