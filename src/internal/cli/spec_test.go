package cli

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestParseCompressSpec(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want CompressSpec
	}{
		{"zstd", CompressSpec{Name: "zstd"}},
		{"none", CompressSpec{Name: "none"}},
		{"zstd:level=19", CompressSpec{Name: "zstd", Params: map[string]string{"level": "19"}}},
		{"zstd:level=19,long=27", CompressSpec{Name: "zstd", Params: map[string]string{"level": "19", "long": "27"}}},
		{"xz:preset=6", CompressSpec{Name: "xz", Params: map[string]string{"preset": "6"}}},
		{"s2:mode=better", CompressSpec{Name: "s2", Params: map[string]string{"mode": "better"}}},
		{"zstd: level = 19 ", CompressSpec{Name: "zstd", Params: map[string]string{"level": "19"}}},
		// A value may itself contain an '=' - the split is on the first one.
		{"x:k=a=b", CompressSpec{Name: "x", Params: map[string]string{"k": "a=b"}}},
		// A key alone is "on"; the codec decides what that means (doc/design.md
		// 10.2), and refuses it for a key such as level.
		{"zstd:level=19,long,train", CompressSpec{Name: "zstd", Params: map[string]string{"level": "19", "long": "on", "train": "on"}}},
		{"zstd:level", CompressSpec{Name: "zstd", Params: map[string]string{"level": "on"}}},
		{"zstd:train=off", CompressSpec{Name: "zstd", Params: map[string]string{"train": "off"}}},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseCompressSpec(tc.in)
			if err != nil {
				t.Fatalf("ParseCompressSpec(%q): %v", tc.in, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestParseCompressSpecRejects(t *testing.T) {
	for _, in := range []string{
		"",
		":level=9",     // no codec name
		"zstd:",        // colon with no parameters
		"zstd:level=",  // an empty value: write the key alone, or give one
		"x:k=",         // the same
		"zstd:=19",     // empty parameter name
		"zstd:l=1,l=2", // the same parameter twice
	} {
		t.Run(in, func(t *testing.T) {
			if got, err := ParseCompressSpec(in); err == nil {
				t.Errorf("ParseCompressSpec(%q) = %+v, want an error", in, got)
			}
		})
	}
}

// TestCompressSpecStringRoundTrip matters for --show-config: what it prints
// must parse back to the same thing.
func TestCompressSpecStringRoundTrip(t *testing.T) {
	for _, in := range []string{"zstd", "none", "zstd:level=19", "zstd:level=19,long=27", "zstd:long=on,train=on"} {
		spec, err := ParseCompressSpec(in)
		if err != nil {
			t.Fatalf("ParseCompressSpec(%q): %v", in, err)
		}
		again, err := ParseCompressSpec(spec.String())
		if err != nil {
			t.Fatalf("re-parsing %q: %v", spec.String(), err)
		}
		if !reflect.DeepEqual(spec, again) {
			t.Errorf("%q round-tripped to %+v", in, again)
		}
	}
}

func TestParseSize(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Size
	}{
		{"0", 0},
		{"1", 1},
		{"1024", 1024},
		{"4MiB", 4 << 20},
		{"4M", 4 << 20},
		{"4mb", 4 << 20},
		{"512K", 512 << 10},
		{"2GiB", 2 << 30},
		{"1TiB", 1 << 40},
		{"32b", 32},
		{" 8 MiB ", 8 << 20},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseSize(tc.in)
			if err != nil {
				t.Fatalf("ParseSize(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("ParseSize(%q) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseSizeRejects(t *testing.T) {
	for _, in := range []string{
		"", "bogus", "MiB", "-1", "1.5MiB", "4XiB", "9223372036854775807TiB",
	} {
		t.Run(in, func(t *testing.T) {
			if got, err := ParseSize(in); err == nil {
				t.Errorf("ParseSize(%q) = %d, want an error", in, got)
			}
		})
	}
}

func TestSizeStringRoundTrip(t *testing.T) {
	for _, in := range []Size{0, 1, 1023, 4 << 20, 32 << 20, 2 << 30, 1 << 40} {
		got, err := ParseSize(in.String())
		if err != nil {
			t.Fatalf("ParseSize(%q): %v", in.String(), err)
		}
		if got != in {
			t.Errorf("%d rendered as %q and parsed back as %d", in, in.String(), got)
		}
	}
}

// TestWindowWiderThanTheChunkWarns: the chunks are independent, so a zstd
// window or an xz dictionary larger than a chunk does nothing beyond it, and
// the program says so (doc/design.md 10.2). Only a parameter that was given
// counts: plain xz uses preset 6, but nobody asked for its dictionary.
func TestWindowWiderThanTheChunkWarns(t *testing.T) {
	for _, tc := range []struct {
		argv []string
		warn bool
	}{
		{[]string{"-cf", "a", "-Z", "zstd:long", "p"}, true},
		{[]string{"-cf", "a", "-Z", "zstd:long", "--chunk-size", "128MiB", "p"}, false},
		{[]string{"-cf", "a", "-Z", "zstd:long=20", "p"}, false},
		{[]string{"-cqf", "a", "-Z", "zstd:long", "p"}, false},
		{[]string{"-cf", "a", "-Z", "xz:preset=9", "p"}, true},
		{[]string{"-cf", "a", "-Z", "xz:preset=9", "--chunk-size", "64MiB", "p"}, false},
		{[]string{"-cf", "a", "-Z", "xz:preset=3", "p"}, false}, // 4 MiB, the chunk size
		{[]string{"-cf", "a", "-Z", "xz:preset=2", "p"}, false},
		{[]string{"-cf", "a", "-Z", "xz", "p"}, false},
	} {
		o := mustParse(t, tc.argv...)
		var stderr bytes.Buffer
		if err := checkCompress(o, &stderr); err != nil {
			t.Fatalf("%q: %v", tc.argv, err)
		}
		if got := strings.Contains(stderr.String(), "no effect"); got != tc.warn {
			t.Errorf("%q: warned %v, want %v (%q)", tc.argv, got, tc.warn, stderr.String())
		}
	}
	// A key with no form alone is a usage error, before the archive exists.
	o := mustParse(t, "-cf", "a", "-Z", "zstd:level", "p")
	var usage *UsageError
	if err := checkCompress(o, io.Discard); !errors.As(err, &usage) {
		t.Errorf("zstd:level: %v, want a usage error", err)
	}
}

func TestListCodecsShowsTheFormAlone(t *testing.T) {
	var out bytes.Buffer
	if err := runListCodecs(&out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"alone 27", "train", "alone 114688"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("--list-codecs lacks %q:\n%s", want, out.String())
		}
	}
}
