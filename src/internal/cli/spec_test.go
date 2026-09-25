package cli

import (
	"reflect"
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
		// An empty value is legal; the codec registry decides what it means.
		{"x:k=", CompressSpec{Name: "x", Params: map[string]string{"k": ""}}},
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
		"zstd:level",   // not k=v
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
	for _, in := range []string{"zstd", "none", "zstd:level=19", "zstd:level=19,long=27"} {
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
