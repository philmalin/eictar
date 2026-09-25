package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/philmalin/eictar/src/internal/format"
)

func TestSavedPercent(t *testing.T) {
	for _, tc := range []struct {
		plain, stored uint64
		want          string
	}{
		{0, 0, "-"}, // an empty file saves nothing and loses nothing
		{1000, 1000, "0.0%"},
		{1000, 250, "75.0%"},
		{3, 19, "-533.3%"}, // a tiny sealed file: the tag outweighs it
	} {
		if got := savedPercent(tc.plain, tc.stored); got != tc.want {
			t.Errorf("savedPercent(%d, %d) = %q, want %q", tc.plain, tc.stored, got, tc.want)
		}
	}
}

func TestWriteTableAlignment(t *testing.T) {
	var b bytes.Buffer
	writeTable(&b, [][]string{
		{"a", "1", "first"},
		{"bbb", "12345", "é-second"},
	}, map[int]bool{1: true})
	want := "a        1  first\n" +
		"bbb  12345  é-second\n"
	if b.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", b.String(), want)
	}
}

func TestPlural(t *testing.T) {
	for n, want := range map[int]string{0: "0 files", 1: "1 file", 2: "2 files"} {
		if got := plural(n, "file"); got != want {
			t.Errorf("plural(%d) = %q, want %q", n, got, want)
		}
	}
}

// TestLongColumns: a member with a blob shows its stored size, percentage
// and codec; one without shows "-" there, and -vv adds three columns.
func TestLongColumns(t *testing.T) {
	file := &format.Member{
		Path: "f", Type: format.TypeReg, Mode: 0o644, Size: 1000, Length: 250,
		Chunks: []uint32{250}, Codec: format.NoCodec, Enc: &format.EncInfo{},
		Digest: bytes.Repeat([]byte{0xab}, 32),
	}
	dir := &format.Member{Path: "d", Type: format.TypeDir, Mode: 0o755}

	cols := longColumns(nil, file, false)
	if got := strings.Join(cols[2:5], " "); got != "1000 250 75.0%" {
		t.Errorf("size, stored, saved = %q", got)
	}
	cols = longColumns(nil, dir, false)
	if got := strings.Join(cols[3:6], " "); got != "- - -" {
		t.Errorf("a directory's blob columns = %q, want dashes", got)
	}

	cols = longColumns(nil, file, true)
	if len(cols) != 11 {
		t.Fatalf("-vv gives %d columns, want 11: %q", len(cols), cols)
	}
	if got := strings.Join(cols[6:9], " "); got != "1 sealed abababababababab" {
		t.Errorf("chunks, sealed, digest = %q", got)
	}
}
