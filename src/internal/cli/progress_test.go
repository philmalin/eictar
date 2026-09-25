package cli

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	"eictar/src/internal/format"
)

func TestMeterLine(t *testing.T) {
	for _, tc := range []struct {
		done, total, files int64
		elapsed            time.Duration
		want               string
	}{
		{1 << 30, 4 << 30, 0, 10 * time.Second, "1.0 GiB / 4.0 GiB  25%  102.4 MiB/s  0:30 left"},
		{0, 1 << 20, 0, 0, "0 B / 1.0 MiB  0%  0 B/s  -:-- left"},
		{3 << 20, 0, 1, time.Second, "3.0 MiB  1 member  3.0 MiB/s"},
		{512, 0, 7, 2 * time.Second, "512 B  7 members  256 B/s"},
	} {
		if got := meterLine(tc.done, tc.total, tc.files, tc.elapsed); got != tc.want {
			t.Errorf("meterLine(%d, %d, %d, %v) = %q, want %q", tc.done, tc.total, tc.files, tc.elapsed, got, tc.want)
		}
	}
	if got := clock(2*time.Hour + 3*time.Minute + 4*time.Second); got != "2:03:04" {
		t.Errorf("clock = %q", got)
	}
}

// TestMeterStaysQuietUntilWorkStarts: before the first byte there may be a
// passphrase prompt on the terminal, and a redraw would write over it. Then
// a -v line clears the status line before it is printed.
func TestMeterStaysQuietUntilWorkStarts(t *testing.T) {
	var term, out bytes.Buffer
	old := isTerminal
	isTerminal = func(io.Writer) bool { return true }
	t.Cleanup(func() { isTerminal = old })

	o := &Options{Progress: true}
	rep := &reporter{out: &out, errOut: &term, verbose: 1}
	r, done := withProgress(o, rep, &term)
	m := r.(*meter)

	time.Sleep(3 * meterInterval)
	if term.Len() != 0 {
		m.mu.Lock()
		t.Errorf("the meter drew before any work: %q", term.String())
		m.mu.Unlock()
	}

	m.Total(1000)
	m.Advance(250)
	m.Member(&format.Member{Path: "a/b"})
	done()

	if out.String() != "a/b\n" {
		t.Errorf("-v output = %q", out.String())
	}
	s := term.String()
	if !strings.Contains(s, "25%") || !strings.HasSuffix(s, "\r") {
		t.Errorf("status line = %q; want the percentage, and a cleared line at the end", s)
	}
}

func TestNoMeterWithoutATerminal(t *testing.T) {
	rep := &reporter{}
	r, done := withProgress(&Options{Progress: true}, rep, &bytes.Buffer{})
	done()
	if r != rep {
		t.Error("a meter was drawn to something that is not a terminal")
	}
}
