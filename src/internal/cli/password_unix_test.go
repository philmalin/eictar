//go:build unix

package cli

import (
	"errors"
	"io"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// TestReadPasswordLineEndsAtEOF: a terminal that has hung up gives 0 bytes
// to each read. term.ReadPassword then reads for ever (TestPromptReadFails
// found it: CI stopped the test after 30 minutes). The line ends there, and
// with nothing read it is io.EOF.
func TestReadPasswordLineEndsAtEOF(t *testing.T) {
	errForEver := errors.New("the line was read again after the end of the input, 100 times")
	reader := func(input string) func([]byte) (int, error) {
		empty := 0
		return func(b []byte) (int, error) {
			if input == "" {
				if empty++; empty > 100 {
					return 0, errForEver
				}
				return 0, nil
			}
			n := copy(b, input)
			input = input[n:]
			return n, nil
		}
	}
	for _, tc := range []struct {
		input, want string
		err         error
	}{
		{"", "", io.EOF},
		{"pw", "pw", nil},
		{"pw\nrest", "pw", nil},
		{"p\rw\n", "pw", nil},
		{"px\bw\n", "pw", nil},
		{"\b\n", "", nil},
	} {
		got, err := readPasswordLine(reader(tc.input))
		if string(got) != tc.want || !errors.Is(err, tc.err) {
			t.Errorf("%q: %q, %v; want %q, %v", tc.input, got, err, tc.want, tc.err)
		}
	}
	wantErr := errors.New("the read failed")
	if _, err := readPasswordLine(func([]byte) (int, error) { return 0, wantErr }); !errors.Is(err, wantErr) {
		t.Errorf("a failed read: %v", err)
	}
}

// TestReadPasswordSetsTheTerminal: the line is read with the echo off, in
// line mode with signals, and with a carriage return read as a newline.
// Then the terminal gets its settings back. A terminal whose settings cannot
// be read or set gives an error before any read: with the echo on, the
// passphrase shows on the screen.
func TestReadPasswordSetsTheTerminal(t *testing.T) {
	savedGet, savedSet := getTermios, setTermios
	t.Cleanup(func() { getTermios, setTermios = savedGet, savedSet })

	input := func(t *testing.T, s string) int {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { r.Close() })
		w.WriteString(s)
		w.Close()
		return int(r.Fd())
	}
	start := unix.Termios{Lflag: unix.ECHO, Iflag: unix.IXON}
	var set []unix.Termios
	getTermios = func(int) (*unix.Termios, error) { s := start; return &s, nil }
	setTermios = func(_ int, s *unix.Termios) error { set = append(set, *s); return nil }

	got, err := readPassword(input(t, "pw\n"))
	if string(got) != "pw" || err != nil {
		t.Fatalf("%q, %v; want pw", got, err)
	}
	if len(set) != 2 {
		t.Fatalf("the terminal was set %d times, want 2", len(set))
	}
	if l := set[0].Lflag; l&unix.ECHO != 0 || l&unix.ICANON == 0 || l&unix.ISIG == 0 {
		t.Errorf("the read had Lflag %#x: the echo on, or no line mode, or no signals", l)
	}
	if i := set[0].Iflag; i&unix.ICRNL == 0 || i&unix.IXON == 0 {
		t.Errorf("the read had Iflag %#x, want ICRNL and the IXON of before", i)
	}
	if set[1] != start {
		t.Errorf("the terminal got back %+v, want %+v", set[1], start)
	}

	failed := errors.New("the ioctl failed")
	getTermios = func(int) (*unix.Termios, error) { return nil, failed }
	if _, err := readPassword(input(t, "pw\n")); !errors.Is(err, failed) {
		t.Errorf("the settings could not be read: %v", err)
	}
	set = nil
	getTermios = func(int) (*unix.Termios, error) { s := start; return &s, nil }
	setTermios = func(_ int, s *unix.Termios) error { set = append(set, *s); return failed }
	if _, err := readPassword(input(t, "pw\n")); !errors.Is(err, failed) || len(set) != 1 {
		t.Errorf("the echo could not be turned off: %v, set %d times", err, len(set))
	}
}
