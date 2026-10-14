//go:build linux

package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// openPTY gives the two ends of a pseudo-terminal: the test writes what a
// person types to master, and the prompt reads it from slave.
func openPTY(t *testing.T) (master, slave *os.File) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal: %v", err)
	}
	if err := unix.IoctlSetPointerInt(int(m.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		m.Close()
		t.Skipf("unlocking the pseudo-terminal: %v", err)
	}
	n, err := unix.IoctlGetInt(int(m.Fd()), unix.TIOCGPTN)
	if err != nil {
		m.Close()
		t.Skipf("the number of the pseudo-terminal: %v", err)
	}
	s, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		m.Close()
		t.Skipf("opening the pseudo-terminal: %v", err)
	}
	t.Cleanup(func() { s.Close(); m.Close() })
	return m, s
}

// TestPromptOnATerminal: the prompt asks once, or twice on create, and
// refuses an empty passphrase and two that do not match. A new passphrase
// says so.
func TestPromptOnATerminal(t *testing.T) {
	for _, tc := range []struct {
		name    string
		src     passphraseSource
		typed   string
		want    string
		err     string
		prompts string
	}{
		{"once", passphraseSource{}, "pw\nother\n", "pw", "", "Passphrase: \n"},
		{"twice", passphraseSource{confirm: true}, "pw\npw\n", "pw", "", "Passphrase: \nPassphrase (again): \n"},
		{"no match", passphraseSource{confirm: true}, "pw\npx\n", "", "do not match", "Passphrase: \nPassphrase (again): \n"},
		{"empty", passphraseSource{confirm: true}, "\n", "", "empty passphrase", "Passphrase: \n"},
		{"new", passphraseSource{isNew: true}, "pw\n", "pw", "", "New passphrase: \n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			master, slave := openPTY(t)
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			src := tc.src
			src.stdin, src.stderr = slave, w
			if _, err := master.WriteString(tc.typed); err != nil {
				t.Fatal(err)
			}
			got, err := src.prompt()
			w.Close()
			prompts, _ := io.ReadAll(r)
			if string(got) != tc.want || (tc.err == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.err)) {
				t.Errorf("%q, %v; want %q, %q", got, err, tc.want, tc.err)
			}
			if string(prompts) != tc.prompts {
				t.Errorf("prompts %q, want %q", prompts, tc.prompts)
			}
		})
	}
}

// TestPromptReadFails: a terminal that closes while the prompt waits is an
// error, at the first read and at the second. The test closes it when the
// prompt has asked.
func TestPromptReadFails(t *testing.T) {
	for _, tc := range []struct{ typed, closeAfter string }{
		{"", "Passphrase: "},
		{"pw\n", "Passphrase (again): "},
	} {
		master, slave := openPTY(t)
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			_, err := passphraseSource{stdin: slave, stderr: w, confirm: true}.prompt()
			w.Close()
			done <- err
		}()
		master.WriteString(tc.typed)
		var seen strings.Builder
		buf := make([]byte, 64)
		for !strings.Contains(seen.String(), tc.closeAfter) {
			n, err := r.Read(buf)
			if err != nil {
				t.Fatalf("the prompt did not ask: %q, %v", seen.String(), err)
			}
			seen.Write(buf[:n])
		}
		master.Close()
		if err := <-done; err == nil || !strings.Contains(err.Error(), "reading the passphrase") {
			t.Errorf("closed after %q: %v", tc.closeAfter, err)
		}
		r.Close()
	}
}

// TestPromptOnTheProcessTerminal: with no terminal given, the prompt uses
// the standard input and the standard error of the process.
func TestPromptOnTheProcessTerminal(t *testing.T) {
	master, slave := openPTY(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	savedIn, savedErr := os.Stdin, os.Stderr
	os.Stdin, os.Stderr = slave, w
	defer func() { os.Stdin, os.Stderr = savedIn, savedErr }()
	master.WriteString("pw\n")
	got, err := passphraseSource{}.prompt()
	os.Stdin, os.Stderr = savedIn, savedErr
	w.Close()
	prompts, _ := io.ReadAll(r)
	if string(got) != "pw" || err != nil || string(prompts) != "Passphrase: \n" {
		t.Errorf("%q, %v, prompts %q", got, err, prompts)
	}
}
