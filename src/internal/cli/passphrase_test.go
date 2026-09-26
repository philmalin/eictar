package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPassphraseFromFile(t *testing.T) {
	dir := t.TempDir()

	for _, tc := range []struct {
		name    string
		content string
		want    string
	}{
		{"plain", "hunter2", "hunter2"},
		{"trailing newline", "hunter2\n", "hunter2"},
		{"crlf", "hunter2\r\n", "hunter2"},
		{"first line only", "hunter2\nignored\n", "hunter2"},
		{"spaces are significant", "  spaced  \n", "  spaced  "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(dir, "pass")
			if err := os.WriteFile(p, []byte(tc.content), 0o600); err != nil {
				t.Fatalf("writing: %v", err)
			}
			got, err := passphraseSource{file: p}.get()
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPassphraseFileErrors(t *testing.T) {
	dir := t.TempDir()

	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}
	if _, err := (passphraseSource{file: empty}).get(); err == nil {
		t.Error("an empty passphrase file was accepted")
	}
	if _, err := (passphraseSource{file: filepath.Join(dir, "missing")}).get(); err == nil {
		t.Error("a missing passphrase file was accepted")
	}
}

func TestPassphraseFromEnv(t *testing.T) {
	t.Setenv("EICTAR_TEST_PASSPHRASE", "from the environment")

	got, err := passphraseSource{env: "EICTAR_TEST_PASSPHRASE"}.get()
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(got) != "from the environment" {
		t.Errorf("got %q", got)
	}

	if _, err := (passphraseSource{env: "EICTAR_TEST_UNSET"}).get(); err == nil {
		t.Error("an unset variable was accepted")
	}

	t.Setenv("EICTAR_TEST_EMPTY", "")
	if _, err := (passphraseSource{env: "EICTAR_TEST_EMPTY"}).get(); err == nil {
		t.Error("an empty variable was accepted")
	}
}

// TestPassphrasePromptNeedsATerminal: with no terminal the error must say how
// to supply one, rather than hanging on a pipe or reading a line of the data.
func TestPassphrasePromptNeedsATerminal(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	var stderr bytes.Buffer
	_ = stderr
	_, err = passphraseSource{stdin: r}.get()
	if !errors.Is(err, ErrNoPassphrase) {
		t.Fatalf("error = %v, want ErrNoPassphrase", err)
	}
	for _, want := range []string{"--passphrase-file", "--passphrase-env"} {
		if !bytes.Contains([]byte(err.Error()), []byte(want)) {
			t.Errorf("error = %q, want it to mention %s", err, want)
		}
	}
}

// TestNewPassphraseNamesItsOwnOptions: the new passphrase of
// --change-passphrase has its own options, and the messages name them.
func TestNewPassphraseNamesItsOwnOptions(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()
	_, err = passphraseSource{stdin: r, isNew: true}.get()
	if !errors.Is(err, ErrNoPassphrase) || !strings.Contains(err.Error(), "--new-passphrase-file") {
		t.Errorf("error = %v, want ErrNoPassphrase naming --new-passphrase-file", err)
	}
	src := passphraseSource{env: "V", isNew: true}
	if got := src.describe(); got != "--new-passphrase-env V" {
		t.Errorf("describe() = %q", got)
	}
	var warned []string
	src.warnIfInsecureSource(func(f string, a ...any) { warned = append(warned, fmt.Sprintf(f, a...)) })
	if len(warned) != 1 || !strings.Contains(warned[0], "--new-passphrase-env") {
		t.Errorf("warnings = %q, want one naming --new-passphrase-env", warned)
	}
}

func TestPassphraseWarnsAboutEnv(t *testing.T) {
	var warned []string
	warn := func(format string, args ...any) { warned = append(warned, format) }

	passphraseSource{env: "SOMEVAR"}.warnIfInsecureSource(warn)
	if len(warned) != 1 {
		t.Errorf("--passphrase-env produced %d warnings, want 1", len(warned))
	}

	warned = nil
	passphraseSource{file: "/tmp/p"}.warnIfInsecureSource(warn)
	if len(warned) != 0 {
		t.Errorf("--passphrase-file warned %d times, want 0", len(warned))
	}
}

// TestPassphraseFileThatOthersCanRead: a warning, as ssh gives for a key
// (doc/Security_Audit.md, finding 8).
func TestPassphraseFileThatOthersCanRead(t *testing.T) {
	for _, tc := range []struct {
		mode os.FileMode
		warn bool
	}{{0o600, false}, {0o400, false}, {0o640, true}, {0o644, true}} {
		p := filepath.Join(t.TempDir(), "pass")
		os.WriteFile(p, []byte("x\n"), tc.mode)
		os.Chmod(p, tc.mode)
		var warned []string
		passphraseSource{file: p}.warnIfInsecureSource(func(f string, a ...any) { warned = append(warned, fmt.Sprintf(f, a...)) })
		if got := len(warned) == 1 && strings.Contains(warned[0], "chmod 600"); got != tc.warn {
			t.Errorf("mode %04o: warnings %q, want a warning: %v", tc.mode, warned, tc.warn)
		}
	}
}
