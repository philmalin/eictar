package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPrintable(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"src/main.go", "src/main.go"},
		{"naïve café/日本", "naïve café/日本"},
		{"a\x1b[31mRED", `a\x1b[31mRED`},
		{"two\nlines", `two\nlines`},
		{"tab\there\rcr", `tab\there\rcr`},
		{"del\x7f", `del\x7f`},
		{"back\\slash", `back\\slash`},
		{"latin1 \xe9t\xe9", `latin1 \xe9t\xe9`},
		{"c1 \u009b31m", `c1 \u009b31m`},
		{"evil\u202Etxt.exe", `evil\u202etxt.exe`},
		{"replacement � stays", "replacement � stays"},
	} {
		if got := printable(tc.in); got != tc.want {
			t.Errorf("printable(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// forceTerminal makes isTerminal answer yes, for the run of one test.
func forceTerminal(t *testing.T, yes bool) {
	saved := isTerminal
	isTerminal = func(io.Writer) bool { return yes }
	t.Cleanup(func() { isTerminal = saved })
}

// TestNamesOnATerminal: a name with an escape sequence reaches a terminal
// escaped, in the listing, the long listing, a dry run and --diff, and a pipe
// exactly (doc/Security_Audit.md, finding 12).
func TestNamesOnATerminal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a Windows file name cannot hold a control character")
	}
	dir := t.TempDir()
	evil := "a\x1b[2J"
	if err := os.MkdirAll(filepath.Join(dir, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "src", evil), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(dir, "a.ect")
	run := func(argv ...string) (string, string) {
		var stdout, stderr bytes.Buffer
		Run(argv, &stdout, &stderr)
		return stdout.String(), stderr.String()
	}
	forceTerminal(t, false)
	run("--no-config", "-cf", archivePath, "-C", dir, "src")
	// A tree with src and without the file: --diff names the file.
	emptySrc := t.TempDir()
	if err := os.Mkdir(filepath.Join(emptySrc, "src"), 0o755); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		argv []string
	}{
		{"list", []string{"--no-config", "-tf", archivePath}},
		{"long list", []string{"--no-config", "-tvf", archivePath}},
		{"dry run", []string{"--no-config", "-cnf", filepath.Join(dir, "b.ect"), "-C", dir, "src"}},
		{"diff", []string{"--no-config", "--diff", "-f", archivePath, "-C", emptySrc}},
	} {
		forceTerminal(t, true)
		out, _ := run(tc.argv...)
		if strings.Contains(out, "\x1b") || !strings.Contains(out, `src/a\x1b[2J`) {
			t.Errorf("%s on a terminal: %q, want the name escaped", tc.name, out)
		}
		forceTerminal(t, false)
		if out, _ := run(tc.argv...); !strings.Contains(out, "src/"+evil) {
			t.Errorf("%s to a pipe: %q, want the name exactly", tc.name, out)
		}
	}
}

// A message is always escaped: it is for a person, who can read a log on a
// terminal later.
func TestMessagesAreEscaped(t *testing.T) {
	forceTerminal(t, false)
	var stderr bytes.Buffer
	rep := &reporter{errOut: &stderr}
	rep.Warn("%s: socket ignored", "dir/\x1b]0;title\x07")
	if want := "eictar: dir/\\x1b]0;title\\x07: socket ignored\n"; stderr.String() != want {
		t.Errorf("Warn wrote %q, want %q", stderr.String(), want)
	}

	var out, errOut bytes.Buffer
	Run([]string{"--no-config", "-tf", filepath.Join(t.TempDir(), "no\x1b[2Jsuch.ect")}, &out, &errOut)
	if strings.Contains(errOut.String(), "\x1b") {
		t.Errorf("error on stderr: %q, want the name escaped", errOut.String())
	}
}
