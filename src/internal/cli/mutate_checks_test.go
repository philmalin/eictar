package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// Tests of mutate.go: the refusals and messages of append, compact, a
// change of passphrase, verify, repair and info.

// TestAppendRefusals: append refuses a codec that is not valid and an
// exclude file that is not there, before it touches the archive.
func TestAppendRefusals(t *testing.T) {
	dir, archivePath := opsTree(t)
	before, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		argv []string
		code int
		text string
	}{
		{[]string{"-rf", archivePath, "-C", dir, "--compress", "zstd:level=99", "t/a.txt"}, ExitUsage, "--compress"},
		{[]string{"-rf", archivePath, "-C", dir, "-X", filepath.Join(dir, "missing"), "t/a.txt"}, ExitIO, "reading -X"},
	} {
		code, _, stderr := runCLI(tc.argv...)
		if code != tc.code || !strings.Contains(stderr, printable(tc.text)) {
			t.Errorf("%q: exit %d, %q", tc.argv, code, stderr)
		}
	}
	if after, _ := os.ReadFile(archivePath); string(after) != string(before) {
		t.Error("a refused append changed the archive")
	}
}

// TestAppendPartial: a file that fails under --keep-going makes the exit
// code 1.
func TestAppendPartial(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a file that the user cannot read")
	}
	dir, archivePath := opsTree(t)
	locked := filepath.Join(dir, "t", "locked")
	if err := os.WriteFile(locked, []byte("x"), 0); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCLI("-rf", archivePath, "-C", dir, "--keep-going", "t/locked", "t/a.txt")
	if code != ExitPartial {
		t.Errorf("exit %d, %s; want %d", code, stderr, ExitPartial)
	}
}

// TestCompactMessages: compact says what it did, and says nothing with -q.
// A failure is the error, also with -q.
func TestCompactMessages(t *testing.T) {
	_, archivePath := opsTree(t)
	code, stdout, stderr := runCLI("--compact", "-f", archivePath)
	if code != ExitOK || stdout != archivePath+": nothing to compact\n" {
		t.Errorf("nothing to do: exit %d, %q, %s", code, stdout, stderr)
	}
	if code, _, stderr := runCLI("--delete", "-f", archivePath, "t/a.txt"); code != ExitOK {
		t.Fatalf("delete: exit %d: %s", code, stderr)
	}
	fi, err := os.Stat(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = runCLI("--compact", "-f", archivePath)
	after, err := os.Stat(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	old, now := fi.Size(), after.Size()
	want := strings.Join([]string{archivePath + ":", itoa(old - now), "bytes reclaimed", "(" + itoa(old), "->", itoa(now) + "),", "1 tombstones removed"}, " ")
	if code != ExitOK || strings.TrimSpace(stdout) != want {
		t.Errorf("compact: exit %d, %q, %s; want %q", code, stdout, stderr, want)
	}
	if code, stdout, _ := runCLI("--compact", "-qf", archivePath); code != ExitOK || stdout != "" {
		t.Errorf("-q: exit %d, %q", code, stdout)
	}
	missing := filepath.Join(t.TempDir(), "missing.ect")
	for _, argv := range [][]string{{"--compact", "-f", missing}, {"--compact", "-qf", missing}, {"--repair", "-f", missing}, {"--info", "-f", missing}} {
		if code, stdout, _ := runCLI(argv...); code == ExitOK || stdout != "" {
			t.Errorf("%q: exit %d, %q; want a failure", argv, code, stdout)
		}
	}
	if code, stdout, _ := runCLI("--repair", "-qf", archivePath); code != ExitOK || stdout != "" {
		t.Errorf("repair -q: exit %d, %q", code, stdout)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// TestVerifyQuick: --quick says that it read the structure only.
func TestVerifyQuick(t *testing.T) {
	_, archivePath := opsTree(t)
	code, stdout, stderr := runCLI("--verify", "--quick", "-f", archivePath)
	if code != ExitOK || stdout != archivePath+": structure OK (member data not read)\n" {
		t.Errorf("exit %d, %q, %s", code, stdout, stderr)
	}
}

// TestChangePassphraseKDF: the --kdf-* options that the command line gives
// change the key derivation, and the others keep those of the archive.
func TestChangePassphraseKDF(t *testing.T) {
	dir, _ := opsTree(t)
	pass := filepath.Join(dir, "pass")
	newPass := filepath.Join(dir, "new")
	for p, s := range map[string]string{pass: "correct horse", newPass: "battery staple"} {
		if err := os.WriteFile(p, []byte(s+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	archivePath := filepath.Join(dir, "e.ect")
	if code, _, stderr := runCLI("-cef", archivePath, "-C", dir, "--passphrase-file", pass,
		"--kdf-time", "2", "--kdf-memory", "8192", "--kdf-threads", "1", "t"); code != ExitOK {
		t.Fatalf("create: exit %d: %s", code, stderr)
	}
	if code, _, stderr := runCLI("--change-passphrase", "-f", archivePath, "--passphrase-file", pass,
		"--new-passphrase-file", newPass, "--kdf-memory", "16384", "--kdf-threads", "2"); code != ExitOK {
		t.Fatalf("change: exit %d: %s", code, stderr)
	}
	code, stdout, stderr := runCLI("--info", "-f", archivePath, "--passphrase-file", newPass)
	if code != ExitOK || !strings.Contains(stdout, "time=2 memory=16384 KiB threads=2") {
		t.Errorf("exit %d, %s, %s", code, stdout, stderr)
	}
}

// TestInfoRows: the rows that depend on the archive: an index that is
// authenticated and not sealed, members stored without a codec, no shared
// content, and an archive with no content.
func TestInfoRows(t *testing.T) {
	dir, _ := opsTree(t)
	pass := filepath.Join(dir, "pass")
	if err := os.WriteFile(pass, []byte("correct horse\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A passphrase goes only with an encrypted archive: with one, eictar
	// refuses an archive that is not.
	info := func(argv ...string) string {
		t.Helper()
		var open []string
		if argv[0] == "-e" {
			open = []string{"--passphrase-file", pass}
		}
		archivePath := filepath.Join(t.TempDir(), "i.ect")
		create := append([]string{"-cf", archivePath, "-C", dir}, argv...)
		if code, _, stderr := runCLI(create...); code != ExitOK {
			t.Fatalf("create %q: exit %d: %s", argv, code, stderr)
		}
		code, stdout, stderr := runCLI(append([]string{"--info", "-f", archivePath}, open...)...)
		if code != ExitOK {
			t.Fatalf("info: exit %d: %s", code, stderr)
		}
		return stdout
	}
	row := func(out, key string) string {
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(l, key+":") {
				return strings.TrimSpace(strings.TrimPrefix(l, key+":"))
			}
		}
		return ""
	}

	out := info("-e", "--passphrase-file", pass, "--kdf-time", "1", "--kdf-memory", "8192", "--kdf-threads", "1", "t")
	if !strings.HasSuffix(row(out, "index"), "bytes, authenticated, not sealed") {
		t.Errorf("index: %q", row(out, "index"))
	}
	if strings.Contains(out, "shared content:") || strings.Contains(row(out, "codecs"), "none (") {
		t.Errorf("no shared content, no stored member:\n%s", out)
	}

	out = info("--compress", "none", "t")
	if got := row(out, "codecs"); got != "none (2 members)" {
		t.Errorf("stored: codecs %q", got)
	}

	if err := os.Mkdir(filepath.Join(dir, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	out = info("--compress", "none", "empty")
	if got := row(out, "codecs"); got != "-" {
		t.Errorf("no content: codecs %q", got)
	}
}

// TestDryRunRefusals: a dry run refuses what its real run refuses.
func TestDryRunRefusals(t *testing.T) {
	dir, archivePath := opsTree(t)
	missing := filepath.Join(dir, "missing")
	for _, tc := range []struct {
		argv []string
		code int
		text string
	}{
		{[]string{"-cnf", filepath.Join(dir, "n.ect"), "-C", dir, "--compress", "zstd:level=99", "t"}, ExitUsage, "--compress"},
		{[]string{"-cnf", filepath.Join(dir, "n.ect"), "-C", dir, "-X", missing, "t"}, ExitIO, "reading -X"},
		{[]string{"-rnf", missing + ".ect", "-C", dir, "t"}, ExitIO, "missing.ect"},
		{[]string{"-xnf", archivePath, "-d", t.TempDir(), "-X", missing}, ExitIO, "reading -X"},
		{[]string{"-xnf", missing + ".ect", "-d", t.TempDir()}, ExitIO, "missing.ect"},
		{[]string{"--delete", "-nf", archivePath, "nothing"}, ExitUsage, "nothing"},
	} {
		if code, _, stderr := runCLI(tc.argv...); code != tc.code || !strings.Contains(stderr, printable(tc.text)) {
			t.Errorf("%q: exit %d, %s; want %d", tc.argv, code, stderr, tc.code)
		}
	}
}

// TestDryRunPolicies: the dry run of -u applies the update mode, and that
// of -r the policy for a path that the archive has.
func TestDryRunPolicies(t *testing.T) {
	dir, archivePath := opsTree(t)
	if code, stdout, stderr := runCLI("-unf", archivePath, "-C", dir, "t/a.txt"); code != ExitOK || stdout != "" {
		t.Errorf("-u of an unchanged file: exit %d, %q, %s; want nothing", code, stdout, stderr)
	}
	if code, stdout, stderr := runCLI("-rnf", archivePath, "-C", dir, "--on-conflict", "skip", "t/a.txt"); code != ExitOK || stdout != "" {
		t.Errorf("-r skip: exit %d, %q, %s; want nothing", code, stdout, stderr)
	}
}

// TestDryRunPartialAndCollision: a failure under --keep-going makes the
// exit code 1, and a collision after --strip-components is in the summary.
func TestDryRunPartialAndCollision(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{"p1", "p2"} {
		if err := os.MkdirAll(filepath.Join(dir, p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, p, "a"), []byte(p), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	archivePath := filepath.Join(dir, "a.ect")
	if code, _, stderr := runCLI("-cf", archivePath, "-C", dir, "p1", "p2"); code != ExitOK {
		t.Fatalf("create: exit %d: %s", code, stderr)
	}
	_, _, stderr := runCLI("-xnf", archivePath, "-d", t.TempDir(), "--strip-components", "1")
	if !strings.Contains(stderr, "; 1 left out (same path)") {
		t.Errorf("summary: %q", stderr)
	}

	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		return
	}
	if err := os.Chmod(filepath.Join(dir, "p1"), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(filepath.Join(dir, "p1"), 0o755) })
	code, _, stderr := runCLI("-cnf", filepath.Join(dir, "n.ect"), "-C", dir, "--keep-going", "p1", "p2")
	if code != ExitPartial {
		t.Errorf("a directory that does not open: exit %d, %s; want %d", code, stderr, ExitPartial)
	}
}
