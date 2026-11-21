package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/philmalin/eictar/src/internal/archive"
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

// TestRepairThroughRun: a file that ends with a damaged trailer is refused
// with exit 3, and is not changed. -n says what a repair removes, also with
// -q, and --discard-damaged removes it. A file whose last write stopped
// before its trailer is repaired with no option (doc/design.md 9.5).
func TestRepairThroughRun(t *testing.T) {
	dir, archivePath := opsTree(t)
	first, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runCLI("-rf", archivePath, "-C", dir, "t/a.txt"); code != ExitOK {
		t.Fatalf("append: exit %d: %s", code, stderr)
	}
	damaged, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	damaged[len(damaged)-10] ^= 0xff
	if err := os.WriteFile(archivePath, damaged, 0o644); err != nil {
		t.Fatal(err)
	}
	unchanged := func(what string) {
		t.Helper()
		if b, _ := os.ReadFile(archivePath); !bytes.Equal(b, damaged) {
			t.Fatalf("%s changed the archive", what)
		}
	}
	removed := itoa(int64(len(damaged) - len(first)))

	code, stdout, stderr := runCLI("--repair", "-f", archivePath)
	if code != ExitCorrupt || stdout != "" || !strings.Contains(stderr, "--discard-damaged") {
		t.Errorf("repair: exit %d, %q, %q", code, stdout, stderr)
	}
	unchanged("a refused repair")
	code, stdout, _ = runCLI("--repair", "-n", "-qf", archivePath)
	if want := archivePath + ": would remove " + removed + " bytes and restore generation 1; " +
		"the newest generation looks complete, so the repair needs --discard-damaged\n"; code != ExitOK || stdout != want {
		t.Errorf("-n -q: exit %d, %q, want %q", code, stdout, want)
	}
	code, stdout, _ = runCLI("--repair", "-n", "--discard-damaged", "-f", archivePath)
	if want := archivePath + ": would remove " + removed + " bytes and restore generation 1\n"; code != ExitOK || stdout != want {
		t.Errorf("-n --discard-damaged: exit %d, %q, want %q", code, stdout, want)
	}
	unchanged("-n")
	code, stdout, _ = runCLI("--repair", "--discard-damaged", "-f", archivePath)
	if want := archivePath + ": removed " + removed + " bytes; restored generation 1\n"; code != ExitOK || stdout != want {
		t.Errorf("--discard-damaged: exit %d, %q, want %q", code, stdout, want)
	}
	if b, _ := os.ReadFile(archivePath); !bytes.Equal(b, first) {
		t.Error("the archive is not its first generation")
	}

	// An interrupted write: no trailer at the end, and no option needed.
	if err := os.WriteFile(archivePath, append(bytes.Clone(first), "blob"...), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, stdout, _ = runCLI("--repair", "-n", "-f", archivePath); code != ExitOK ||
		stdout != archivePath+": would remove 4 bytes and restore generation 1\n" {
		t.Errorf("-n of an interrupted write: exit %d, %q", code, stdout)
	}
	if code, stdout, _ = runCLI("--repair", "-f", archivePath); code != ExitOK ||
		stdout != archivePath+": removed 4 bytes; restored generation 1\n" {
		t.Errorf("repair of an interrupted write: exit %d, %q", code, stdout)
	}

	if code, _, stderr := runCLI("--verify", "--discard-damaged", "-f", archivePath); code != ExitUsage ||
		!strings.Contains(stderr, "--discard-damaged applies to --repair only") {
		t.Errorf("--discard-damaged with --verify: exit %d, %s", code, stderr)
	}
	// A read during an append is a busy archive, not a damaged one.
	if code := exitCodeFor(fmt.Errorf("a.ect: %w", archive.ErrLocked)); code != ExitIO {
		t.Errorf("a locked archive: exit %d, want %d", code, ExitIO)
	}
}

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
	if got := row(out, "content"); !strings.HasSuffix(got, " (100.0%)") {
		t.Errorf("stored: content %q", got)
	}

	if err := os.Mkdir(filepath.Join(dir, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	out = info("--compress", "none", "empty")
	if got := row(out, "codecs"); got != "-" {
		t.Errorf("no content: codecs %q", got)
	}
	if got := row(out, "content"); got != "0 bytes, stored in 0 bytes" {
		t.Errorf("no content: content %q", got)
	}
}

// TestInfoContentPercent: the content row gives the stored size as a
// percentage of the plain size, to one decimal.
func TestInfoContentPercent(t *testing.T) {
	var b strings.Builder
	writeInfo(&b, "a.ect", &archive.ArchiveInfo{Plain: 110361, Blobs: 35871})
	if !strings.Contains(b.String(), "content:     110361 bytes, stored in 35871 bytes (32.5%)\n") {
		t.Errorf("%s", b.String())
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
