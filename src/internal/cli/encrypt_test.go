package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// kdfFast keeps the key derivation of the tests short.
var kdfFast = []string{"--kdf-time", "1", "--kdf-memory", "8192", "--kdf-threads", "1"}

// TestEncryptArchiveThroughRun: --encrypt-archive encrypts a plaintext
// archive, says so, and prints the reminder about the old file, also with -q.
// A second run is a usage error that names --change-passphrase.
func TestEncryptArchiveThroughRun(t *testing.T) {
	dir, archivePath := opsTree(t)
	pass := filepath.Join(dir, "pass")
	if err := os.WriteFile(pass, []byte("battery staple\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const reminder = "the old plaintext file can still be read from free disk space, snapshots and backups"

	code, stdout, stderr := runCLI(append([]string{"--encrypt-archive", "-f", archivePath, "--passphrase-file", pass}, kdfFast...)...)
	if code != ExitOK || !strings.Contains(stdout, ": encrypted; 2 members sealed, ") || !strings.Contains(stderr, reminder) {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	code, stdout, stderr = runCLI("--info", "-f", archivePath, "--passphrase-file", pass)
	if code != ExitOK || !strings.Contains(stdout, "XChaCha20-Poly1305") || !strings.Contains(stdout, "authenticated, not sealed") {
		t.Errorf("info: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if code, _, stderr := runCLI("--verify", "-f", archivePath, "--passphrase-file", pass); code != ExitOK {
		t.Errorf("verify: exit %d: %s", code, stderr)
	}

	before, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	code, _, stderr = runCLI("--encrypt-archive", "-f", archivePath, "--passphrase-file", pass)
	if code != ExitUsage || !strings.Contains(stderr, "already encrypted") || !strings.Contains(stderr, "--change-passphrase") {
		t.Errorf("an encrypted archive: exit %d, want %d: %s", code, ExitUsage, stderr)
	}
	if after, _ := os.ReadFile(archivePath); !bytes.Equal(before, after) {
		t.Error("a refused run changed the archive")
	}

	// -q hides the summary, and not the reminder.
	quiet := filepath.Join(dir, "q.ect")
	if code, _, stderr := runCLI("-cf", quiet, "-C", dir, "t"); code != ExitOK {
		t.Fatalf("create: exit %d: %s", code, stderr)
	}
	code, stdout, stderr = runCLI(append([]string{"--encrypt-archive", "-q", "--encrypt-index", "-f", quiet, "--passphrase-file", pass}, kdfFast...)...)
	if code != ExitOK || stdout != "" || !strings.Contains(stderr, reminder) {
		t.Errorf("-q: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	code, stdout, _ = runCLI("--info", "-f", quiet, "--passphrase-file", pass)
	if code != ExitOK || !strings.Contains(stdout, "bytes, sealed") {
		t.Errorf("--encrypt-index: exit %d, stdout %q", code, stdout)
	}
}

// TestEncryptArchiveRefusals: the options that mean nothing with
// --encrypt-archive are usage errors, and the archive does not change.
func TestEncryptArchiveRefusals(t *testing.T) {
	_, archivePath := opsTree(t)
	before, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		argv []string
		text string
	}{
		{[]string{"-e"}, "needs no -e"},
		{[]string{"--new-passphrase-file", "x"}, "--change-passphrase only"},
		{[]string{"--recompress", "zstd"}, "--compact only"},
		{[]string{"t/a.txt"}, "no positional arguments"},
		{[]string{"--scratch-dir", "x"}, "does not apply"},
		{[]string{"--compact"}, "only one operation"},
	} {
		argv := append([]string{"--encrypt-archive", "-f", archivePath}, tc.argv...)
		code, _, stderr := runCLI(argv...)
		if code != ExitUsage || !strings.Contains(stderr, tc.text) {
			t.Errorf("%q: exit %d, stderr %q; want %d and %q", tc.argv, code, stderr, ExitUsage, tc.text)
		}
	}
	if after, _ := os.ReadFile(archivePath); !bytes.Equal(before, after) {
		t.Error("a refused run changed the archive")
	}
}

// TestEncryptArchiveOptions: --encrypt-index and the --kdf-* options apply,
// as for a create, and need no -e.
func TestEncryptArchiveOptions(t *testing.T) {
	o := mustParse(t, "--encrypt-archive", "-f", "a", "--encrypt-index", "--kdf-time", "5")
	if o.Op != OpEncryptArchive || !o.EncryptIdx || o.KDFTime != 5 || o.Encrypt {
		t.Errorf("op %v, encrypt-index %v, kdf-time %d, encrypt %v", o.Op, o.EncryptIdx, o.KDFTime, o.Encrypt)
	}
	if !OpEncryptArchive.WritesArchive() {
		t.Error("--encrypt-archive does not write the archive")
	}
}

// TestConfigScopeOfEncryptArchive: encrypt-index and the kdf-* keys of a
// configuration apply to --encrypt-archive, as they do to a create. encrypt
// does not: the operation itself encrypts.
func TestConfigScopeOfEncryptArchive(t *testing.T) {
	home := t.TempDir()
	writeConfig(t, filepath.Join(home, ".eictarrc"), "encrypt = yes\nencrypt-index = on\nkdf-time = 5\n")
	withEnv(t, home)
	o := mustParse(t, "--encrypt-archive", "-f", "a")
	if !o.EncryptIdx || o.KDFTime != 5 || o.Encrypt {
		t.Errorf("--encrypt-archive: encrypt-index %v, kdf-time %d, encrypt %v", o.EncryptIdx, o.KDFTime, o.Encrypt)
	}
	if o := mustParse(t, "--compact", "-f", "a"); o.EncryptIdx || o.KDFTime == 5 {
		t.Errorf("--compact: encrypt-index %v, kdf-time %d", o.EncryptIdx, o.KDFTime)
	}
}
