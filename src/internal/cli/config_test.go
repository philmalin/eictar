package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeConfig puts a configuration file at path, private to the user.
func writeConfig(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func parseErr(t *testing.T, argv ...string) error {
	t.Helper()
	_, err := Parse(argv)
	return err
}

// TestConfigPrecedence: the command line wins over the environment, which
// wins over the configuration file, which wins over the default.
func TestConfigPrecedence(t *testing.T) {
	home := t.TempDir()
	writeConfig(t, filepath.Join(home, ".eictarrc"), "workers = 3\nchunk-size = 1MiB\n")

	withEnv(t, home)
	if o := mustParse(t, "-cf", "a", "p"); o.Workers != 3 || o.ChunkSize != 1<<20 {
		t.Errorf("file: workers=%d chunk=%v", o.Workers, o.ChunkSize)
	}
	withEnv(t, home, "EICTAR_WORKERS=5")
	if o := mustParse(t, "-cf", "a", "p"); o.Workers != 5 || o.ChunkSize != 1<<20 {
		t.Errorf("environment: workers=%d chunk=%v", o.Workers, o.ChunkSize)
	}
	if o := mustParse(t, "-cf", "a", "-j", "7", "p"); o.Workers != 7 {
		t.Errorf("command line: workers=%d", o.Workers)
	}
}

func TestCodecDefaults(t *testing.T) {
	home := t.TempDir()
	writeConfig(t, filepath.Join(home, ".eictarrc"), "compress = zstd\n[codec.zstd]\nlevel = 19\n[codec.xz]\npreset = 2\n")
	withEnv(t, home)

	for _, tc := range []struct {
		argv []string
		want string
	}{
		{[]string{"-cf", "a", "p"}, "zstd:level=19"},
		{[]string{"-cf", "a", "--compress", "zstd:level=5", "p"}, "zstd:level=5"},
		{[]string{"-cJf", "a", "p"}, "xz:preset=2"},
		{[]string{"-czf", "a", "p"}, "gzip"},
	} {
		if got := mustParse(t, tc.argv...).Compress.String(); got != tc.want {
			t.Errorf("%q: compress = %s, want %s", tc.argv, got, tc.want)
		}
	}

	withEnv(t, home, "EICTAR_CODEC_ZSTD_LEVEL=7")
	if got := mustParse(t, "-cf", "a", "p").Compress.String(); got != "zstd:level=7" {
		t.Errorf("the environment did not win over the file: %s", got)
	}
}

// TestConfigRefusals: an unknown key, an unknown variable, a bad value and a
// passphrase are all usage errors, and each names where it came from.
func TestConfigRefusals(t *testing.T) {
	for _, tc := range []struct {
		name, file string
		env        []string
		want       string
	}{
		{"unknown key", "compres = zstd\n", nil, `unknown setting "compres"`},
		{"unknown variable", "", []string{"EICTAR_COMPESS=zstd"}, "EICTAR_COMPESS"},
		{"passphrase variable", "", []string{"EICTAR_PASSPHRASE=secret"}, "a passphrase never comes"},
		{"passphrase in file", "passphrase-file = /tmp/p\n", nil, "command line only"},
		{"archive in file", "file = a.eictar\n", nil, "command line only"},
		{"bad value", "workers = many\n", nil, ".eictarrc:1"},
		{"bad bool", "keep-going = maybe\n", nil, "want true or false"},
		{"bad codec value", "[codec.zstd]\nlevel = 99\n", nil, ".eictarrc:2"},
		{"unknown codec", "[codec.lz4]\n", nil, "unknown codec"},
		{"unknown section", "[general]\n", nil, "unknown section"},
		{"set twice", "workers = 2\nworkers = 3\n", nil, "set twice"},
		{"bad codec variable", "", []string{"EICTAR_CODEC_ZSTD_LEVLE=3"}, "EICTAR_CODEC_ZSTD_LEVLE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			if tc.file != "" {
				writeConfig(t, filepath.Join(home, ".eictarrc"), tc.file)
			}
			withEnv(t, home, tc.env...)
			err := parseErr(t, "-cf", "a", "p")
			var usage *UsageError
			if !errors.As(err, &usage) || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("got %v, want a usage error containing %q", err, tc.want)
			}
		})
	}
}

// TestConfigScope: a configured value that means nothing for the operation
// is ignored, rather than an error on every run; the command line keeps its
// own rules, and a shorthand beats the configured codec.
func TestConfigScope(t *testing.T) {
	home := t.TempDir()
	writeConfig(t, filepath.Join(home, ".eictarrc"),
		"compress = xz\npreserve-owner = yes\nencrypt-index = on\nupdate-mode = digest\nlong = true\n")
	withEnv(t, home)
	isRoot = func() bool { return false }
	t.Cleanup(func() { isRoot = func() bool { return os.Geteuid() == 0 } })

	if o := mustParse(t, "-tf", "a"); !o.Long || o.PreserveOwner {
		t.Errorf("-t: long=%v preserve-owner=%v", o.Long, o.PreserveOwner)
	}
	if o := mustParse(t, "-rf", "a", "p"); o.UpdateMode != "newer" || o.Compress.Name != "xz" {
		t.Errorf("-r: update-mode=%s compress=%s", o.UpdateMode, o.Compress)
	}
	if o := mustParse(t, "-czf", "a", "p"); o.Compress.Name != "gzip" {
		t.Errorf("-z did not beat compress = xz: %s", o.Compress)
	}
	// On extract, preserve-owner applies, and a normal user is told so.
	if err := parseErr(t, "-xf", "a"); err == nil || !strings.Contains(err.Error(), "needs root") {
		t.Errorf("-x with preserve-owner from the file: %v", err)
	}
}

func TestConfigFileMustBePrivate(t *testing.T) {
	home := t.TempDir()
	p := writeConfig(t, filepath.Join(home, ".eictarrc"), "workers = 2\n")
	if err := os.Chmod(p, 0o620); err != nil {
		t.Fatal(err)
	}
	withEnv(t, home)
	if err := parseErr(t, "-cf", "a", "p"); err == nil || !strings.Contains(err.Error(), "can write it") {
		t.Errorf("a group-writable file: %v", err)
	}
}

// TestPassphraseVariableIsNotASetting: the variable --passphrase-env names
// may start with EICTAR_; it is a secret, not an unknown setting.
func TestPassphraseVariableIsNotASetting(t *testing.T) {
	withEnv(t, t.TempDir(), "EICTAR_BACKUP_PASS=secret")
	if err := parseErr(t, "-tf", "a", "--passphrase-env", "EICTAR_BACKUP_PASS"); err != nil {
		t.Errorf("the passphrase variable was read as a setting: %v", err)
	}
	if err := parseErr(t, "-tf", "a"); err == nil {
		t.Error("without --passphrase-env, EICTAR_BACKUP_PASS is an unknown setting")
	}
}

func TestNoConfigIgnoresFileAndEnvironment(t *testing.T) {
	home := t.TempDir()
	writeConfig(t, filepath.Join(home, ".eictarrc"), "workers = 2\n")
	withEnv(t, home, "EICTAR_CHUNK_SIZE=1MiB", "EICTAR_BOGUS=1")
	o := mustParse(t, "-cf", "a", "--no-config", "p")
	if o.Workers == 2 || o.ChunkSize == 1<<20 {
		t.Errorf("--no-config still read the configuration: workers=%d chunk=%v", o.Workers, o.ChunkSize)
	}
}

// TestConfigFileSearch: --config, then EICTAR_CONFIG, then the XDG file,
// then ~/.eictarrc; and never the current directory.
func TestConfigFileSearch(t *testing.T) {
	home := t.TempDir()
	writeConfig(t, filepath.Join(home, ".eictarrc"), "workers = 2\n")
	writeConfig(t, filepath.Join(home, ".config", "eictar", "config"), "workers = 3\n")
	named := writeConfig(t, filepath.Join(t.TempDir(), "named"), "workers = 4\n")
	envNamed := writeConfig(t, filepath.Join(t.TempDir(), "env"), "workers = 5\n")

	withEnv(t, home)
	if o := mustParse(t, "-cf", "a", "p"); o.Workers != 3 {
		t.Errorf("the XDG file did not come before ~/.eictarrc: workers=%d", o.Workers)
	}
	withEnv(t, home, "EICTAR_CONFIG="+envNamed)
	if o := mustParse(t, "-cf", "a", "p"); o.Workers != 5 {
		t.Errorf("EICTAR_CONFIG: workers=%d", o.Workers)
	}
	if o := mustParse(t, "-cf", "a", "--config", named, "p"); o.Workers != 4 {
		t.Errorf("--config: workers=%d", o.Workers)
	}
	if err := parseErr(t, "-cf", "a", "--config", filepath.Join(home, "missing"), "p"); err == nil {
		t.Error("a missing --config file was not an error")
	}

	// A .eictarrc in the working directory can come from someone else's
	// archive. It must have no effect.
	cwd := t.TempDir()
	writeConfig(t, filepath.Join(cwd, ".eictarrc"), "exclude = *\n")
	t.Chdir(cwd)
	withEnv(t, t.TempDir())
	if o := mustParse(t, "-cf", "a", "p"); len(o.Exclude) != 0 {
		t.Errorf("a .eictarrc in the current directory was read: exclude=%v", o.Exclude)
	}
}

func TestConfigComments(t *testing.T) {
	home := t.TempDir()
	writeConfig(t, filepath.Join(home, ".eictarrc"),
		"# a comment\n\nexclude = build#1   # a trailing comment\nexclude = *.o\n")
	withEnv(t, home)
	o := mustParse(t, "-cf", "a", "p")
	if strings.Join(o.Exclude, "|") != "build#1|*.o" {
		t.Errorf("exclude = %q", o.Exclude)
	}
}

func TestShowConfig(t *testing.T) {
	home := t.TempDir()
	rc := writeConfig(t, filepath.Join(home, ".eictarrc"), "workers = 3\n[codec.zstd]\nlevel = 19\n")
	withEnv(t, home, "EICTAR_CHUNK_SIZE=8MiB")

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"--show-config", "-j", "9"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{
		"# configuration file: " + rc,
		"workers", "9", "(command line)",
		"chunk-size", "8MiB", "(EICTAR_CHUNK_SIZE)",
		"compress", "zstd:level=19",
		"codec.zstd.level", rc + ":3",
		"update-mode", "(default)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("--show-config does not show %q:\n%s", want, out)
		}
	}
}
