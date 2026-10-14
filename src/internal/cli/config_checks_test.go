package cli

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/philmalin/eictar/src/internal/archive"
)

// Tests of config.go that the other tests do not reach: the variables that
// are set but empty, files that cannot be read as a configuration, and the
// edges of a comment.

// TestConfigPathEdges: a variable that is set but empty counts as not set,
// and an empty home has no files.
func TestConfigPathEdges(t *testing.T) {
	home := t.TempDir()
	rc := writeConfig(t, filepath.Join(home, ".eictarrc"), "workers = 1\n")
	for _, tc := range []struct {
		name string
		env  []string
		want string
	}{
		{"EICTAR_CONFIG empty", []string{"EICTAR_CONFIG="}, rc},
		{"XDG_CONFIG_HOME empty", []string{"XDG_CONFIG_HOME="}, rc},
	} {
		withEnv(t, home, tc.env...)
		if got, err := configPath(""); err != nil || got != tc.want {
			t.Errorf("%s: %q, %v; want %q", tc.name, got, err, tc.want)
		}
	}

	// XDG_CONFIG_HOME empty is not set: ~/.config comes before ~/.eictarrc.
	xdg := writeConfig(t, filepath.Join(home, ".config", "eictar", "config"), "workers = 2\n")
	withEnv(t, home, "XDG_CONFIG_HOME=")
	if got, _ := configPath(""); got != xdg {
		t.Errorf("XDG_CONFIG_HOME empty: %q, want %q", got, xdg)
	}
	// XDG_CONFIG_HOME set: ~/.config is not looked at, even when the file
	// that XDG_CONFIG_HOME names is not there.
	withEnv(t, home, "XDG_CONFIG_HOME="+t.TempDir())
	if got, _ := configPath(""); got != rc {
		t.Errorf("XDG_CONFIG_HOME set: %q, want %q", got, rc)
	}

	// With XDG_CONFIG_HOME empty, and no home, the files are not looked for
	// in the working directory.
	cwd := t.TempDir()
	writeConfig(t, filepath.Join(cwd, "eictar", "config"), "workers = 3\n")
	writeConfig(t, filepath.Join(cwd, ".eictarrc"), "workers = 4\n")
	t.Chdir(cwd)
	withEnv(t, "", "XDG_CONFIG_HOME=")
	if got, _ := configPath(""); got != "" {
		t.Errorf("no home: %q, want none", got)
	}
}

// TestConfigFileRefusals: each refusal of a file that is not a usable
// configuration is a usage error that says why.
func TestConfigFileRefusals(t *testing.T) {
	dir := t.TempDir()
	long := writeConfig(t, filepath.Join(dir, "long"), "exclude = "+strings.Repeat("x", 70<<10)+"\n")
	section := writeConfig(t, filepath.Join(dir, "section"), "[codec.zstd\n")
	for _, tc := range []struct {
		name, path, want string
		usage            bool
	}{
		{"missing", filepath.Join(dir, "missing"), "configuration file", true},
		{"a directory", dir, "is not a regular file", true},
		{"a line too long", long, "reading " + long, false},
		{"a section with no ]", section, "is not a [section]", true},
	} {
		err := parseErr(t, "-cf", "a", "--config", tc.path, "p")
		var usage *UsageError
		if err == nil || !strings.Contains(err.Error(), tc.want) || errors.As(err, &usage) != tc.usage {
			t.Errorf("%s: %v; want %q, a usage error: %v", tc.name, err, tc.want, tc.usage)
		}
	}
}

// TestStripComment: a # starts a comment at the start of a line, or after a
// space or a tab, and not inside a word.
func TestStripComment(t *testing.T) {
	for in, want := range map[string]string{
		"# all":       "",
		"a = b # c":   "a = b",
		"a = b\t# c":  "a = b",
		"a = b#c":     "a = b#c",
		"a = b #":     "a = b",
		"a = b\t#":    "a = b",
		"  a = b  ":   "a = b",
		"a = b#c # d": "a = b#c",
	} {
		if got := stripComment(in); got != want {
			t.Errorf("stripComment(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestCodecDefaultsAndMoreParams: the command line can give more parameters
// than the configuration has defaults; both go into the spec.
func TestCodecDefaultsAndMoreParams(t *testing.T) {
	home := t.TempDir()
	writeConfig(t, filepath.Join(home, ".eictarrc"), "[codec.zstd]\nlevel = 5\n")
	withEnv(t, home)
	if got := mustParse(t, "-cf", "a", "--compress", "zstd:level=3,long=20", "p").Compress.String(); got != "zstd:level=3,long=20" {
		t.Errorf("compress = %s", got)
	}
}

// TestUnparsableSizes: a size that does not parse is refused, also where 0
// would mean "no limit".
func TestUnparsableSizes(t *testing.T) {
	for _, opt := range []string{"--chunk-size", "--memory-limit", "--spill-threshold"} {
		if err := parseErr(t, "-cf", "a", opt, "lots", "p"); err == nil || !strings.Contains(err.Error(), opt) {
			t.Errorf("%s lots: %v", opt, err)
		}
	}
}

// showConfig runs --show-config with argv, and returns the source that it
// shows for each key.
func showConfig(t *testing.T, argv ...string) (string, map[string]string) {
	t.Helper()
	code, stdout, stderr := runCLI(append([]string{"--show-config"}, argv...)...)
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	sources := map[string]string{}
	for _, line := range strings.Split(stdout, "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[1] == "=" {
			_, src, _ := strings.Cut(line, "(")
			sources[f[0]] = strings.TrimSuffix(src, ")")
		}
	}
	return stdout, sources
}

// TestShowConfigSources: with an operation, a setting that it does not use
// says so, and the operation is shown. A shorthand for the codec is the
// command line for compress, and for nothing else.
func TestShowConfigSources(t *testing.T) {
	out, src := showConfig(t)
	if strings.Contains(out, "# operation:") || src["update-mode"] != "default" {
		t.Errorf("no operation: update-mode %q:\n%s", src["update-mode"], out)
	}
	out, src = showConfig(t, "-cf", "a", "p")
	if !strings.Contains(out, "# operation: ") || src["update-mode"] != "default; not used by this operation" || src["chunk-size"] != "default" {
		t.Errorf("create: update-mode %q, chunk-size %q:\n%s", src["update-mode"], src["chunk-size"], out)
	}
	for _, short := range []string{"-z", "-J", "--zstd"} {
		_, src = showConfig(t, "-cf", "a", short, "p")
		if src["compress"] != "command line" || src["workers"] != "default" {
			t.Errorf("%s: compress %q, workers %q", short, src["compress"], src["workers"])
		}
	}
}

// TestRunMessages: -v names the configuration file, and only then. A
// create says the name that it gives the archive, and a dry run says that
// it would; another operation, or -q, says nothing.
func TestRunMessages(t *testing.T) {
	home := t.TempDir()
	rc := writeConfig(t, filepath.Join(home, ".eictarrc"), "workers = 2\n")
	withEnv(t, home)
	_, archivePath := opsTree(t)
	for _, tc := range []struct {
		argv []string
		want bool
	}{
		{[]string{"-tvf", archivePath}, true},
		{[]string{"-tf", archivePath}, false},
	} {
		_, _, stderr := runCLI(tc.argv...)
		if strings.Contains(stderr, "using configuration file "+rc) != tc.want {
			t.Errorf("%q: %q", tc.argv, stderr)
		}
	}
	withEnv(t, "")
	if _, _, stderr := runCLI("-tvf", archivePath); strings.Contains(stderr, "using configuration file") {
		t.Errorf("-v with no configuration file: %q", stderr)
	}

	dir := filepath.Dir(archivePath)
	name := filepath.Join(dir, "named")
	for _, tc := range []struct {
		argv []string
		want string
	}{
		{[]string{"-cf", name, "-C", dir, "t"}, "eictar: creating " + name + ".ect"},
		{[]string{"-tf", name}, ""},
		{[]string{"-cnf", filepath.Join(dir, "other"), "-C", dir, "t"}, "eictar: would create " + filepath.Join(dir, "other") + ".ect"},
		{[]string{"-cqf", filepath.Join(dir, "quiet"), "-C", dir, "t"}, ""},
	} {
		code, _, stderr := runCLI(tc.argv...)
		first, _, _ := strings.Cut(stderr, "\n")
		if code != ExitOK || first != tc.want {
			t.Errorf("%q: exit %d, %q; want %q", tc.argv, code, stderr, tc.want)
		}
	}
}

// TestArchiveNameEdges: a name that ends in a separator, an empty name, and
// an operation with no archive keep their name.
func TestArchiveNameEdges(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "backup.ect"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		op   Operation
		in   string
		want string
	}{
		{OpCreate, "dir/", "dir/"},
		{OpCreate, "", ""},
		{OpListCodecs, filepath.Join(dir, "backup"), filepath.Join(dir, "backup")},
	} {
		if got := archiveName(tc.op, tc.in); got != tc.want {
			t.Errorf("%v %q: %q, want %q", tc.op, tc.in, got, tc.want)
		}
	}
}

// TestVersionOfARelease: a version set at build time is the version.
func TestVersionOfARelease(t *testing.T) {
	saved := Version
	t.Cleanup(func() { Version = saved })
	Version = "1.2.3"
	if got := version(); got != "1.2.3" {
		t.Errorf("version() = %q", got)
	}
}

// TestNeedsEscapeEdges: each range of characters that a name must not show
// as they are, at both ends, and the characters just outside.
func TestNeedsEscapeEdges(t *testing.T) {
	for s, want := range map[string]bool{
		"\u001f": true, " ": false, "~": false, "\u007f": true,
		"\u0080": true, "\u009f": true, " ": false,
		"؜": true, "‎": true, "‏": true,
		" ": false, "‪": true, "‮": true, " ": false,
		"⁥": false, "⁦": true, "⁩": true, "⁪": false,
		"�": false, "\xff": true, "\\": true, "a": false,
	} {
		if got := needsEscape(s); got != want {
			t.Errorf("needsEscape(%q) = %v, want %v", s, got, want)
		}
		if got := printable(s) != s; got != want {
			t.Errorf("printable(%q) = %q", s, printable(s))
		}
	}
}

// TestMeterEdges: the edges of the sizes, the times and the line of the
// meter, and a meter only when --progress asks for one.
func TestMeterEdges(t *testing.T) {
	for n, want := range map[int64]string{1023: "1023 B", 1024: "1.0 KiB", 1 << 62: "4096.0 PiB"} {
		if got := humanBytes(n); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", n, got, want)
		}
	}
	for d, want := range map[time.Duration]string{59 * time.Minute: "59:00", time.Hour: "1:00:00"} {
		if got := clock(d); got != want {
			t.Errorf("clock(%v) = %q, want %q", d, got, want)
		}
	}
	if got := meterLine(100, 100, 1, time.Second); !strings.HasSuffix(got, "0:00 left") {
		t.Errorf("done: %q", got)
	}

	var out bytes.Buffer
	m := &meter{out: &out}
	m.clear()
	if out.Len() != 0 {
		t.Errorf("clear with nothing shown: %q", out.String())
	}
	m.started.Store(true)
	m.start.Store(time.Now().UnixNano())
	m.now = time.Now
	m.shown = 60
	m.draw()
	line := meterLine(0, 0, 0, 0)
	if want := "\r" + line + strings.Repeat(" ", 60-len(line)); !strings.HasPrefix(out.String(), "\r") || len(out.String()) != len(want) {
		t.Errorf("a shorter line: %q, want it padded to 60", out.String())
	}

	old := isTerminal
	isTerminal = func(io.Writer) bool { return true }
	t.Cleanup(func() { isTerminal = old })
	rep := &reporter{}
	r, done := withProgress(&Options{}, rep, &bytes.Buffer{})
	done()
	if r != rep {
		t.Error("a meter with no --progress")
	}
}

// TestDiffRefusalsAndLines: --diff refuses an exclude file and a -C that are
// not there, and a line shows a name that it escapes once.
func TestDiffRefusalsAndLines(t *testing.T) {
	dir, archivePath := opsTree(t)
	missing := filepath.Join(dir, "missing")
	for _, argv := range [][]string{
		{"--diff", "-f", archivePath, "-C", dir, "-X", missing},
		{"--diff", "-f", archivePath, "-C", missing},
	} {
		if code, _, stderr := runCLI(argv...); code != ExitIO || !strings.Contains(stderr, missing) {
			t.Errorf("%q: exit %d, %s", argv, code, stderr)
		}
	}
	for _, tc := range []struct {
		d    archive.Difference
		want string
	}{
		{archive.Difference{Kind: archive.DiffHardlink, Path: "a", Archive: "b\x1b"}, `a: not a hardlink of b\x1b`},
		{archive.Difference{Kind: archive.DiffLink, Path: "l", Archive: `x\y`, Disk: "z"}, `l: link target differs: archive "x\\y", disk "z"`},
	} {
		if got := differenceLine(tc.d, printable); got != tc.want {
			t.Errorf("%v: %q, want %q", tc.d.Kind, got, tc.want)
		}
	}
}
