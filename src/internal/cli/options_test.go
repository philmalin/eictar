package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"eictar/src/internal/archive"
	"eictar/src/internal/format"
)

func mustParse(t *testing.T, argv ...string) *Options {
	t.Helper()
	o, err := Parse(argv)
	if err != nil {
		t.Fatalf("Parse(%q): %v", argv, err)
	}
	return o
}

// TestParseBundling covers the classical UNIX forms the interface promises
// (doc/design.md section 10): separate, bundled, and bundled with the
// value-taking letter last.
func TestParseBundling(t *testing.T) {
	want := func(o *Options) bool {
		return o.Op == OpCreate && o.Archive == "a.eictar" &&
			len(o.Args) == 1 && o.Args[0] == "path"
	}

	for _, argv := range [][]string{
		{"-c", "-f", "a.eictar", "path"},
		{"-cf", "a.eictar", "path"},
		{"-cf=a.eictar", "path"},
		{"--create", "--file", "a.eictar", "path"},
		{"--create", "--file=a.eictar", "path"},
		{"-c", "--file=a.eictar", "path"},
		{"path", "-cf", "a.eictar"}, // interspersed
	} {
		t.Run(strings.Join(argv, " "), func(t *testing.T) {
			if o := mustParse(t, argv...); !want(o) {
				t.Errorf("parsed as op=%v file=%q args=%q", o.Op, o.Archive, o.Args)
			}
		})
	}
}

func TestParseVerboseCounts(t *testing.T) {
	for _, tc := range []struct {
		argv []string
		want int
	}{
		{[]string{"-tf", "a"}, 0},
		{[]string{"-tvf", "a"}, 1},
		{[]string{"-tvvf", "a"}, 2},
		{[]string{"-tf", "a", "-v", "-v", "-v"}, 3},
	} {
		t.Run(strings.Join(tc.argv, " "), func(t *testing.T) {
			if got := mustParse(t, tc.argv...).Verbose; got != tc.want {
				t.Errorf("Verbose = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestParseOperations(t *testing.T) {
	for _, tc := range []struct {
		argv []string
		want Operation
	}{
		{[]string{"-cf", "a", "p"}, OpCreate},
		{[]string{"-rf", "a", "p"}, OpAppend},
		{[]string{"-tf", "a"}, OpList},
		{[]string{"-xf", "a"}, OpExtract},
		{[]string{"-uf", "a", "p"}, OpUpdate},
		{[]string{"--delete", "-f", "a", "p"}, OpDelete},
		{[]string{"--compact", "-f", "a"}, OpCompact},
		{[]string{"--verify", "-f", "a"}, OpVerify},
		{[]string{"--repair", "-f", "a"}, OpRepair},
		{[]string{"--info", "-f", "a"}, OpInfo},
		{[]string{"--list-codecs"}, OpListCodecs},
	} {
		t.Run(tc.want.String(), func(t *testing.T) {
			if got := mustParse(t, tc.argv...).Op; got != tc.want {
				t.Errorf("Op = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseCompressionSelection(t *testing.T) {
	for _, tc := range []struct {
		argv []string
		want string
	}{
		{[]string{"-cf", "a", "p"}, "zstd"}, // the default
		{[]string{"-cf", "a", "-z", "p"}, "gzip"},
		{[]string{"-cf", "a", "-J", "p"}, "xz"},
		{[]string{"-cf", "a", "--zstd", "p"}, "zstd"},
		{[]string{"-cf", "a", "--compress", "none", "p"}, "none"},
		{[]string{"-cf", "a", "-Z", "zstd:level=19", "p"}, "zstd:level=19"},
	} {
		t.Run(strings.Join(tc.argv, " "), func(t *testing.T) {
			if got := mustParse(t, tc.argv...).Compress.String(); got != tc.want {
				t.Errorf("Compress = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseOverwritePolicy(t *testing.T) {
	for _, tc := range []struct {
		argv []string
		want string
	}{
		{[]string{"-xf", "a"}, OverwriteAlways},
		{[]string{"-xkf", "a"}, OverwriteNever},
		{[]string{"-xf", "a", "--newer-only"}, OverwriteNewer},
		{[]string{"-xf", "a", "--overwrite"}, OverwriteAlways},
	} {
		t.Run(strings.Join(tc.argv, " "), func(t *testing.T) {
			if got := mustParse(t, tc.argv...).Overwrite; got != tc.want {
				t.Errorf("Overwrite = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseSizesAndDefaults(t *testing.T) {
	o := mustParse(t, "-cf", "a", "--chunk-size", "8MiB", "--memory-limit", "2GiB", "p")
	if o.ChunkSize != 8<<20 {
		t.Errorf("ChunkSize = %d, want %d", o.ChunkSize, 8<<20)
	}
	if o.MemoryLimit != 2<<30 {
		t.Errorf("MemoryLimit = %d, want %d", o.MemoryLimit, 2<<30)
	}

	d := mustParse(t, "-cf", "a", "p")
	if d.ChunkSize != 4<<20 {
		t.Errorf("default ChunkSize = %d, want %d", d.ChunkSize, 4<<20)
	}
	if d.SpillThreshold != 32<<20 {
		t.Errorf("default SpillThreshold = %d, want %d", d.SpillThreshold, 32<<20)
	}
	if d.UpdateMode != archive.UpdateNewer {
		t.Errorf("default UpdateMode = %q, want %q", d.UpdateMode, archive.UpdateNewer)
	}
	if d.Workers < 1 {
		t.Errorf("default Workers = %d, want at least 1", d.Workers)
	}
}

// TestParseUsageErrors is the exit-code-2 surface. Every case here is a
// mistake a user can make, and each must be refused with an explanation
// rather than acted on.
func TestParseUsageErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		argv []string
	}{
		{"no operation", []string{"-f", "a"}},
		// Parse itself still refuses an empty command line; Run intercepts it
		// earlier and prints the help. See TestRunWithNoArgumentsPrintsHelp.
		{"no operation, no args", []string{}},
		{"two operations", []string{"-c", "-x", "-f", "a", "p"}},
		{"three operations", []string{"-c", "-x", "-t", "-f", "a", "p"}},
		{"list without -f", []string{"-t"}},
		{"create without -f", []string{"-c", "p"}},
		{"create without paths", []string{"-cf", "a"}},
		{"append without paths", []string{"-rf", "a"}},
		{"delete without patterns", []string{"--delete", "-f", "a"}},
		{"compact with arguments", []string{"--compact", "-f", "a", "extra"}},
		{"info with arguments", []string{"--info", "-f", "a", "extra"}},
		{"archive is a pipe", []string{"-cf", "-", "p"}},
		{"unknown long option", []string{"-cf", "a", "--nonesuch", "p"}},
		{"unknown short option", []string{"-cQf", "a", "p"}},
		{"missing flag value", []string{"-cf"}},
		{"zero workers", []string{"-cf", "a", "-j", "0", "p"}},
		{"negative workers", []string{"-cf", "a", "-j", "-4", "p"}},
		{"bad size", []string{"-cf", "a", "--chunk-size", "lots", "p"}},
		{"zero chunk size", []string{"-cf", "a", "--chunk-size", "0", "p"}},
		{"bad compress spec", []string{"-cf", "a", "--compress", "zstd:level", "p"}},
		{"conflicting codecs", []string{"-cf", "a", "-z", "-J", "p"}},
		{"shorthand conflicts with --compress", []string{"-cf", "a", "-z", "--compress", "xz", "p"}},
		{"conflicting overwrite policies", []string{"-xf", "a", "-k", "--overwrite"}},
		{"quiet and verbose", []string{"-tvqf", "a"}},
		{"two passphrase sources", []string{"-cef", "a", "--passphrase-file", "f", "--passphrase-env", "V", "p"}},
		{"encrypt-index without encrypt", []string{"-cf", "a", "--encrypt-index", "p"}},
		{"update-mode without -u", []string{"-tf", "a", "--update-mode", "digest"}},
		{"bad update-mode", []string{"-uf", "a", "--update-mode", "sometimes", "p"}},
		{"recompress without compact", []string{"-cf", "a", "--recompress", "zstd", "p"}},
		{"bad recompress spec", []string{"--compact", "-f", "a", "--recompress", "zstd:"}},
		{"config and no-config", []string{"-tf", "a", "--config", "c", "--no-config"}},
		{"change-passphrase with arguments", []string{"--change-passphrase", "-f", "a", "extra"}},
		{"two new passphrase sources", []string{"--change-passphrase", "-f", "a",
			"--new-passphrase-file", "f", "--new-passphrase-env", "V"}},
		{"new passphrase without change-passphrase", []string{"-tf", "a", "--new-passphrase-file", "f"}},
		{"new passphrase env on create", []string{"-cef", "a", "--new-passphrase-env", "V", "p"}},
		{"encrypt on change-passphrase", []string{"--change-passphrase", "-f", "a", "-e"}},
		{"encrypt-index on change-passphrase", []string{"--change-passphrase", "-f", "a", "--encrypt-index"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o, err := Parse(tc.argv)
			if err == nil {
				t.Fatalf("Parse(%q) succeeded, got %+v", tc.argv, o)
			}
			var ue *UsageError
			if !errors.As(err, &ue) {
				t.Errorf("error is %T (%v), want *UsageError", err, err)
			}
		})
	}
}

func TestParseAcceptsValidUpdateModes(t *testing.T) {
	for _, mode := range updateModes {
		o := mustParse(t, "-uf", "a", "--update-mode", mode, "p")
		if o.UpdateMode != mode {
			t.Errorf("UpdateMode = %q, want %q", o.UpdateMode, mode)
		}
	}
}

func TestOperationProperties(t *testing.T) {
	if OpListCodecs.NeedsArchive() {
		t.Error("--list-codecs must not require an archive")
	}
	for _, op := range []Operation{OpCreate, OpList, OpExtract, OpVerify, OpInfo} {
		if !op.NeedsArchive() {
			t.Errorf("%v should require an archive", op)
		}
	}
	for _, op := range []Operation{OpCreate, OpAppend, OpUpdate, OpDelete, OpCompact, OpRepair} {
		if !op.WritesArchive() {
			t.Errorf("%v should be a writing operation", op)
		}
	}
	for _, op := range []Operation{OpList, OpExtract, OpVerify, OpInfo, OpListCodecs} {
		if op.WritesArchive() {
			t.Errorf("%v should not be a writing operation", op)
		}
	}
}

// TestRunExitCodes checks the mapping in doc/design.md 10.7 end to end, through
// the same entry point the binary uses.
func TestRunExitCodes(t *testing.T) {
	for _, tc := range []struct {
		name string
		argv []string
		want int
	}{
		{"version", []string{"--version"}, ExitOK},
		{"help", []string{"--help"}, ExitOK},
		{"usage error", []string{"-c"}, ExitUsage},
		{"quick without verify", []string{"-tf", "a", "--quick"}, ExitUsage},
		{"on-conflict without -r", []string{"-uf", "a", "--on-conflict", "skip", "p"}, ExitUsage},
		{"bad on-conflict", []string{"-rf", "a", "--on-conflict", "never", "p"}, ExitUsage},
		{"exclude on delete", []string{"--delete", "-f", "a", "--exclude", "x", "p"}, ExitUsage},
		{"missing input path", []string{"-cf", "a", "nonesuch"}, ExitIO},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := Run(tc.argv, &stdout, &stderr); got != tc.want {
				t.Errorf("Run(%q) = %d, want %d (stderr: %s)", tc.argv, got, tc.want, stderr.String())
			}
		})
	}
}

// TestRunWithNoArgumentsPrintsHelp: a bare invocation is a question, not a
// mistake, so it gets the same output as --help.
func TestRunWithNoArgumentsPrintsHelp(t *testing.T) {
	var bare, bareErr bytes.Buffer
	code := Run(nil, &bare, &bareErr)

	if code != ExitOK {
		t.Errorf("Run() = %d, want %d", code, ExitOK)
	}
	if bareErr.Len() != 0 {
		t.Errorf("stderr = %q, want it empty", bareErr.String())
	}

	var help, helpErr bytes.Buffer
	Run([]string{"--help"}, &help, &helpErr)
	if bare.String() != help.String() {
		t.Errorf("a bare run printed something other than --help:\n%s", bare.String())
	}
	if !strings.Contains(bare.String(), "--create") {
		t.Errorf("the help is missing its operations:\n%s", bare.String())
	}
}

// TestRunWithArgumentsButNoOperationStillErrors: once the user has typed
// something, a mistake is worth reporting as one.
func TestRunWithArgumentsButNoOperationStillErrors(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"-f", "a.eictar"}, &stdout, &stderr); code != ExitUsage {
		t.Errorf("Run = %d, want %d", code, ExitUsage)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want the error on stderr alone", stdout.String())
	}
}

func TestRunVersionAndHelpGoToStdout(t *testing.T) {
	for _, argv := range [][]string{{"--version"}, {"--help"}} {
		var stdout, stderr bytes.Buffer
		Run(argv, &stdout, &stderr)
		if stdout.Len() == 0 {
			t.Errorf("Run(%q) wrote nothing to stdout", argv)
		}
		if stderr.Len() != 0 {
			t.Errorf("Run(%q) wrote to stderr: %q", argv, stderr.String())
		}
	}
}

// TestRunUsageErrorsGoToStderr keeps the streams straight: a script doing
// `eictar -tf a > list` must not find an error message in its output file.
func TestRunUsageErrorsGoToStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer
	Run([]string{"-f", "a"}, &stdout, &stderr) // an archive but no operation
	if stdout.Len() != 0 {
		t.Errorf("usage error wrote %q to stdout", stdout.String())
	}
	if !strings.Contains(stderr.String(), "no operation selected") {
		t.Errorf("stderr = %q, want it to explain the problem", stderr.String())
	}
}

// TestHelpMentionsEveryOperation stops the usage text from drifting away from
// the operations the parser actually accepts.
func TestHelpMentionsEveryOperation(t *testing.T) {
	var stdout, stderr bytes.Buffer
	Run([]string{"--help"}, &stdout, &stderr)
	help := stdout.String()

	for op, name := range operationNames {
		if op == OpNone {
			continue
		}
		if !strings.Contains(help, name) {
			t.Errorf("--help does not mention %s", name)
		}
	}
}

// TestParseDestination covers -d, the zip-style "unpack here" option.
func TestParseDestination(t *testing.T) {
	for _, argv := range [][]string{
		{"-xf", "a", "-d", "out"},
		{"-xd", "out", "-f", "a"}, // only the last letter of a bundle takes a value
		{"-xf", "a", "-dout"},
		{"-xf", "a", "--destination", "out"},
		{"-xf", "a", "--destination=out"},
	} {
		t.Run(strings.Join(argv, " "), func(t *testing.T) {
			o := mustParse(t, argv...)
			if o.Op != OpExtract {
				t.Errorf("Op = %v, want %v", o.Op, OpExtract)
			}
			if o.Destination != "out" {
				t.Errorf("Destination = %q, want %q", o.Destination, "out")
			}
			if o.Archive != "a" {
				t.Errorf("Archive = %q, want %q", o.Archive, "a")
			}
		})
	}
}

func TestParseDestinationErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		argv []string
	}{
		{"with create", []string{"-cf", "a", "-d", "out", "p"}},
		{"with list", []string{"-tf", "a", "-d", "out"}},
		{"with append", []string{"-rf", "a", "-d", "out", "p"}},
		{"together with -C", []string{"-xf", "a", "-d", "out", "-C", "elsewhere"}},
		{"with --to-stdout", []string{"-xOf", "a", "-d", "out"}},
		{"missing value", []string{"-xf", "a", "-d"}},
		// -d is value-taking, so in a bundle it swallows the rest: here it
		// takes "f" as its value and leaves -f unset.
		{"bundled before -f", []string{"-xdf", "out", "a"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if o, err := Parse(tc.argv); err == nil {
				t.Fatalf("Parse(%q) succeeded, got %+v", tc.argv, o)
			}
		})
	}
}

// TestExtractStillAcceptsChdir keeps -C working for extraction, since that is
// what a tar user types.
func TestExtractStillAcceptsChdir(t *testing.T) {
	o := mustParse(t, "-xf", "a", "-C", "out")
	if len(o.Chdir) != 1 || o.Chdir[0] != "out" {
		t.Errorf("Chdir = %q, want [out]", o.Chdir)
	}
	if o.Destination != "" {
		t.Errorf("Destination = %q, want empty", o.Destination)
	}
}

// TestUnbuiltOptionsAreRefused is the guard against quiet wrongness: an option
// this build ignores must stop the run, not pass silently. --exclude is the
// case that matters most - a user who excludes a secret and is not told the
// option did nothing ends up shipping it.
func TestUnbuiltOptionsAreRefused(t *testing.T) {
	markUnbuilt(t, "json", "M99")
	var stdout, stderr bytes.Buffer
	argv := []string{"-tf", "a", "--json"}
	if code := Run(argv, &stdout, &stderr); code != ExitInternal {
		t.Errorf("Run(%q) = %d, want %d", argv, code, ExitInternal)
	}
	if !strings.Contains(stderr.String(), "not implemented") || !strings.Contains(stderr.String(), "M99") {
		t.Errorf("stderr = %q, want it to say the option is not implemented, and when", stderr.String())
	}
}

// markUnbuilt makes an option unbuilt for one test. Every option is built
// since M7, but the gate must keep working for the next one that is not.
func markUnbuilt(t *testing.T, name, milestone string) {
	t.Helper()
	unbuiltOptions[name] = milestone
	t.Cleanup(func() { delete(unbuiltOptions, name) })
}

// TestUnbuiltOptionsDoNotFireOnDefaults checks the gate keys off what the user
// typed, not off the value: --workers has a non-zero default, and an ordinary
// run must not trip over it.
func TestUnbuiltOptionsDoNotFireOnDefaults(t *testing.T) {
	o := mustParse(t, "-tf", "a")
	if err := o.Unbuilt(); err != nil {
		t.Errorf("a plain listing was refused: %v", err)
	}
}

// TestUsageErrorsOutrankUnbuilt: fix what you typed before being told a
// feature is missing.
func TestUsageErrorsOutrankUnbuilt(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"-c", "--exclude", "x"}, &stdout, &stderr); code != ExitUsage {
		t.Errorf("Run = %d, want %d (a usage error should be reported first)", code, ExitUsage)
	}
}

// TestParseStillAcceptsUnbuiltOptions keeps the parser testable across the
// whole option surface: Parse validates, Unbuilt decides what can run.
func TestParseStillAcceptsUnbuiltOptions(t *testing.T) {
	markUnbuilt(t, "recompress", "M99")
	o := mustParse(t, "--compact", "-f", "a", "--recompress", "zstd")
	if o.Recompress != "zstd" {
		t.Errorf("parsing dropped the value: Recompress=%q", o.Recompress)
	}
	if err := o.Unbuilt(); err == nil {
		t.Error("Unbuilt accepted options this build ignores")
	}
}

// TestEncryptionOptionsAreBuilt: the encryption options became real in M4.
func TestEncryptionOptionsAreBuilt(t *testing.T) {
	o := mustParse(t, "-cf", "a", "-e", "--encrypt-index",
		"--passphrase-file", "p.txt", "--kdf-memory", "65536", "p")
	if err := o.Unbuilt(); err != nil {
		t.Errorf("an encryption option was refused: %v", err)
	}
	if !o.Encrypt || !o.EncryptIdx || o.PassphraseFile != "p.txt" || o.KDFMemory != 65536 {
		t.Errorf("options did not parse: %+v", o)
	}
}

// TestConcurrencyOptionsAreBuilt: -j, --memory-limit and --spill-threshold
// became real in M3, so they must no longer be refused.
func TestConcurrencyOptionsAreBuilt(t *testing.T) {
	o := mustParse(t, "-cf", "a", "-j", "8", "--memory-limit", "2GiB",
		"--spill-threshold", "64MiB", "p")
	if err := o.Unbuilt(); err != nil {
		t.Errorf("a concurrency option was refused: %v", err)
	}
	if o.Workers != 8 {
		t.Errorf("Workers = %d, want 8", o.Workers)
	}
	if o.MemoryLimit != 2<<30 {
		t.Errorf("MemoryLimit = %d, want %d", o.MemoryLimit, 2<<30)
	}
	if o.SpillThreshold != 64<<20 {
		t.Errorf("SpillThreshold = %d, want %d", o.SpillThreshold, 64<<20)
	}
}

// TestTuningBounds: a mistyped size or worker count must be refused, not
// attempted. --chunk-size feeds an allocation on both sides of the archive.
func TestTuningBounds(t *testing.T) {
	for _, tc := range []struct {
		name string
		argv []string
		ok   bool
	}{
		{"chunk at the minimum", []string{"-cf", "a", "--chunk-size", "512", "p"}, true},
		{"chunk below the minimum", []string{"-cf", "a", "--chunk-size", "1", "p"}, false},
		{"chunk at the maximum", []string{"-cf", "a", "--chunk-size", "256MiB", "p"}, true},
		{"chunk above the maximum", []string{"-cf", "a", "--chunk-size", "257MiB", "p"}, false},
		{"chunk absurd", []string{"-cf", "a", "--chunk-size", "1TiB", "p"}, false},
		{"workers at the maximum", []string{"-cf", "a", "-j", "1024", "p"}, true},
		{"workers above the maximum", []string{"-cf", "a", "-j", "1025", "p"}, false},
		{"workers absurd", []string{"-cf", "a", "-j", "100000000", "p"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.argv)
			if tc.ok && err != nil {
				t.Errorf("Parse(%q) = %v, want it accepted", tc.argv, err)
			}
			if !tc.ok && err == nil {
				t.Errorf("Parse(%q) was accepted, want a usage error", tc.argv)
			}
		})
	}
}

// TestChdirOnExtractMustExist: -C means "work in this directory", and unlike
// -d it does not create one (doc/design.md 7.1).
func TestChdirOnExtractMustExist(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-xf", "nonexistent.eictar", "-C", "/nonexistent-directory-xyz"},
		&stdout, &stderr)

	if code == ExitOK {
		t.Error("extraction into a missing -C directory succeeded")
	}
	if !strings.Contains(stderr.String(), "-C") {
		t.Errorf("stderr = %q, want it to name the option", stderr.String())
	}
}

// TestEncryptionOptionsOnlyOnCreate: an existing archive's encryption is fixed
// by its header, so these options elsewhere would be silently ignored.
func TestEncryptionOptionsOnlyOnCreate(t *testing.T) {
	for _, argv := range [][]string{
		{"-tf", "a", "-e"},
		{"-xf", "a", "--encrypt-index"},
		{"-tf", "a", "--kdf-time", "5"},
		{"-xf", "a", "--kdf-memory", "65536"},
		{"-tf", "a", "--kdf-threads", "2"},
	} {
		t.Run(strings.Join(argv, " "), func(t *testing.T) {
			if _, err := Parse(argv); err == nil {
				t.Error("accepted an encryption option outside -c")
			}
		})
	}
	// Supplying a passphrase is fine anywhere: reading needs one.
	mustParse(t, "-tf", "a", "--passphrase-file", "p")
}

// TestChangePassphraseOptions: a change of passphrase takes the --kdf-*
// options, and remembers which ones were typed, because only those change
// the archive's key derivation (doc/design.md 9.7).
func TestChangePassphraseOptions(t *testing.T) {
	o := mustParse(t, "--change-passphrase", "-f", "a", "--passphrase-file", "old",
		"--new-passphrase-file", "new", "--kdf-memory", "65536")
	if o.Op != OpChangePassphrase || o.NewPassphraseFile != "new" || !o.Op.WritesArchive() {
		t.Errorf("parsed %v, new passphrase file %q", o.Op, o.NewPassphraseFile)
	}
	if !o.explicit["kdf-memory"] || o.explicit["kdf-time"] || o.explicit["kdf-threads"] {
		t.Errorf("explicit = %v, want only kdf-memory", o.explicit)
	}
	mustParse(t, "--change-passphrase", "-f", "a", "--new-passphrase-env", "V")
}

func TestKDFBounds(t *testing.T) {
	for _, tc := range []struct {
		argv []string
		ok   bool
	}{
		{[]string{"-cf", "a", "-e", "--kdf-time", "64", "p"}, true},
		{[]string{"-cf", "a", "-e", "--kdf-time", "65", "p"}, false},
		{[]string{"-cf", "a", "-e", "--kdf-time", "0", "p"}, false},
		{[]string{"-cf", "a", "-e", "--kdf-memory", "4194304", "p"}, true},
		{[]string{"-cf", "a", "-e", "--kdf-memory", "4194305", "p"}, false},
	} {
		t.Run(strings.Join(tc.argv, " "), func(t *testing.T) {
			_, err := Parse(tc.argv)
			if tc.ok != (err == nil) {
				t.Errorf("Parse = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

// TestPassphraseSourceMeansEncryptionExpected: a user who hands over a
// passphrase expects a sealed archive, which is how a stripped one is caught.
func TestPassphraseSourceMeansEncryptionExpected(t *testing.T) {
	if mustParse(t, "-tf", "a").expectsEncryption() {
		t.Error("a plain listing expected encryption")
	}
	if !mustParse(t, "-tf", "a", "--passphrase-file", "p").expectsEncryption() {
		t.Error("--passphrase-file did not signal an expectation of encryption")
	}
	if !mustParse(t, "-xf", "a", "--passphrase-env", "V").expectsEncryption() {
		t.Error("--passphrase-env did not signal an expectation of encryption")
	}
}

// TestCompressionErrorsAreUsageErrors: a bad spec is a command-line mistake
// (exit 2), and -z/-J select codecs that are not built yet (exit 70). Neither
// is an I/O failure.
func TestCompressionErrorsAreUsageErrors(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		argv []string
		want int
	}{
		{[]string{"-cf", dir + "/a.eictar", "--compress", "nonesuch", dir}, ExitUsage},
		{[]string{"-cf", dir + "/a.eictar", "--compress", "zstd:level=99", dir}, ExitUsage},
		{[]string{"-cf", dir + "/a.eictar", "--compress", "zstd:levle=3", dir}, ExitUsage},
		{[]string{"-cf", dir + "/a.eictar", "--compress", "xz:preset=10", dir}, ExitUsage},
		{[]string{"-cf", dir + "/a.eictar", "--compress", "s2:mode=fastest", dir}, ExitUsage},
		// -z and -J select codecs that exist since M7.
		{[]string{"-czf", dir + "/a.eictar", dir}, ExitOK},
		{[]string{"-cJf", dir + "/a.eictar", dir}, ExitOK},
	} {
		t.Run(strings.Join(tc.argv[:len(tc.argv)-1], " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := Run(tc.argv, &stdout, &stderr); got != tc.want {
				t.Errorf("Run(%q) = %d, want %d (stderr: %s)", tc.argv, got, tc.want, stderr.String())
			}
		})
	}
}

// TestMetadataOptionsAreBuilt: the M5 options are no longer refused.
func TestMetadataOptionsAreBuilt(t *testing.T) {
	for _, argv := range [][]string{
		{"-cf", "a", "--exclude", "*.log", "-X", "list", "--one-file-system", "p"},
		{"-cf", "a", "--no-owner", "--no-xattrs", "--no-acls", "p"},
		{"-xf", "a", "-p", "--no-xattrs"},
		{"-tf", "a", "--exclude", "*.log"},
	} {
		if err := mustParse(t, argv...).Unbuilt(); err != nil {
			t.Errorf("%q: %v", argv, err)
		}
	}
}

// TestMutationOptionsAreBuilt: the M6 operations and options run, and the
// metadata and exclude options reach -r and -u, which walk the filesystem as
// -c does.
func TestMutationOptionsAreBuilt(t *testing.T) {
	for _, argv := range [][]string{
		{"-rf", "a", "--on-conflict", "skip", "p"},
		{"-uf", "a", "--update-mode", "digest", "p"},
		{"-rf", "a", "--exclude", "*.log", "--no-owner", "--one-file-system", "p"},
		{"-uf", "a", "--no-xattrs", "--no-acls", "p"},
		{"--verify", "-f", "a", "--quick"},
		{"--delete", "-f", "a", "p"},
		{"--compact", "-f", "a"},
		{"--repair", "-f", "a"},
		{"--info", "-f", "a"},
	} {
		if err := mustParse(t, argv...).Unbuilt(); err != nil {
			t.Errorf("%q: %v", argv, err)
		}
	}
}

// TestMetadataOptionScope: each option means something on some operations
// only, and elsewhere it would be ignored in silence.
func TestMetadataOptionScope(t *testing.T) {
	for _, argv := range [][]string{
		{"-xf", "a", "--one-file-system"},
		{"-cf", "a", "-p", "p"},
		{"-tf", "a", "-p"},
		{"-cf", "a", "--preserve-devices", "p"},
		{"-tf", "a", "--no-owner"},
	} {
		t.Run(strings.Join(argv, " "), func(t *testing.T) {
			if _, err := Parse(argv); err == nil {
				t.Error("accepted an option on an operation it does not apply to")
			}
		})
	}
}

// TestRootOnlyOptions: chown and mknod need root, so the options that ask for
// them are refused up front for anyone else - once, not member by member.
func TestRootOnlyOptions(t *testing.T) {
	saved := isRoot
	defer func() { isRoot = saved }()

	isRoot = func() bool { return false }
	for _, opt := range []string{"--preserve-owner", "--preserve-devices"} {
		_, err := Parse([]string{"-xf", "a", opt})
		if err == nil || !strings.Contains(err.Error(), "needs root") {
			t.Errorf("%s as a user: error = %v, want 'needs root'", opt, err)
		}
	}

	isRoot = func() bool { return true }
	for _, opt := range []string{"--preserve-owner", "--preserve-devices"} {
		if _, err := Parse([]string{"-xf", "a", opt}); err != nil {
			t.Errorf("%s as root: %v", opt, err)
		}
	}
}

func TestModeString(t *testing.T) {
	for _, tc := range []struct {
		typ  format.MemberType
		mode uint32
		want string
	}{
		{format.TypeReg, 0o644, "-rw-r--r--"},
		{format.TypeDir, 0o755, "drwxr-xr-x"},
		{format.TypeReg, 0o4755, "-rwsr-xr-x"},
		{format.TypeReg, 0o4644, "-rwSr--r--"},
		{format.TypeReg, 0o2755, "-rwxr-sr-x"},
		{format.TypeDir, 0o1777, "drwxrwxrwt"},
		{format.TypeDir, 0o1776, "drwxrwxrwT"},
		{format.TypeFIFO, 0o600, "prw-------"},
		{format.TypeCharDev, 0o666, "crw-rw-rw-"},
		{format.TypeHardlink, 0o644, "hrw-r--r--"},
	} {
		m := format.Member{Type: tc.typ, Mode: tc.mode}
		if got := modeString(&m); got != tc.want {
			t.Errorf("modeString(%s %#o) = %q, want %q", tc.typ, tc.mode, got, tc.want)
		}
	}
}
