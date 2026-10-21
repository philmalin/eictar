package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/philmalin/eictar/src/internal/archive"
	"github.com/philmalin/eictar/src/internal/codec"
	"github.com/spf13/pflag"
)

var completionScript = filepath.Join("..", "..", "..", "completions", "eictar.bash")

// completionList returns the words of the list that the bash completion
// script assigns to the variable name.
func completionList(t *testing.T, script, name string) []string {
	t.Helper()
	m := regexp.MustCompile(`(?m)^` + name + `='([^']*)'`).FindStringSubmatch(script)
	if m == nil {
		t.Fatalf("%s does not set %s", completionScript, name)
	}
	return strings.Fields(m[1])
}

// TestBashCompletionNamesEveryOption keeps completions/eictar.bash in step
// with the parser, as TestManPageNamesEveryOption keeps the man page: the
// script lists each option and each fixed set of values, and nothing else.
func TestBashCompletionNamesEveryOption(t *testing.T) {
	b, err := os.ReadFile(completionScript)
	if err != nil {
		t.Fatal(err)
	}
	script := string(b)
	var long, short []string
	o := Defaults()
	fs, _ := o.flagSet("eictar")
	fs.VisitAll(func(f *pflag.Flag) {
		long = append(long, "--"+f.Name)
		if f.Shorthand != "" {
			short = append(short, "-"+f.Shorthand)
		}
	})
	for _, c := range []struct {
		name string
		want []string
	}{
		{"_eictar_long", long},
		{"_eictar_short", short},
		{"_eictar_codecs", codec.Names()},
		{"_eictar_update_modes", []string{archive.UpdateNewer, archive.UpdateDifferent, archive.UpdateDigest}},
		{"_eictar_conflicts", []string{archive.ConflictReplace, archive.ConflictSkip, archive.ConflictError}},
	} {
		got := completionList(t, script, c.name)
		slices.Sort(got)
		want := slices.Sorted(slices.Values(c.want))
		if !slices.Equal(got, want) {
			t.Errorf("%s in %s:\n got %q\nwant %q", c.name, completionScript, got, want)
		}
	}
}

// TestBashCompletion runs the completion function of completions/eictar.bash
// in bash. After an option that takes a value, it must offer values and not
// options. After any other option, it must offer options again.
func TestBashCompletion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the bash completion is for Unix shells")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash on this system")
	}
	script, err := filepath.Abs(completionScript)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, name := range []string{"a.ect", "b.txt", "my file.ect"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}

	type tc struct {
		words []string // the command line; the last word is the one to complete
		want  string   // COMPREPLY, joined with commas, in any order
	}
	cases := []tc{
		{[]string{"eictar", "--upd"}, "--update,--update-mode"},
		{[]string{"eictar", "-cv", "--no-c"}, "--no-config"},
		{[]string{"eictar", ""}, "a.ect,b.txt,my file.ect,sub"},
		{[]string{"eictar", "-f", ""}, "sub,a.ect,my file.ect"},
		{[]string{"eictar", "-cf", ""}, "sub,a.ect,my file.ect"},
		{[]string{"eictar", "--file", "=", ""}, "sub,a.ect,my file.ect"},
		{[]string{"eictar", "--file", "=", "m"}, "my file.ect"},
		{[]string{"eictar", "-C", ""}, "sub"},
		{[]string{"eictar", "--destination", ""}, "sub"},
		{[]string{"eictar", "-T", "b"}, "b.txt"},
		{[]string{"eictar", "--passphrase-env", "EICTAR_COMPLETION_T"}, "EICTAR_COMPLETION_TEST"},
		{[]string{"eictar", "-Z", ""}, strings.Join(codec.Names(), ",")},
		{[]string{"eictar", "--recompress", "z"}, "zstd"},
		{[]string{"eictar", "--update-mode", ""}, "newer,different,digest"},
		{[]string{"eictar", "--on-conflict", "s"}, "skip"},
		{[]string{"eictar", "-j", ""}, ""},
	}
	// Each option, long and short: "--cr" after it is a value when the option
	// takes one, and the start of --create when it does not.
	o := Defaults()
	fs, _ := o.flagSet("eictar")
	fs.VisitAll(func(f *pflag.Flag) {
		want := ""
		if f.NoOptDefVal != "" { // a bool or a count takes no value
			want = "--create"
		}
		cases = append(cases, tc{[]string{"eictar", "--" + f.Name, "--cr"}, want})
		if f.Shorthand != "" {
			cases = append(cases, tc{[]string{"eictar", "-" + f.Shorthand, "--cr"}, want})
		}
	})

	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
	var driver strings.Builder
	driver.WriteString(`source "$1"
comp() { COMP_WORDS=("$@"); COMP_CWORD=$(($# - 1)); _eictar; local IFS=,; echo "${COMPREPLY[*]}"; }
`)
	for _, c := range cases {
		driver.WriteString("comp")
		for _, w := range c.words {
			driver.WriteString(" " + quote(w))
		}
		driver.WriteString("\n")
	}
	cmd := exec.Command(bash, "--norc", "--noprofile", "-c", driver.String(), "driver", script)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "LC_ALL=C", "EICTAR_COMPLETION_TEST=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bash: %v\n%s", err, out)
	}
	got := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	if len(got) != len(cases) {
		t.Fatalf("bash wrote %d lines for %d cases:\n%s", len(got), len(cases), out)
	}
	// Compare as sets: compgen gives file names in the order of the
	// directory, which changes with the file system, and bash sorts the
	// list before it shows it.
	set := func(s string) string {
		l := strings.Split(s, ",")
		slices.Sort(l)
		return strings.Join(l, ",")
	}
	for i, c := range cases {
		if set(got[i]) != set(c.want) {
			t.Errorf("completion of %q: got %q, want %q", c.words, got[i], c.want)
		}
	}
}
