package cli

import (
	"bytes"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The parsers of what a person types (doc/design.md 13.5, step 4).

// FuzzCompressSpec parses a compression spec. A spec that parses has a name,
// and keys and values that are not empty, and its String parses back to the
// same spec.
func FuzzCompressSpec(f *testing.F) {
	for _, s := range []string{"zstd", "zstd:level=19,long=27", "zstd:level=19,long,train", "none", "x:k=v,j"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		spec, err := ParseCompressSpec(s)
		if err != nil {
			return
		}
		if spec.Name == "" {
			t.Fatalf("%q: no name", s)
		}
		for k, v := range spec.Params {
			if k == "" || v == "" {
				t.Fatalf("%q: an empty key or value: %q=%q", s, k, v)
			}
		}
		again, err := ParseCompressSpec(spec.String())
		if err != nil || again.Name != spec.Name || !maps.Equal(again.Params, spec.Params) {
			t.Fatalf("%q gives %q, which parses to %+v, %v", s, spec.String(), again, err)
		}
	})
}

// FuzzConfigFile reads a configuration file. Any content gives a usage
// error, or an error of the read for a line that is too long, or settings
// that --show-config shows. Nothing panics.
func FuzzConfigFile(f *testing.F) {
	for _, s := range []string{
		"workers = 3\n",
		"# a comment\nexclude = build#1 # a trailing comment\n",
		"[codec.zstd]\nlevel = 19\n",
		"compress = xz\n[codec.xz]\npreset = 2\n",
		"keep-going = true\nchunk-size = 8MiB\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, content []byte) {
		if len(content) > 4096 {
			return
		}
		path := filepath.Join(t.TempDir(), "config")
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		code := Run([]string{"--show-config", "--config", path}, &stdout, &stderr)
		switch {
		case code == ExitOK:
			if !strings.Contains(stdout.String(), "# configuration file: "+path) {
				t.Fatalf("exit 0 with no settings shown:\n%s", stdout.String())
			}
		case code == ExitUsage:
		case strings.Contains(stderr.String(), "reading "+path):
		default:
			t.Fatalf("exit %d: %s", code, stderr.String())
		}
		_, err := Parse([]string{"--config", path, "-cf", "a", "p"})
		var usage *UsageError
		if err != nil && !errors.As(err, &usage) && !strings.Contains(err.Error(), "reading "+path) {
			t.Fatalf("Parse: %v", err)
		}
	})
}
