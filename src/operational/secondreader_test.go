//go:build operational

package operational

import (
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/philmalin/eictar/src/internal/testutil"
	"github.com/philmalin/eictar/tools/ectread/compare"
	"github.com/philmalin/eictar/tools/ectread/ect"
)

// The second reader (doc/design.md 13.5, step 2) reads the archives that
// eictar writes, from doc/format.md alone. eictar and the reader must give
// the same members, with the same fields, and the same bytes.

// agree compares eictar and the second reader on one archive: the listing
// of eictar -t --json, a tree that eictar extracts, and a tree that the
// reader extracts.
func agree(t *testing.T, archive, pass string) {
	t.Helper()
	var key, open []string
	var opt ect.Options
	if pass != "" {
		key = []string{"--passphrase-file", pass}
		b, err := os.ReadFile(pass)
		if err != nil {
			t.Fatal(err)
		}
		line, _, _ := strings.Cut(string(b), "\n")
		opt.Passphrase = []byte(line)
	}
	open = append([]string{"-tf", archive, "--json"}, key...)
	list := testutil.Run(t, t.TempDir(), open...)
	if list.ExitCode != exitOK {
		t.Fatalf("list: exit %d (stderr: %s)", list.ExitCode, list.Stderr)
	}
	out := filepath.Join(t.TempDir(), "eictar")
	x := testutil.Run(t, t.TempDir(), append([]string{"-xf", archive, "-d", out}, key...)...)
	if x.ExitCode != exitOK {
		t.Fatalf("extract: exit %d (stderr: %s)", x.ExitCode, x.Stderr)
	}
	a, err := ect.Open(archive, opt)
	if err != nil {
		t.Fatalf("the second reader: %v", err)
	}
	defer a.Close()
	if err := compare.Listing(a, []byte(list.Stdout)); err != nil {
		t.Error(err)
	}
	if err := compare.Tree(a, out); err != nil {
		t.Error(err)
	}
	mine := filepath.Join(t.TempDir(), "ectread")
	if err := ect.Extract(a, mine, io.Discard); err != nil {
		t.Errorf("the second reader extracts: %v", err)
	} else if err := compare.Tree(a, mine, "fifo"); err != nil {
		t.Errorf("the extraction of the second reader: %v", err)
	}
}

// covers checks that an archive of TestSecondReaderCodecs has what the
// comparison is for: three generations, shared content, a hardlink whose
// target is a tombstone, a sparse file where the system makes one, and a
// dictionary when dict is true.
func covers(t *testing.T, archive, pass string, dict bool) {
	t.Helper()
	var opt ect.Options
	if pass != "" {
		opt.Passphrase = []byte("second reader")
	}
	a, err := ect.Open(archive, opt)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	has := map[string]bool{"dictionary": len(a.Dicts) > 0}
	for _, m := range a.Live() {
		has["shared content"] = has["shared content"] || m.Data != 0
		has["a sparse file"] = has["a sparse file"] || m.IsSparse
		has["a pipe"] = has["a pipe"] || m.Type == "fifo"
		if m.Type == "hardlink" {
			has["a hardlink to a tombstone"] = has["a hardlink to a tombstone"] || a.ByID(m.Hardlink).Dead
		}
	}
	want := []string{"shared content", "a hardlink to a tombstone"}
	if runtime.GOOS == "linux" {
		want = append(want, "a sparse file", "a pipe")
	}
	if dict {
		want = append(want, "dictionary")
	}
	for _, w := range want {
		if !has[w] {
			t.Errorf("the archive has no %s", w)
		}
	}
	if a.Generation != 3 {
		t.Errorf("generation %d, want 3", a.Generation)
	}
}

func TestSecondReaderGoldens(t *testing.T) {
	root, err := filepath.Abs("../internal/archive/testdata/golden")
	if err != nil {
		t.Fatal(err)
	}
	pass := passFile(t, "golden")
	for _, g := range []struct{ name, pass string }{
		{"plain.ect", ""}, {"encrypted.ect", pass}, {"dict.ect", pass}, {"shared.ect", ""},
	} {
		t.Run(g.name, func(t *testing.T) { agree(t, filepath.Join(root, g.name), g.pass) })
	}
}

// TestSecondReaderCodecs writes an archive with each codec, plain and
// encrypted, in three generations: a create, an append that replaces a
// file, and a delete of the target of a hardlink. Then eictar and the
// second reader must agree on it.
func TestSecondReaderCodecs(t *testing.T) {
	tree := testutil.NewTree(t)
	rnd := rand.New(rand.NewPCG(1, 2))
	random := make([]byte, 150_000)
	for i := range random {
		random[i] = byte(rnd.Uint32())
	}
	text := strings.Repeat("a line of text that compresses. ", 9000)
	tree.Dir("work", 0o755).
		Dir("work/sub", 0o750).
		Text("work/empty", 0o644, "").
		Text("work/small.txt", 0o600, "small\n").
		Text("work/text.txt", 0o644, text).
		Text("work/copy.txt", 0o644, text).
		File("work/random.bin", 0o644, random)
	for i := range 40 {
		tree.Text(fmt.Sprintf("work/sub/f%02d.go", i), 0o644,
			fmt.Sprintf("package sub\n\n// F%d returns %d.\nfunc F%d() int { return %d }\n", i, i*i, i, i*i))
	}
	work := filepath.Join(tree.Root, "work")
	if err := os.Link(filepath.Join(work, "random.bin"), filepath.Join(work, "hard.bin")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../small.txt", filepath.Join(work, "sub", "link")); err != nil {
		t.Logf("no symbolic link: %v", err)
	}
	specialFiles(t, work)

	pass := passFile(t, "second reader")
	for _, spec := range []string{"none", "zstd", "zstd:level=19,long", "zstd:train", "flate", "gzip", "s2", "xz"} {
		for _, enc := range [][]string{nil, {"-e"}, {"-e", "--encrypt-index"}} {
			name := spec + "/plain"
			var key []string
			if enc != nil {
				name = spec + "/" + strings.Join(enc, "")
				key = []string{"--passphrase-file", pass}
			}
			t.Run(name, func(t *testing.T) {
				dir := t.TempDir()
				archive := filepath.Join(dir, "a.ect")
				run := func(args ...string) {
					t.Helper()
					if res := testutil.Run(t, tree.Root, append(args, key...)...); res.ExitCode != exitOK {
						t.Fatalf("%v: exit %d (stderr: %s)", args, res.ExitCode, res.Stderr)
					}
				}
				args := append([]string{"-cf", archive, "-Z", spec, "--chunk-size", "64KiB",
					"--kdf-memory", "8192", "--kdf-time", "1"}, enc...)
				run(append(args, "work")...)
				if err := os.WriteFile(filepath.Join(work, "small.txt"), []byte("small, and changed\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				defer os.WriteFile(filepath.Join(work, "small.txt"), []byte("small\n"), 0o600)
				run("-rf", archive, "-Z", spec, "work/small.txt")
				run("--delete", "-f", archive, "work/hard.bin")
				var p string
				if enc != nil {
					p = pass
				}
				agree(t, archive, p)
				covers(t, archive, p, spec == "zstd:train")
			})
		}
	}
}
