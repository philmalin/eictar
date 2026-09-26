//go:build operational

package operational

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/philmalin/eictar/src/internal/testutil"
)

// runOK runs the binary and fails the test on a non-zero exit.
func runOK(t *testing.T, dir string, args ...string) testutil.Result {
	t.Helper()
	res := testutil.Run(t, dir, args...)
	if res.ExitCode != exitOK {
		t.Fatalf("eictar %q: exit %d (stderr: %s)", args, res.ExitCode, res.Stderr)
	}
	return res
}

func listing(t *testing.T, dir string, args ...string) []string {
	t.Helper()
	res := runOK(t, dir, append([]string{"-t"}, args...)...)
	return strings.Fields(res.Stdout)
}

// TestMutationLifecycle is the full lifecycle of the problem statement:
// create, list, extract, append, replace, delete, verify, compact, verify.
func TestMutationLifecycle(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		name := map[bool]string{false: "plain", true: "encrypted"}[encrypted]
		t.Run(name, func(t *testing.T) {
			tree := fixture(t)
			archive := filepath.Join(t.TempDir(), "life.ect")
			var key []string
			if encrypted {
				key = []string{"--passphrase-file", passFile(t, "correct horse")}
			}
			with := func(args ...string) []string { return append(args, key...) }

			create := []string{"-cf", archive, "work"}
			if encrypted {
				create = append(create, "-e", "--encrypt-index", "--kdf-memory", "8192", "--kdf-time", "1")
			}
			runOK(t, tree.Root, with(create...)...)
			before := listing(t, tree.Root, with("-f", archive)...)

			// Change one file, add another, and append both.
			tree.Text("work/README.md", 0o644, "rewritten")
			tree.Text("work/NEW.txt", 0o644, "new")
			// A different codec setting from the create: one extraction must read both.
			runOK(t, tree.Root, with("-rf", archive, "--compress", "zstd:level=19", "work/README.md", "work/NEW.txt")...)
			after := listing(t, tree.Root, with("-f", archive)...)
			if len(after) != len(before)+1 {
				t.Fatalf("after append: %d members, want %d:\n%v", len(after), len(before)+1, after)
			}

			runOK(t, tree.Root, with("--delete", "-f", archive, "work/src")...)
			for _, p := range listing(t, tree.Root, with("-f", archive)...) {
				if strings.HasPrefix(p, "work/src") {
					t.Errorf("%s is still listed after --delete", p)
				}
			}

			info := runOK(t, tree.Root, with("--info", "-f", archive)...)
			for _, want := range []string{"generation:", "3", "tombstoned", "dead space:"} {
				if !strings.Contains(info.Stdout, want) {
					t.Errorf("--info does not show %q:\n%s", want, info.Stdout)
				}
			}

			runOK(t, tree.Root, with("--verify", "-f", archive)...)
			size := fileSize(t, archive)
			compact := runOK(t, tree.Root, with("--compact", "-f", archive)...)
			if !strings.Contains(compact.Stdout, "reclaimed") || fileSize(t, archive) >= size {
				t.Errorf("compact did not shrink the archive (%d -> %d): %s", size, fileSize(t, archive), compact.Stdout)
			}
			runOK(t, tree.Root, with("--verify", "-f", archive)...)

			// What comes out is the tree as it is now, without work/src.
			if err := os.RemoveAll(tree.Path("work/src")); err != nil {
				t.Fatal(err)
			}
			dest := t.TempDir()
			runOK(t, tree.Root, with("-xf", archive, "-d", dest)...)
			testutil.CompareTrees(t, tree.Path("work"), filepath.Join(dest, "work"),
				testutil.CompareOptions{Mode: true})
		})
	}
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Size()
}

// TestUnmatchedPatternsAndConflictsExitTwo: a mistake in what was asked for
// is a usage error, and the archive is unchanged.
func TestUnmatchedPatternsAndConflictsExitTwo(t *testing.T) {
	tree := fixture(t)
	archive := filepath.Join(t.TempDir(), "a.ect")
	runOK(t, tree.Root, "-cf", archive, "work")
	before, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}

	for _, args := range [][]string{
		{"-rf", archive, "--on-conflict", "error", "work/README.md"},
		{"--delete", "-f", archive, "work/README.md", "no/such/member"},
		{"-tf", archive, "work/README.md", "no/such/member"},
		{"-xf", archive, "-d", t.TempDir(), "work/README.md", "no/such/member"},
		{"--verify", "-f", archive, "no/such/member"},
	} {
		res := testutil.Run(t, tree.Root, args...)
		if res.ExitCode != exitUsage {
			t.Errorf("%q: exit %d, want %d (stderr: %s)", args, res.ExitCode, exitUsage, res.Stderr)
		}
		after, err := os.ReadFile(archive)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, after) {
			t.Errorf("%q changed the archive", args)
		}
	}
}

func TestUpdateSkipsWhatIsCurrent(t *testing.T) {
	tree := fixture(t)
	archive := filepath.Join(t.TempDir(), "a.ect")
	runOK(t, tree.Root, "-cf", archive, "work")
	size := fileSize(t, archive)

	// A touch changes the time, not the content: digest mode adds nothing.
	later := time.Now().Add(time.Hour)
	tree.SetTimes("work/README.md", later, later)
	res := runOK(t, tree.Root, "-uvf", archive, "--update-mode", "digest", "work")
	if strings.TrimSpace(res.Stdout) != "" || fileSize(t, archive) != size {
		t.Errorf("digest mode re-archived an unchanged file: %q", res.Stdout)
	}

	// The default mode, newer, takes it.
	res = runOK(t, tree.Root, "-uvf", archive, "work")
	if strings.TrimSpace(res.Stdout) != "work/README.md" {
		t.Errorf("-u -v printed %q, want only work/README.md", res.Stdout)
	}
}

func TestVerifyReportsDamage(t *testing.T) {
	tree := fixture(t)
	archive := filepath.Join(t.TempDir(), "a.ect")
	runOK(t, tree.Root, "-cf", archive, "--compress", "none", "work")

	// With no compression the content is on disk as it is; damage one byte
	// of a known file.
	data, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	i := bytes.Index(data, []byte("package main"))
	if i < 0 {
		t.Fatal("stored content not found")
	}
	data[i] ^= 0x20
	if err := os.WriteFile(archive, data, 0o644); err != nil {
		t.Fatal(err)
	}

	res := testutil.Run(t, tree.Root, "--verify", "-f", archive)
	if res.ExitCode != exitCorrupt || !strings.Contains(res.Stderr, "work/src/main.go") {
		t.Errorf("verify: exit %d, stderr %q; want exit %d naming the member", res.ExitCode, res.Stderr, exitCorrupt)
	}
	if quick := testutil.Run(t, tree.Root, "--verify", "--quick", "-f", archive); quick.ExitCode != exitOK {
		t.Errorf("--quick reads no member data, so it passes: exit %d (%s)", quick.ExitCode, quick.Stderr)
	}
}

// TestKilledAppendIsRepaired kills a real append part way through, the way a
// power cut or an OOM kill does. The archive must be refused with a message
// that names --repair, and --repair must give back the old archive exactly
// (doc/design.md 9.1 and 9.5).
func TestKilledAppendIsRepaired(t *testing.T) {
	tree := fixture(t)
	archive := filepath.Join(t.TempDir(), "a.ect")
	runOK(t, tree.Root, "-cf", archive, "work")
	before, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	beforeList := listing(t, tree.Root, "-f", archive)

	// Many members, compressed hard on one worker: a member's blob lands in
	// the file only when the whole member is encoded, so the append grows
	// the file in steps and is still running when it is killed.
	rnd := rand.New(rand.NewSource(1))
	tree.Dir("big", 0o755)
	for i := 0; i < 48; i++ {
		b := make([]byte, 1<<20)
		rnd.Read(b)
		tree.File(filepath.Join("big", strings.Repeat("x", i+1)), 0o644, b)
	}

	cmd := exec.Command(testutil.Binary(t), "-rf", archive, "-j", "1",
		"--compress", "zstd:level=19", "big")
	cmd.Dir = tree.Root
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for fileSize(t, archive) <= int64(len(before)) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cmd.Process.Signal(syscall.SIGKILL)
	cmd.Wait()
	if cmd.ProcessState.Success() {
		t.Skip("the append finished before it could be killed")
	}
	if fileSize(t, archive) <= int64(len(before)) {
		t.Fatal("the append wrote nothing before it was killed")
	}

	res := testutil.Run(t, tree.Root, "-tf", archive)
	if res.ExitCode != exitCorrupt || !strings.Contains(res.Stderr, "--repair") {
		t.Fatalf("list of a torn archive: exit %d, stderr %q; want exit %d naming --repair",
			res.ExitCode, res.Stderr, exitCorrupt)
	}

	repair := runOK(t, tree.Root, "--repair", "-f", archive)
	if !strings.Contains(repair.Stdout, "generation 1") {
		t.Errorf("repair said %q", repair.Stdout)
	}
	after, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("repair did not restore the archive exactly")
	}
	if got := listing(t, tree.Root, "-f", archive); strings.Join(got, "\n") != strings.Join(beforeList, "\n") {
		t.Errorf("listing after repair:\n%v\nwant:\n%v", got, beforeList)
	}

	again := runOK(t, tree.Root, "--repair", "-f", archive)
	if !strings.Contains(again.Stdout, "nothing to repair") {
		t.Errorf("second repair said %q", again.Stdout)
	}
}

// TestOverlappingAppendsAreRefused: two appends at the same time, as two
// overlapping backup jobs would run them. The second stops at once with
// exit 4 and says why; the first finishes normally (doc/design.md 9.6).
func TestOverlappingAppendsAreRefused(t *testing.T) {
	tree := fixture(t)
	archive := filepath.Join(t.TempDir(), "a.ect")
	runOK(t, tree.Root, "-cf", archive, "work")
	size := fileSize(t, archive)

	rnd := rand.New(rand.NewSource(2))
	tree.Dir("big", 0o755)
	for i := 0; i < 32; i++ {
		b := make([]byte, 1<<20)
		rnd.Read(b)
		tree.File(filepath.Join("big", strings.Repeat("y", i+1)), 0o644, b)
	}

	first := exec.Command(testutil.Binary(t), "-rf", archive, "-j", "1",
		"--compress", "zstd:level=19", "big")
	first.Dir = tree.Root
	if err := first.Start(); err != nil {
		t.Fatal(err)
	}
	// The first append holds the lock once it has written a blob.
	deadline := time.Now().Add(30 * time.Second)
	for fileSize(t, archive) <= size && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	second := testutil.Run(t, tree.Root, "-rf", archive, "work/README.md")
	if err := first.Wait(); err != nil {
		t.Fatalf("the first append failed: %v", err)
	}
	if second.ExitCode != 4 || !strings.Contains(second.Stderr, "another eictar is changing this archive") {
		t.Errorf("second append: exit %d, stderr %q; want exit 4 and the reason", second.ExitCode, second.Stderr)
	}
	if got := listing(t, tree.Root, "-f", archive, "big"); len(got) != 33 {
		t.Errorf("after the first append, big holds %d members, want 33", len(got))
	}
	runOK(t, tree.Root, "--verify", "-f", archive)
}

// TestEveryCodecInOneArchive: members from separate appends, each with its
// own codec, extracted in one pass (doc/design.md 13.2, mixed archives).
// -z and -J select gzip and xz, as in tar.
func TestEveryCodecInOneArchive(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Dir("w", 0o755)
	codecs := [][]string{
		{"--compress", "zstd:level=19"}, {"-z"}, {"-J"},
		{"--compress", "flate:level=1"}, {"--compress", "s2:mode=best"}, {"--compress", "none"},
	}
	for i := range codecs {
		tree.Text(filepath.Join("w", strings.Repeat("f", i+1)), 0o644, strings.Repeat("codec test data. ", 5000+i))
	}
	archive := filepath.Join(t.TempDir(), "mixed.ect")
	for i, c := range codecs {
		op := "-rf"
		if i == 0 {
			op = "-cf"
		}
		args := append([]string{op, archive}, c...)
		runOK(t, tree.Root, append(args, filepath.Join("w", strings.Repeat("f", i+1)))...)
	}

	long := runOK(t, tree.Root, "-tvf", archive).Stdout
	for _, want := range []string{"zstd:level=19", "gzip:level=6", "xz:preset=6", "flate:level=1", "s2:mode=best", "none"} {
		if !strings.Contains(long, want) {
			t.Errorf("the listing does not show %s:\n%s", want, long)
		}
	}
	runOK(t, tree.Root, "--verify", "-f", archive)
	dest := t.TempDir()
	runOK(t, tree.Root, "-xf", archive, "-d", dest)
	testutil.CompareTrees(t, tree.Path("w"), filepath.Join(dest, "w"), testutil.CompareOptions{})
}

// TestRecompress: --compact --recompress encodes every member again. A bad
// spec is a usage error that leaves the archive alone.
func TestRecompress(t *testing.T) {
	tree := fixture(t)
	archive := filepath.Join(t.TempDir(), "a.ect")
	runOK(t, tree.Root, "-cf", archive, "--compress", "s2", "work")
	before, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}

	if bad := testutil.Run(t, tree.Root, "--compact", "-f", archive, "--recompress", "xz:preset=42"); bad.ExitCode != exitUsage {
		t.Errorf("bad spec: exit %d (%s)", bad.ExitCode, bad.Stderr)
	}
	if after, _ := os.ReadFile(archive); !bytes.Equal(before, after) {
		t.Fatal("a refused recompress changed the archive")
	}

	res := runOK(t, tree.Root, "--compact", "-f", archive, "--recompress", "xz:preset=3")
	if !strings.Contains(res.Stdout, "encoded again with xz:preset=3") {
		t.Errorf("compact said %q", res.Stdout)
	}
	if long := runOK(t, tree.Root, "-tvf", archive).Stdout; strings.Contains(long, "s2:") || !strings.Contains(long, "xz:preset=3") {
		t.Errorf("the listing still shows the old codec:\n%s", long)
	}
	runOK(t, tree.Root, "--verify", "-f", archive)
	dest := t.TempDir()
	runOK(t, tree.Root, "-xf", archive, "-d", dest)
	testutil.CompareTrees(t, tree.Path("work"), filepath.Join(dest, "work"), testutil.CompareOptions{Mode: true})
}

// TestDictionaryThroughTheBinary: -Z zstd:train stores a dictionary, which
// --info and the listing show, and the archive gives back every file
// (doc/design.md 4.2). With nothing to learn from, there is a notice and no
// dictionary.
func TestDictionaryThroughTheBinary(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Dir("src", 0o755)
	for i := 0; i < 120; i++ {
		tree.Text(fmt.Sprintf("src/f%03d.go", i), 0o644, fmt.Sprintf(
			"// Copyright 2026 The Example Authors.\npackage p%d\n\nimport \"fmt\"\n\nfunc F%d() { fmt.Println(%d) }\n%s",
			i%4, i, i, strings.Repeat("// shared comment line\n", 1+i%5)))
	}
	archive := filepath.Join(t.TempDir(), "d.ect")
	runOK(t, tree.Root, "-cf", archive, "-Z", "zstd:level=19,train=8K", "src")
	if info := runOK(t, tree.Root, "--info", "-f", archive); !strings.Contains(info.Stdout, "dictionary:") ||
		!strings.Contains(info.Stdout, "120 live members") {
		t.Errorf("--info:\n%s", info.Stdout)
	}
	if list := runOK(t, tree.Root, "-tvf", archive); !strings.Contains(list.Stdout, "zstd:level=19,dict") {
		t.Errorf("-tv does not show the dictionary:\n%s", list.Stdout)
	}
	runOK(t, tree.Root, "--verify", "-f", archive)
	dest := t.TempDir()
	runOK(t, tree.Root, "-xf", archive, "-d", dest)
	testutil.CompareTrees(t, filepath.Join(tree.Root, "src"), filepath.Join(dest, "src"), testutil.CompareOptions{})

	small := testutil.NewTree(t)
	small.Text("one.txt", 0o644, "x")
	res := runOK(t, small.Root, "-cf", filepath.Join(t.TempDir(), "s.ect"), "-Z", "zstd:train", "one.txt")
	if !strings.Contains(res.Stderr, "without a dictionary") {
		t.Errorf("stderr = %q, want the notice", res.Stderr)
	}
	if bad := testutil.Run(t, small.Root, "-cf", filepath.Join(t.TempDir(), "b.ect"), "-Z", "gzip:train", "one.txt"); bad.ExitCode != exitUsage {
		t.Errorf("gzip:train: exit %d, want %d", bad.ExitCode, exitUsage)
	}
}

// TestSharedContentThroughTheBinary: copies share one blob, and the listing,
// --info and --json say so, also when the owner is an earlier version or a
// deleted file (doc/design.md 4.3). --no-dedup stores each copy.
func TestSharedContentThroughTheBinary(t *testing.T) {
	text := strings.Repeat("one content, two places\n", 2000)
	tree := testutil.NewTree(t)
	tree.Dir("s", 0o755)
	tree.Text("s/a.txt", 0o644, text)
	tree.Text("s/b.txt", 0o644, text)
	archive := filepath.Join(t.TempDir(), "s.ect")
	runOK(t, tree.Root, "-cf", archive, "s")

	long := runOK(t, tree.Root, "-tvvf", archive).Stdout
	if !strings.Contains(long, "same as s/") || !strings.Contains(long, "1 same as another") {
		t.Errorf("-tvv:\n%s", long)
	}
	if info := runOK(t, tree.Root, "--info", "-f", archive).Stdout; !strings.Contains(info, "shared content:  1 member") {
		t.Errorf("--info:\n%s", info)
	}
	if js := runOK(t, tree.Root, "-tf", archive, "--json").Stdout; !strings.Contains(js, `"same_as": "s/`) {
		t.Errorf("--json:\n%s", js)
	}

	// -u takes an unchanged, touched file again: it shares its own earlier
	// version. Then the other copy goes, and a sharer names a deleted owner.
	tree.SetTimes("s/a.txt", time.Unix(5, 0), time.Unix(6, 0))
	tree.SetTimes("s/b.txt", time.Unix(5, 0), time.Unix(6, 0))
	runOK(t, tree.Root, "-uf", archive, "--update-mode", "different", "s")
	long = runOK(t, tree.Root, "-tvf", archive).Stdout
	if !strings.Contains(long, "same as its earlier version") {
		t.Errorf("after -u:\n%s", long)
	}
	runOK(t, tree.Root, "--verify", "-f", archive)
	dest := t.TempDir()
	runOK(t, tree.Root, "-xf", archive, "-d", dest)
	testutil.CompareTrees(t, filepath.Join(tree.Root, "s"), filepath.Join(dest, "s"), testutil.CompareOptions{})

	full := filepath.Join(t.TempDir(), "f.ect")
	runOK(t, tree.Root, "-cf", full, "--no-dedup", "s")
	if long := runOK(t, tree.Root, "-tvf", full).Stdout; strings.Contains(long, "same as") {
		t.Errorf("--no-dedup:\n%s", long)
	}
}
