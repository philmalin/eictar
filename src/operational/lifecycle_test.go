//go:build operational

package operational

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"eictar/src/internal/testutil"
)

const (
	exitPartial = 1
	exitCorrupt = 3
)

// fixture builds a tree worth archiving: nested directories, an empty file,
// text that compresses, bytes that do not, and content crossing a chunk
// boundary.
func fixture(t *testing.T) *testutil.Tree {
	t.Helper()

	tree := testutil.NewTree(t)
	tree.Dir("work", 0o755).
		Dir("work/src", 0o750).
		Text("work/README.md", 0o644, strings.Repeat("documentation. ", 200)).
		Text("work/src/main.go", 0o644, "package main\n\nfunc main() {}\n").
		Text("work/empty.txt", 0o644, "").
		File("work/data.bin", 0o600, []byte{0x00, 0xff, 0x7f, 0x80, 0x01}).
		File("work/large.bin", 0o644, []byte(strings.Repeat("0123456789", 600_000)))
	return tree
}

// TestLifecycle is the operational round trip: create, list, extract, compare.
// It drives the binary exactly as a user would.
func TestLifecycle(t *testing.T) {
	for _, codecName := range []string{"none", "zstd", "zstd:level=19"} {
		t.Run(codecName, func(t *testing.T) {
			tree := fixture(t)
			archive := filepath.Join(t.TempDir(), "backup.eictar")

			create := testutil.Run(t, tree.Root, "-cvf", archive, "--compress", codecName, "work")
			if create.ExitCode != exitOK {
				t.Fatalf("create: exit %d (stderr: %s)", create.ExitCode, create.Stderr)
			}
			for _, want := range []string{"work", "work/README.md", "work/src/main.go"} {
				if !strings.Contains(create.Stdout, want) {
					t.Errorf("-v output does not mention %q:\n%s", want, create.Stdout)
				}
			}

			list := testutil.Run(t, tree.Root, "-tf", archive)
			if list.ExitCode != exitOK {
				t.Fatalf("list: exit %d (stderr: %s)", list.ExitCode, list.Stderr)
			}
			got := strings.Fields(list.Stdout)
			want := []string{
				"work", "work/README.md", "work/data.bin", "work/empty.txt",
				"work/large.bin", "work/src", "work/src/main.go",
			}
			if strings.Join(got, " ") != strings.Join(want, " ") {
				t.Errorf("listing:\n got %v\nwant %v", got, want)
			}

			dest := t.TempDir()
			extract := testutil.Run(t, tree.Root, "-xf", archive, "-d", dest)
			if extract.ExitCode != exitOK {
				t.Fatalf("extract: exit %d (stderr: %s)", extract.ExitCode, extract.Stderr)
			}

			testutil.CompareTrees(t,
				filepath.Join(tree.Root, "work"),
				filepath.Join(dest, "work"),
				testutil.CompareOptions{Mode: true, MTime: true})
		})
	}
}

// TestDestinationIsCreated is the -d promise: unlike -C, the directory need
// not exist.
func TestDestinationIsCreated(t *testing.T) {
	tree := fixture(t)
	archive := filepath.Join(t.TempDir(), "a.eictar")

	if res := testutil.Run(t, tree.Root, "-cf", archive, "work"); res.ExitCode != exitOK {
		t.Fatalf("create: exit %d (stderr: %s)", res.ExitCode, res.Stderr)
	}

	dest := filepath.Join(t.TempDir(), "does", "not", "exist")
	res := testutil.Run(t, tree.Root, "-xf", archive, "-d", dest)
	if res.ExitCode != exitOK {
		t.Fatalf("extract: exit %d (stderr: %s)", res.ExitCode, res.Stderr)
	}
	if _, err := os.Stat(filepath.Join(dest, "work", "README.md")); err != nil {
		t.Errorf("extraction did not create the destination: %v", err)
	}
}

// TestAbsolutePathsAreStripped is the convention from doc/design.md 7: the
// leading slash goes, one warning is printed, and extraction lands under the
// destination rather than over the system.
func TestAbsolutePathsAreStripped(t *testing.T) {
	tree := fixture(t)
	archive := filepath.Join(t.TempDir(), "a.eictar")
	absPath := filepath.Join(tree.Root, "work", "README.md")

	create := testutil.Run(t, tree.Root, "-cf", archive, absPath)
	if create.ExitCode != exitOK {
		t.Fatalf("create: exit %d (stderr: %s)", create.ExitCode, create.Stderr)
	}
	if !strings.Contains(create.Stderr, "removing leading") {
		t.Errorf("stderr = %q, want a one-time notice about stripping", create.Stderr)
	}

	list := testutil.Run(t, tree.Root, "-tf", archive)
	for _, line := range strings.Fields(list.Stdout) {
		if strings.HasPrefix(line, "/") {
			t.Errorf("member %q kept its leading slash", line)
		}
	}

	dest := t.TempDir()
	if res := testutil.Run(t, tree.Root, "-xf", archive, "-d", dest); res.ExitCode != exitOK {
		t.Fatalf("extract: exit %d (stderr: %s)", res.ExitCode, res.Stderr)
	}

	// The member landed under the destination, mirroring its absolute path.
	found := false
	filepath.Walk(dest, func(p string, fi os.FileInfo, err error) error {
		if err == nil && fi.Mode().IsRegular() && filepath.Base(p) == "README.md" {
			found = true
		}
		return nil
	})
	if !found {
		t.Error("the stripped member did not land under the destination")
	}
}

func TestSelectiveExtract(t *testing.T) {
	tree := fixture(t)
	archive := filepath.Join(t.TempDir(), "a.eictar")

	if res := testutil.Run(t, tree.Root, "-cf", archive, "work"); res.ExitCode != exitOK {
		t.Fatalf("create: exit %d", res.ExitCode)
	}

	dest := t.TempDir()
	res := testutil.Run(t, tree.Root, "-xf", archive, "-d", dest, "work/src")
	if res.ExitCode != exitOK {
		t.Fatalf("extract: exit %d (stderr: %s)", res.ExitCode, res.Stderr)
	}

	if _, err := os.Stat(filepath.Join(dest, "work", "src", "main.go")); err != nil {
		t.Errorf("the selected member was not extracted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "work", "README.md")); err == nil {
		t.Error("an unselected member was extracted")
	}
}

func TestToStdout(t *testing.T) {
	tree := fixture(t)
	archive := filepath.Join(t.TempDir(), "a.eictar")

	if res := testutil.Run(t, tree.Root, "-cf", archive, "work"); res.ExitCode != exitOK {
		t.Fatalf("create: exit %d", res.ExitCode)
	}

	res := testutil.Run(t, tree.Root, "-xOvf", archive, "work/src/main.go")
	if res.ExitCode != exitOK {
		t.Fatalf("extract: exit %d (stderr: %s)", res.ExitCode, res.Stderr)
	}
	if res.Stdout != "package main\n\nfunc main() {}\n" {
		t.Errorf("stdout = %q, want the member's content alone", res.Stdout)
	}
	// -v output must go to stderr here, or it would corrupt the content.
	if !strings.Contains(res.Stderr, "main.go") {
		t.Errorf("stderr = %q, want the -v listing there", res.Stderr)
	}
}

func TestKeepExisting(t *testing.T) {
	tree := fixture(t)
	archive := filepath.Join(t.TempDir(), "a.eictar")

	if res := testutil.Run(t, tree.Root, "-cf", archive, "work"); res.ExitCode != exitOK {
		t.Fatalf("create: exit %d", res.ExitCode)
	}

	dest := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dest, "work", "src"), 0o755); err != nil {
		t.Fatalf("seeding: %v", err)
	}
	keep := filepath.Join(dest, "work", "src", "main.go")
	if err := os.WriteFile(keep, []byte("mine"), 0o644); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	if res := testutil.Run(t, tree.Root, "-xkf", archive, "-d", dest); res.ExitCode != exitOK {
		t.Fatalf("extract: exit %d (stderr: %s)", res.ExitCode, res.Stderr)
	}

	got, err := os.ReadFile(keep)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	if string(got) != "mine" {
		t.Errorf("-k overwrote an existing file: content = %q", got)
	}
}

// TestDamagedArchiveExitsCorrupt keeps exit code 3 distinct from code 4, which
// is what lets a backup script tell a broken archive from a full disk.
func TestDamagedArchiveExitsCorrupt(t *testing.T) {
	tree := fixture(t)
	archive := filepath.Join(t.TempDir(), "a.eictar")

	if res := testutil.Run(t, tree.Root, "-cf", archive, "work"); res.ExitCode != exitOK {
		t.Fatalf("create: exit %d", res.ExitCode)
	}

	f, err := os.OpenFile(archive, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	var b [1]byte
	if _, err := f.ReadAt(b[:], 20); err != nil {
		t.Fatalf("reading: %v", err)
	}
	b[0] ^= 0xff
	if _, err := f.WriteAt(b[:], 20); err != nil {
		t.Fatalf("writing: %v", err)
	}
	f.Close()

	res := testutil.Run(t, tree.Root, "-tf", archive)
	if res.ExitCode != exitCorrupt {
		t.Errorf("exit %d, want %d for a damaged archive (stderr: %s)",
			res.ExitCode, exitCorrupt, res.Stderr)
	}
}

func TestMissingArchive(t *testing.T) {
	res := testutil.Run(t, t.TempDir(), "-tf", "nonesuch.eictar")
	if res.ExitCode == exitOK {
		t.Error("listing a missing archive succeeded")
	}
	if !strings.Contains(res.Stderr, "nonesuch.eictar") {
		t.Errorf("stderr = %q, want it to name the file", res.Stderr)
	}
}

func TestListCodecs(t *testing.T) {
	res := testutil.Run(t, t.TempDir(), "--list-codecs")
	if res.ExitCode != exitOK {
		t.Fatalf("exit %d (stderr: %s)", res.ExitCode, res.Stderr)
	}
	for _, want := range []string{"zstd", "none", "level"} {
		if !strings.Contains(res.Stdout, want) {
			t.Errorf("--list-codecs does not mention %q:\n%s", want, res.Stdout)
		}
	}
}

func TestUnknownCodecIsRefused(t *testing.T) {
	tree := fixture(t)
	res := testutil.Run(t, tree.Root, "-cf", filepath.Join(t.TempDir(), "a.eictar"),
		"--compress", "brotli", "work")
	if res.ExitCode == exitOK {
		t.Fatal("an unknown codec was accepted")
	}
	if !strings.Contains(res.Stderr, "zstd") {
		t.Errorf("stderr = %q, want it to list the known codecs", res.Stderr)
	}
}

// TestKeepGoingReportsPartial pins exit code 1: the archive was written, but
// not everything made it in.
func TestKeepGoingReportsPartial(t *testing.T) {
	tree := testutil.NewTree(t)
	// An unreadable file fails during create, which is what makes this a
	// partial run rather than a clean one.
	tree.Text("good.txt", 0o644, "content").Unreadable("locked.txt")

	archive := filepath.Join(t.TempDir(), "a.eictar")
	res := testutil.Run(t, tree.Root, "-cf", archive, "--keep-going", "good.txt", "locked.txt")
	if res.ExitCode != exitPartial {
		t.Errorf("exit %d, want %d (stderr: %s)", res.ExitCode, exitPartial, res.Stderr)
	}

	list := testutil.Run(t, tree.Root, "-tf", archive)
	if strings.TrimSpace(list.Stdout) != "good.txt" {
		t.Errorf("archive holds %q, want just good.txt", list.Stdout)
	}
}

// TestSymlinkLifecycle drives symlinks through the binary end to end.
func TestSymlinkLifecycle(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Dir("work", 0o755).
		Dir("work/sub", 0o755).
		Text("work/real.txt", 0o644, "content").
		Text("work/sub/inner.txt", 0o644, "inner").
		Symlink("work/rel", "real.txt").
		Symlink("work/abs", "/etc/hostname").
		Symlink("work/dangling", "gone.txt").
		Symlink("work/dir-link", "sub")

	archive := filepath.Join(t.TempDir(), "a.eictar")
	if res := testutil.Run(t, tree.Root, "-cf", archive, "work"); res.ExitCode != exitOK {
		t.Fatalf("create: exit %d (stderr: %s)", res.ExitCode, res.Stderr)
	}

	list := testutil.Run(t, tree.Root, "-tf", archive, "--long")
	if !strings.Contains(list.Stdout, "lrwxrwxrwx") {
		t.Errorf("long listing does not mark symlinks:\n%s", list.Stdout)
	}

	dest := t.TempDir()
	if res := testutil.Run(t, tree.Root, "-xf", archive, "-d", dest); res.ExitCode != exitOK {
		t.Fatalf("extract: exit %d (stderr: %s)", res.ExitCode, res.Stderr)
	}

	testutil.CompareTrees(t,
		filepath.Join(tree.Root, "work"),
		filepath.Join(dest, "work"),
		testutil.CompareOptions{Mode: true})

	// A dangling link is recreated as a dangling link, not as a missing file.
	if _, err := os.Lstat(filepath.Join(dest, "work", "dangling")); err != nil {
		t.Errorf("the dangling link was not recreated: %v", err)
	}
}

// TestDereferenceOption covers -h through the binary.
func TestDereferenceOption(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Dir("work", 0o755).
		Text("work/real.txt", 0o644, "content").
		Symlink("work/link", "real.txt")

	archive := filepath.Join(t.TempDir(), "a.eictar")
	if res := testutil.Run(t, tree.Root, "-chf", archive, "work"); res.ExitCode != exitOK {
		t.Fatalf("create: exit %d (stderr: %s)", res.ExitCode, res.Stderr)
	}

	dest := t.TempDir()
	if res := testutil.Run(t, tree.Root, "-xf", archive, "-d", dest); res.ExitCode != exitOK {
		t.Fatalf("extract: exit %d (stderr: %s)", res.ExitCode, res.Stderr)
	}

	fi, err := os.Lstat(filepath.Join(dest, "work", "link"))
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Error("-h stored a symlink instead of its target")
	}
	got, err := os.ReadFile(filepath.Join(dest, "work", "link"))
	if err != nil || string(got) != "content" {
		t.Errorf("-h did not store the target's content: %q, %v", got, err)
	}
}

// TestJSONListingIsValidJSON covers the listing a script consumes, including
// the case this program deliberately supports: a filename that is not valid
// UTF-8.
func TestJSONListingIsValidJSON(t *testing.T) {
	tree := testutil.NewTree(t)
	if !tree.AcceptsNonUTF8() {
		t.Skip("this filesystem refuses file names that are not UTF-8 (APFS)")
	}
	tree.Text("plain.txt", 0o644, "content").
		Text("caf\xe9.txt", 0o644, "latin-1 name").
		Symlink("link", "plain.txt")

	archive := filepath.Join(t.TempDir(), "a.eictar")
	if res := testutil.Run(t, tree.Root, "-cf", archive, "."); res.ExitCode != exitOK {
		t.Fatalf("create: exit %d (stderr: %s)", res.ExitCode, res.Stderr)
	}

	res := testutil.Run(t, tree.Root, "-tf", archive, "--json")
	if res.ExitCode != exitOK {
		t.Fatalf("list: exit %d (stderr: %s)", res.ExitCode, res.Stderr)
	}

	var members []struct {
		Path       string `json:"path"`
		PathBase64 string `json:"path_base64"`
		Type       string `json:"type"`
		Size       uint64 `json:"size"`
		Target     string `json:"target"`
	}
	if err := json.Unmarshal([]byte(res.Stdout), &members); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, res.Stdout)
	}
	if len(members) != 3 {
		t.Fatalf("got %d members, want 3: %s", len(members), res.Stdout)
	}

	var sawLatin1, sawLink bool
	for _, m := range members {
		if m.PathBase64 != "" {
			raw, err := base64.StdEncoding.DecodeString(m.PathBase64)
			if err != nil {
				t.Fatalf("path_base64 does not decode: %v", err)
			}
			if string(raw) != "caf\xe9.txt" {
				t.Errorf("path_base64 decodes to %q, want the original bytes", raw)
			}
			sawLatin1 = true
		}
		if m.Type == "symlink" {
			if m.Target != "plain.txt" {
				t.Errorf("symlink target = %q, want %q", m.Target, "plain.txt")
			}
			sawLink = true
		}
	}
	if !sawLatin1 {
		t.Error("the non-UTF-8 path carried no path_base64, so its bytes are unrecoverable")
	}
	if !sawLink {
		t.Error("no symlink in the listing")
	}
}

// TestArchiveDoesNotSwallowItself is the operational form: creating an archive
// inside the tree being archived must not include it.
func TestArchiveDoesNotSwallowItself(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Dir("work", 0o755).Text("work/a.txt", 0o644, "content")

	res := testutil.Run(t, tree.Root, "-cf", "work/self.eictar", "work")
	if res.ExitCode != exitOK {
		t.Fatalf("create: exit %d (stderr: %s)", res.ExitCode, res.Stderr)
	}
	if !strings.Contains(res.Stderr, "not archiving it") {
		t.Errorf("stderr = %q, want a notice that the archive was skipped", res.Stderr)
	}

	list := testutil.Run(t, tree.Root, "-tf", "work/self.eictar")
	if strings.Contains(list.Stdout, "self.eictar") {
		t.Errorf("the archive archived itself:\n%s", list.Stdout)
	}
}

// TestProgressNeedsATerminal: --progress draws only on a terminal. With
// stderr redirected, as here, it must write nothing there, so that a log is
// not filled with carriage returns.
func TestProgressNeedsATerminal(t *testing.T) {
	tree := fixture(t)
	archive := filepath.Join(t.TempDir(), "a.eictar")
	for _, args := range [][]string{
		{"-cf", archive, "--progress", "work"},
		{"-xf", archive, "--progress", "-d", t.TempDir()},
		{"--verify", "-f", archive, "--progress", "-q"},
	} {
		res := testutil.Run(t, tree.Root, args...)
		if res.ExitCode != exitOK || res.Stderr != "" {
			t.Errorf("%q: exit %d, stderr %q", args, res.ExitCode, res.Stderr)
		}
	}
}

// TestWorkerCountsAgree drives the binary at several worker counts and checks
// the extracted trees match, which is the user-visible form of the property
// doc/design.md 13.2 asks for.
func TestWorkerCountsAgree(t *testing.T) {
	tree := fixture(t)
	dir := t.TempDir()

	var extracted []string
	for _, workers := range []string{"1", "2", "8", "32"} {
		archive := filepath.Join(dir, "j"+workers+".eictar")
		create := testutil.Run(t, tree.Root, "-cf", archive, "-j", workers,
			"--compress", "zstd:level=9", "work")
		if create.ExitCode != exitOK {
			t.Fatalf("create -j %s: exit %d (stderr: %s)", workers, create.ExitCode, create.Stderr)
		}

		dest := filepath.Join(dir, "out"+workers)
		x := testutil.Run(t, tree.Root, "-xf", archive, "-d", dest, "-j", workers)
		if x.ExitCode != exitOK {
			t.Fatalf("extract -j %s: exit %d (stderr: %s)", workers, x.ExitCode, x.Stderr)
		}
		extracted = append(extracted, filepath.Join(dest, "work"))

		// Listings must agree too: the index is sorted by member id, which is
		// walk order, so the worker count cannot reorder it.
		list := testutil.Run(t, tree.Root, "-tf", archive)
		if workers != "1" {
			first := testutil.Run(t, tree.Root, "-tf", filepath.Join(dir, "j1.eictar"))
			if list.Stdout != first.Stdout {
				t.Errorf("-j %s listed a different order:\n%s\nvs\n%s",
					workers, list.Stdout, first.Stdout)
			}
		}
	}

	for _, got := range extracted[1:] {
		testutil.CompareTrees(t, extracted[0], got,
			testutil.CompareOptions{Mode: true, MTime: true})
	}
	testutil.CompareTrees(t, filepath.Join(tree.Root, "work"), extracted[0],
		testutil.CompareOptions{Mode: true, MTime: true})
}

// TestMemoryLimitAndSpill exercises the spill path through the binary: a
// budget far smaller than the input forces payloads onto disk, and the result
// must be identical anyway.
func TestMemoryLimitAndSpill(t *testing.T) {
	tree := fixture(t)
	archive := filepath.Join(t.TempDir(), "a.eictar")

	create := testutil.Run(t, tree.Root, "-cf", archive,
		"-j", "8", "--chunk-size", "64KiB",
		"--memory-limit", "256KiB", "--spill-threshold", "128KiB", "work")
	if create.ExitCode != exitOK {
		t.Fatalf("create: exit %d (stderr: %s)", create.ExitCode, create.Stderr)
	}

	dest := t.TempDir()
	if res := testutil.Run(t, tree.Root, "-xf", archive, "-d", dest, "-j", "8"); res.ExitCode != exitOK {
		t.Fatalf("extract: exit %d (stderr: %s)", res.ExitCode, res.Stderr)
	}
	testutil.CompareTrees(t,
		filepath.Join(tree.Root, "work"),
		filepath.Join(dest, "work"),
		testutil.CompareOptions{Mode: true, MTime: true})

	// No spill file may survive the run.
	entries, err := os.ReadDir(filepath.Dir(archive))
	if err != nil {
		t.Fatalf("reading the archive directory: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".eictar-spool-") {
			t.Errorf("a spill file was left behind: %s", e.Name())
		}
	}
}

// TestLargeMemberSpansManyChunks covers the index shape a single big file
// produces: one member with a long chunk table in an otherwise tiny index.
func TestLargeMemberSpansManyChunks(t *testing.T) {
	tree := testutil.NewTree(t)
	// Compressible, so the archive stays small, but large enough to need
	// hundreds of chunks at the size below.
	tree.Text("big.txt", 0o644, strings.Repeat("the quick brown fox. ", 500_000))

	archive := filepath.Join(t.TempDir(), "a.eictar")
	if res := testutil.Run(t, tree.Root, "-cf", archive,
		"--chunk-size", "64KiB", "-j", "4", "big.txt"); res.ExitCode != exitOK {
		t.Fatalf("create: exit %d (stderr: %s)", res.ExitCode, res.Stderr)
	}

	if res := testutil.Run(t, tree.Root, "-tf", archive); res.ExitCode != exitOK {
		t.Fatalf("list: exit %d (stderr: %s)", res.ExitCode, res.Stderr)
	}

	dest := t.TempDir()
	if res := testutil.Run(t, tree.Root, "-xf", archive, "-d", dest); res.ExitCode != exitOK {
		t.Fatalf("extract: exit %d (stderr: %s)", res.ExitCode, res.Stderr)
	}
	testutil.CompareTrees(t, tree.Root, dest, testutil.CompareOptions{Mode: true, MTime: true})
}

// ---------------------------------------------------------------------------
// M4: encryption, through the binary
// ---------------------------------------------------------------------------

func passFile(t *testing.T, text string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "pass.txt")
	if err := os.WriteFile(p, []byte(text+"\n"), 0o600); err != nil {
		t.Fatalf("writing passphrase file: %v", err)
	}
	return p
}

func TestEncryptedLifecycle(t *testing.T) {
	for _, extra := range [][]string{nil, {"--encrypt-index"}} {
		name := "index-plaintext"
		if len(extra) > 0 {
			name = "index-encrypted"
		}
		t.Run(name, func(t *testing.T) {
			tree := fixture(t)
			pass := passFile(t, "correct horse battery staple")
			archive := filepath.Join(t.TempDir(), "enc.eictar")

			args := append([]string{"-cf", archive, "-e",
				"--passphrase-file", pass, "--kdf-memory", "8192", "--kdf-time", "1",
				"-j", "4", "work"}, extra...)
			if res := testutil.Run(t, tree.Root, args...); res.ExitCode != exitOK {
				t.Fatalf("create: exit %d (stderr: %s)", res.ExitCode, res.Stderr)
			}

			list := testutil.Run(t, tree.Root, "-tf", archive, "--passphrase-file", pass)
			if list.ExitCode != exitOK {
				t.Fatalf("list: exit %d (stderr: %s)", list.ExitCode, list.Stderr)
			}
			if !strings.Contains(list.Stdout, "work/README.md") {
				t.Errorf("listing is missing members:\n%s", list.Stdout)
			}

			dest := t.TempDir()
			x := testutil.Run(t, tree.Root, "-xf", archive, "-d", dest,
				"--passphrase-file", pass, "-j", "4")
			if x.ExitCode != exitOK {
				t.Fatalf("extract: exit %d (stderr: %s)", x.ExitCode, x.Stderr)
			}
			testutil.CompareTrees(t,
				filepath.Join(tree.Root, "work"),
				filepath.Join(dest, "work"),
				testutil.CompareOptions{Mode: true, MTime: true})
		})
	}
}

// TestWrongPassphraseExitsThree keeps "this archive did not authenticate"
// distinct from "the disk broke" for a script (doc/design.md 10.7).
func TestWrongPassphraseExitsThree(t *testing.T) {
	tree := fixture(t)
	right := passFile(t, "right one")
	wrong := passFile(t, "wrong one")
	archive := filepath.Join(t.TempDir(), "enc.eictar")

	if res := testutil.Run(t, tree.Root, "-cf", archive, "-e",
		"--passphrase-file", right, "--kdf-memory", "8192", "--kdf-time", "1",
		"work"); res.ExitCode != exitOK {
		t.Fatalf("create: exit %d (stderr: %s)", res.ExitCode, res.Stderr)
	}

	res := testutil.Run(t, tree.Root, "-tf", archive, "--passphrase-file", wrong)
	if res.ExitCode != exitCorrupt {
		t.Errorf("exit %d, want %d (stderr: %s)", res.ExitCode, exitCorrupt, res.Stderr)
	}
	if !strings.Contains(res.Stderr, "passphrase") {
		t.Errorf("stderr = %q, want it to name the passphrase", res.Stderr)
	}
}

// TestEncryptedArchiveWithoutPassphraseFails: no terminal, no passphrase, and
// the message must say how to supply one rather than hanging or guessing.
func TestEncryptedArchiveWithoutPassphraseFails(t *testing.T) {
	tree := fixture(t)
	pass := passFile(t, "a passphrase")
	archive := filepath.Join(t.TempDir(), "enc.eictar")

	if res := testutil.Run(t, tree.Root, "-cf", archive, "-e",
		"--passphrase-file", pass, "--kdf-memory", "8192", "--kdf-time", "1",
		"work"); res.ExitCode != exitOK {
		t.Fatalf("create: exit %d (stderr: %s)", res.ExitCode, res.Stderr)
	}

	res := testutil.Run(t, tree.Root, "-tf", archive)
	if res.ExitCode == exitOK {
		t.Fatal("an encrypted archive listed without a passphrase")
	}
	for _, want := range []string{"--passphrase-file", "--passphrase-env"} {
		if !strings.Contains(res.Stderr, want) {
			t.Errorf("stderr = %q, want it to mention %s", res.Stderr, want)
		}
	}
}

// TestPlaintextArchiveNeverPrompts: a plaintext archive must not ask for a
// passphrase, whatever the passphrase options say.
func TestPlaintextArchiveNeverPrompts(t *testing.T) {
	tree := fixture(t)
	archive := filepath.Join(t.TempDir(), "plain.eictar")

	if res := testutil.Run(t, tree.Root, "-cf", archive, "work"); res.ExitCode != exitOK {
		t.Fatalf("create: exit %d", res.ExitCode)
	}
	res := testutil.Run(t, tree.Root, "-tf", archive)
	if res.ExitCode != exitOK {
		t.Errorf("listing a plaintext archive failed: exit %d (stderr: %s)",
			res.ExitCode, res.Stderr)
	}
}

// TestPassphraseEnv covers the scripted route, and the warning it carries.
func TestPassphraseEnv(t *testing.T) {
	tree := fixture(t)
	archive := filepath.Join(t.TempDir(), "enc.eictar")

	res := testutil.RunEnv(t, tree.Root, []string{"EICTAR_TEST_PASS=from the environment"},
		"-cf", archive, "-e", "--passphrase-env", "EICTAR_TEST_PASS",
		"--kdf-memory", "8192", "--kdf-time", "1", "work")
	if res.ExitCode != exitOK {
		t.Fatalf("create: exit %d (stderr: %s)", res.ExitCode, res.Stderr)
	}
	if !strings.Contains(res.Stderr, "environment") {
		t.Errorf("stderr = %q, want a warning about the environment", res.Stderr)
	}

	x := testutil.RunEnv(t, tree.Root, []string{"EICTAR_TEST_PASS=from the environment"},
		"-tf", archive, "--passphrase-env", "EICTAR_TEST_PASS")
	if x.ExitCode != exitOK {
		t.Fatalf("list: exit %d (stderr: %s)", x.ExitCode, x.Stderr)
	}
	if !strings.Contains(x.Stdout, "work/README.md") {
		t.Errorf("listing is missing members:\n%s", x.Stdout)
	}
}

// TestPlaintextArchiveWithPassphraseIsRefused is the user-visible side of the
// downgrade defence: supplying a passphrase and finding nothing encrypted is
// exit 3, because a stripped or substituted archive looks exactly like this.
func TestPlaintextArchiveWithPassphraseIsRefused(t *testing.T) {
	tree := fixture(t)
	pass := passFile(t, "whatever")
	archive := filepath.Join(t.TempDir(), "plain.eictar")

	if res := testutil.Run(t, tree.Root, "-cf", archive, "work"); res.ExitCode != exitOK {
		t.Fatalf("create: exit %d", res.ExitCode)
	}
	for _, args := range [][]string{
		{"-tf", archive, "--passphrase-file", pass},
		{"-xf", archive, "-d", t.TempDir(), "--passphrase-file", pass},
	} {
		res := testutil.Run(t, tree.Root, args...)
		if res.ExitCode != exitCorrupt {
			t.Errorf("%v: exit %d, want %d (stderr: %s)", args[0], res.ExitCode, exitCorrupt, res.Stderr)
		}
		if !strings.Contains(res.Stderr, "not encrypted") {
			t.Errorf("stderr = %q, want it to say the archive is not encrypted", res.Stderr)
		}
	}
}

// ---------------------------------------------------------------------------
// M5: metadata, through the binary
// ---------------------------------------------------------------------------

// platform is what doc/design.md 15.1 promises on this platform. The
// operational tests keep their own copy, from the design, rather than ask the
// program: a test must not take its expectations from the code it tests.
var platform = map[string]struct{ xattrs, holes, pipes bool }{
	"linux":   {xattrs: true, holes: true, pipes: true},
	"darwin":  {xattrs: true, holes: true, pipes: false},
	"freebsd": {xattrs: true, holes: true, pipes: true},
	"netbsd":  {xattrs: true, holes: false, pipes: true},
	"openbsd": {xattrs: false, holes: false, pipes: true},
}[runtime.GOOS]

func metadataFixture(t *testing.T) *testutil.Tree {
	t.Helper()
	tree := testutil.NewTree(t)
	stamp := time.Unix(1_600_000_000, 0)
	tree.Dir("work", 0o755).
		Dir("work/private", 0o700).
		Text("work/attrs.txt", 0o640, "attributes")
	if platform.xattrs {
		tree.Xattr("work/attrs.txt", "user.origin", []byte("operational test"))
	}
	tree.Text("work/tool", 0o755, "#!/bin/sh\n").
		Chmod("work/tool", 0o755|os.ModeSetuid).
		Text("work/private/data", 0o600, "linked").
		Hardlink("work/alias", "work/private/data").
		Fifo("work/pipe", 0o600).
		Symlink("work/link", "attrs.txt").
		Sparse("work/disk.img", 0o644, 16<<20,
			testutil.Segment{Offset: 0, Data: []byte("head")},
			testutil.Segment{Offset: 8 << 20, Data: []byte("middle")})
	for _, p := range []string{"work/attrs.txt", "work/tool", "work/private/data", "work/pipe", "work/disk.img"} {
		tree.SetTimes(p, stamp, stamp)
	}
	tree.SetLinkTimes("work/link", stamp, stamp.Add(time.Minute))
	tree.SetTimes("work/private", stamp, stamp)
	tree.SetTimes("work", stamp, stamp)
	return tree
}

// TestMetadataLifecycle drives M5 end to end: everything recorded comes back,
// with -p for the special bits, and the socket is skipped with a notice.
func TestMetadataLifecycle(t *testing.T) {
	tree := metadataFixture(t)
	archive := filepath.Join(t.TempDir(), "meta.eictar")

	create := testutil.Run(t, tree.Root, "-cf", archive, "work")
	if create.ExitCode != exitOK {
		t.Fatalf("create: exit %d (stderr: %s)", create.ExitCode, create.Stderr)
	}

	dest := t.TempDir()
	res := testutil.Run(t, tree.Root, "-xpf", archive, "-d", dest)
	if res.ExitCode != exitOK {
		t.Fatalf("extract: exit %d (stderr: %s)", res.ExitCode, res.Stderr)
	}
	if !platform.pipes && !strings.Contains(res.Stderr, "cannot be created safely") {
		t.Errorf("stderr = %q, want a notice that the pipe was skipped", res.Stderr)
	}

	// A pipe does not come back where the platform cannot make one safely.
	if !platform.pipes {
		os.Remove(tree.Path("work/pipe"))
	}
	testutil.CompareTrees(t, tree.Path("work"), filepath.Join(dest, "work"),
		testutil.CompareOptions{Mode: true, Special: true, MTime: true,
			Hardlinks: true, Xattrs: platform.xattrs,
			Holes: platform.holes && tree.Holes("work/disk.img")})
}

// TestSocketIsSkippedThroughTheBinary: a socket has no content and cannot be
// recreated, so create skips it with a notice and archives the rest. It is a
// test of its own, so that a platform where a test cannot make a socket skips
// only this, not the whole metadata lifecycle.
func TestSocketIsSkippedThroughTheBinary(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Dir("work", 0o755).Text("work/f.txt", 0o644, "x").Socket("work/sock")
	archive := filepath.Join(t.TempDir(), "s.eictar")

	create := testutil.Run(t, tree.Root, "-cf", archive, "work")
	if create.ExitCode != exitOK || !strings.Contains(create.Stderr, "socket ignored") {
		t.Errorf("create: exit %d, stderr %q; want success and a notice that the socket was ignored",
			create.ExitCode, create.Stderr)
	}
	if list := testutil.Run(t, tree.Root, "-tf", archive).Stdout; strings.Contains(list, "sock") {
		t.Errorf("the socket was archived:\n%s", list)
	}
}

// TestLongListingShowsMetadata: owner, codec, special bits and link targets.
func TestLongListingShowsMetadata(t *testing.T) {
	tree := metadataFixture(t)
	archive := filepath.Join(t.TempDir(), "meta.eictar")
	if res := testutil.Run(t, tree.Root, "-cf", archive, "work"); res.ExitCode != exitOK {
		t.Fatalf("create: exit %d", res.ExitCode)
	}

	res := testutil.Run(t, tree.Root, "-tf", archive, "--long")
	if res.ExitCode != exitOK {
		t.Fatalf("list: exit %d (stderr: %s)", res.ExitCode, res.Stderr)
	}
	for _, want := range []string{
		"-rwsr-xr-x",        // setuid shown
		"prw-------",        // a pipe
		"link -> attrs.txt", // a symlink's target
		// Names are walked in order, so work/alias is met first and holds
		// the content; work/private/data is the link.
		"work/private/data link to work/alias",
		"zstd", // the codec
		"/",    // owner as name/group
	} {
		if !strings.Contains(res.Stdout, want) {
			t.Errorf("long listing does not contain %q:\n%s", want, res.Stdout)
		}
	}
}

// TestExcludeThroughTheBinary covers --exclude and -X together.
func TestExcludeThroughTheBinary(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Text("work/keep.txt", 0o644, "keep").
		Text("work/secret.key", 0o600, "secret").
		Text("work/build/out.o", 0o644, "object")
	excludes := filepath.Join(t.TempDir(), "excludes")
	if err := os.WriteFile(excludes, []byte("work/build\n\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	archive := filepath.Join(t.TempDir(), "a.eictar")
	if res := testutil.Run(t, tree.Root, "-cf", archive, "--exclude", "*.key", "-X", excludes, "work"); res.ExitCode != exitOK {
		t.Fatalf("create: exit %d (stderr: %s)", res.ExitCode, res.Stderr)
	}
	list := testutil.Run(t, tree.Root, "-tf", archive)
	if strings.Contains(list.Stdout, "secret.key") || strings.Contains(list.Stdout, "build") {
		t.Errorf("excluded paths were archived:\n%s", list.Stdout)
	}
	if !strings.Contains(list.Stdout, "keep.txt") {
		t.Errorf("a kept path is missing:\n%s", list.Stdout)
	}
}

// TestRootOnlyOptionsRefusedForUsers: a clear refusal, exit 2, before any
// file is touched.
func TestRootOnlyOptionsRefusedForUsers(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("needs an ordinary user; this run is root")
	}
	res := testutil.Run(t, t.TempDir(), "-xf", "whatever.eictar", "--preserve-owner")
	if res.ExitCode != exitUsage {
		t.Errorf("exit %d, want %d (stderr: %s)", res.ExitCode, exitUsage, res.Stderr)
	}
	if !strings.Contains(res.Stderr, "needs root") {
		t.Errorf("stderr = %q, want it to say the option needs root", res.Stderr)
	}
}

// TestListingLevels: -t prints paths, -tv (or --long) the long listing with
// the stored size, the percentage saved and the codec, and -tvv adds chunks,
// sealing, the digest and a totals line (doc/design.md 10.9). --json carries
// all of it.
func TestListingLevels(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Dir("d", 0o755).
		Text("d/text.txt", 0o644, strings.Repeat("hello world ", 20000)).
		Symlink("d/link", "text.txt")
	archive := filepath.Join(t.TempDir(), "a.eictar")
	if res := testutil.Run(t, tree.Root, "-cf", archive, "--compress", "zstd:level=3", "d"); res.ExitCode != exitOK {
		t.Fatalf("create: %s", res.Stderr)
	}

	plain := testutil.Run(t, tree.Root, "-tf", archive).Stdout
	if plain != "d\nd/link\nd/text.txt\n" {
		t.Errorf("-t = %q, want the paths alone", plain)
	}

	long := testutil.Run(t, tree.Root, "-tvf", archive).Stdout
	if again := testutil.Run(t, tree.Root, "-tf", archive, "--long").Stdout; again != long {
		t.Errorf("--long and -tv differ:\n%s\n%s", again, long)
	}
	var textLine string
	for _, line := range strings.Split(long, "\n") {
		if strings.HasSuffix(line, " d/text.txt") {
			textLine = line
		}
	}
	f := strings.Fields(textLine)
	// mode owner size stored saved codec date time path
	if len(f) != 9 || f[2] != "240000" || f[5] != "zstd:level=3" || !strings.HasSuffix(f[4], "%") {
		t.Fatalf("-tv line for d/text.txt = %q", textLine)
	}
	if f[3] == f[2] {
		t.Errorf("text that compresses well shows no saving: %q", textLine)
	}
	if !strings.Contains(long, "  d/link -> text.txt\n") {
		t.Errorf("-tv does not show the link: %s", long)
	}

	detail := testutil.Run(t, tree.Root, "-tvvf", archive).Stdout
	lines := strings.Split(strings.TrimSpace(detail), "\n")
	if last := lines[len(lines)-1]; !strings.HasPrefix(last, "3 listed, 1 file, 240000 bytes stored in ") ||
		!strings.Contains(last, "generation 1, 0 tombstoned") {
		t.Errorf("-tvv totals line = %q", last)
	}

	js := testutil.Run(t, tree.Root, "-tf", archive, "--json").Stdout
	var members []map[string]any
	if err := json.Unmarshal([]byte(js), &members); err != nil {
		t.Fatal(err)
	}
	for _, m := range members {
		if m["path"] != "d/text.txt" {
			continue
		}
		for _, key := range []string{"codec", "stored_size", "chunks", "encrypted", "digest"} {
			if _, ok := m[key]; !ok {
				t.Errorf("--json has no %q for a file: %v", key, m)
			}
		}
		if c, _ := m["codec"].(map[string]any); c["name"] != "zstd" {
			t.Errorf("codec = %v", m["codec"])
		}
	}
}
