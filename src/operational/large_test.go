//go:build operational && unix

package operational

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/philmalin/eictar/src/internal/testutil"
)

// largeEnv enables TestLargeArchive. Its value is the size of the large
// file in GiB: 4 or more crosses 2^32 (make large). The test needs disk
// space of approximately four times that size in TMPDIR.
const largeEnv = "EICTAR_TEST_LARGE"

// TestLargeArchive takes an archive past 4 GiB through each operation that
// reads or writes an offset or a length (doc/design.md 13.2). The format
// stores them as CBOR uints, which take 8 bytes above 2^32. A fault that
// keeps 32 bits of one appears only in an archive of this size:
//
//   - big.bin is one member larger than 2^32 bytes.
//   - The blob of z-after.bin starts after big.bin, past 2^32.
//   - sparse.bin has data segments on both sides of 2^32, and in one
//     segment that crosses it. Its holes cost no disk space.
//   - The index starts past 2^32. After an append, the trailer's
//     prev_index_offset is past 2^32 too.
//
// The data is random and the codec is none, so the archive is as large as
// the data. Each step is checked: the listing's sizes, --verify, a full
// extraction, -O, --diff, an append, a crash and --repair, a delete and
// --compact.
func TestLargeArchive(t *testing.T) {
	gib := largeSize(t)
	for _, encrypted := range []bool{false, true} {
		name := map[bool]string{false: "plain", true: "encrypted"}[encrypted]
		t.Run(name, func(t *testing.T) { largeLifecycle(t, gib, encrypted) })
	}
}

// largeSize reads largeEnv. The test is skipped when it is not set.
func largeSize(t *testing.T) int64 {
	v := os.Getenv(largeEnv)
	if v == "" {
		t.Skipf("set %s to the size in GiB (4 or more crosses 2^32), or run make large", largeEnv)
	}
	gib, err := strconv.ParseInt(v, 10, 64)
	if err != nil || gib < 1 || gib > 64 {
		t.Fatalf("%s=%q: want a size in GiB from 1 to 64", largeEnv, v)
	}
	if gib < 4 {
		t.Logf("%s=%d: the archive stays below 2^32, so this run does not test the large offsets", largeEnv, gib)
	}
	return gib
}

func largeLifecycle(t *testing.T, gib int64, encrypted bool) {
	// Not on a whole MiB, so the last chunk is short.
	bigSize := gib<<30 + 1<<20 + 17
	needSpace(t, 4*bigSize+1<<30)

	tree := testutil.NewTree(t)
	writeRandom(t, tree.Path("big.bin"), bigSize, 1)
	tree.File("z-after.bin", 0o644, randomBytes(3<<20+5, 2))
	const sparseSize = 8 << 30
	tree.Sparse("sparse.bin", 0o644, sparseSize,
		testutil.Segment{Offset: 0, Data: randomBytes(4096, 3)},
		testutil.Segment{Offset: 1<<32 - 2048, Data: randomBytes(4096, 4)},
		testutil.Segment{Offset: 1<<32 + 1<<20, Data: randomBytes(65536, 5)},
		testutil.Segment{Offset: sparseSize - 100, Data: randomBytes(100, 6)})
	files := []string{"big.bin", "sparse.bin", "z-after.bin"}
	sizes := map[string]int64{"big.bin": bigSize, "sparse.bin": sparseSize, "z-after.bin": 3<<20 + 5}
	digests := map[string][32]byte{}
	for _, f := range files {
		digests[f] = fileDigest(t, tree.Path(f))
	}

	archive := filepath.Join(t.TempDir(), "large.ect")
	var key []string
	if encrypted {
		key = []string{"--passphrase-file", passFile(t, "correct horse")}
	}
	with := func(args ...string) []string { return append(args, key...) }

	create := []string{"-cf", archive, "--compress", "none"}
	if encrypted {
		create = append(create, "-e", "--encrypt-index", "--kdf-memory", "8192", "--kdf-time", "1")
	}
	runOK(t, tree.Root, with(append(create, files...)...)...)
	if size := fileSize(t, archive); gib >= 4 && size <= 1<<32 {
		t.Fatalf("the archive has %d bytes, want more than 2^32", size)
	}

	// extractAll extracts the archive, and compares each file with its
	// source: size and SHA-256. Then it removes the copy, for the space.
	extractAll := func(want []string) {
		t.Helper()
		dest := filepath.Join(t.TempDir(), "out")
		runOK(t, tree.Root, with("-xf", archive, "-d", dest)...)
		got := listDir(t, dest)
		if strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("extracted %q, want %q", got, want)
		}
		for _, f := range want {
			p := filepath.Join(dest, f)
			if size := fileSize(t, p); size != sizes[f] {
				t.Errorf("%s: extracted %d bytes, want %d", f, size, sizes[f])
			} else if fileDigest(t, p) != digests[f] {
				t.Errorf("%s: the extracted content differs from the source", f)
			}
		}
		if err := os.RemoveAll(dest); err != nil {
			t.Fatal(err)
		}
	}
	// check lists the members with their sizes, and verifies the archive.
	check := func(want []string) {
		t.Helper()
		res := runOK(t, tree.Root, with("-tf", archive, "--json")...)
		var members []struct {
			Path string `json:"path"`
			Size int64  `json:"size"`
		}
		if err := json.Unmarshal([]byte(res.Stdout), &members); err != nil {
			t.Fatalf("the listing is not JSON: %v", err)
		}
		var got []string
		for _, m := range members {
			got = append(got, m.Path)
			if m.Size != sizes[m.Path] {
				t.Errorf("%s: the listing gives %d bytes, want %d", m.Path, m.Size, sizes[m.Path])
			}
		}
		if strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("the listing has %q, want %q", got, want)
		}
		runOK(t, tree.Root, with("--verify", "-q", "-f", archive)...)
	}

	check(files)
	extractAll(files)

	// -O reads one member: the one whose blob starts past 2^32.
	res := runOK(t, tree.Root, with("-xOf", archive, "z-after.bin")...)
	if sha256.Sum256([]byte(res.Stdout)) != digests["z-after.bin"] {
		t.Error("-O z-after.bin: the content differs from the source")
	}

	res = testutil.Run(t, tree.Root, with("--diff", "-f", archive)...)
	if res.ExitCode != exitOK || !strings.Contains(res.Stdout, "no differences") {
		t.Errorf("--diff of the source: exit %d\nstdout: %s\nstderr: %s", res.ExitCode, res.Stdout, res.Stderr)
	}

	// An append: a blob, an index and a prev_index_offset past 2^32.
	tree.File("z-appended.bin", 0o644, randomBytes(1<<20+3, 7))
	sizes["z-appended.bin"] = 1<<20 + 3
	digests["z-appended.bin"] = fileDigest(t, tree.Path("z-appended.bin"))
	runOK(t, tree.Root, with("-rf", archive, "z-appended.bin")...)
	files = append(files, "z-appended.bin")
	check(files)
	dest := filepath.Join(t.TempDir(), "appended")
	runOK(t, tree.Root, with("-xf", archive, "-d", dest, "z-appended.bin")...)
	if fileDigest(t, filepath.Join(dest, "z-appended.bin")) != digests["z-appended.bin"] {
		t.Error("z-appended.bin: the extracted content differs from the source")
	}

	// A crash in the next append: --repair must give back the archive of
	// before, byte for byte.
	beforeSize, beforeDigest := fileSize(t, archive), fileDigest(t, archive)
	tree.File("z-crash.bin", 0o644, randomBytes(2<<20, 8))
	runOK(t, tree.Root, with("-rf", archive, "z-crash.bin")...)
	grown := fileSize(t, archive) - beforeSize
	if grown < 2 {
		t.Fatalf("the append grew the archive by %d bytes", grown)
	}
	if err := os.Truncate(archive, beforeSize+grown/2); err != nil {
		t.Fatal(err)
	}
	res = testutil.Run(t, tree.Root, with("-tf", archive)...)
	if res.ExitCode != exitCorrupt || !strings.Contains(res.Stderr, "--repair") {
		t.Fatalf("list of a torn archive: exit %d, stderr %q; want exit %d naming --repair",
			res.ExitCode, res.Stderr, exitCorrupt)
	}
	runOK(t, tree.Root, with("--repair", "-f", archive)...)
	if fileSize(t, archive) != beforeSize || fileDigest(t, archive) != beforeDigest {
		t.Fatal("--repair did not give back the archive of before the append")
	}

	// A delete, then --compact: every offset moves.
	runOK(t, tree.Root, with("--delete", "-f", archive, "z-after.bin")...)
	runOK(t, tree.Root, with("--compact", "-f", archive)...)
	files = []string{"big.bin", "sparse.bin", "z-appended.bin"}
	check(files)
	extractAll(files)
}

// needSpace fails the test when TMPDIR has less than n bytes free. Without
// the check, a full disk shows as a fault of eictar, late in the run.
func needSpace(t *testing.T, n int64) {
	t.Helper()
	free, err := testutil.FreeSpace(os.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if free < n {
		t.Fatalf("%s has %d GiB free; this test needs %d GiB", os.TempDir(), free>>30, n>>30+1)
	}
}

// writeRandom writes n random bytes to p, in blocks, from a seed.
func writeRandom(t *testing.T, p string, n int64, seed byte) {
	t.Helper()
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	w := bufio.NewWriterSize(f, 1<<20)
	if _, err := io.CopyN(w, rand.NewChaCha8([32]byte{seed}), n); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// randomBytes returns n random bytes from a seed.
func randomBytes(n int, seed byte) []byte {
	b := make([]byte, n)
	rand.NewChaCha8([32]byte{seed}).Read(b)
	return b
}

// fileDigest is the SHA-256 of a file, read as a stream.
func fileDigest(t *testing.T, p string) [32]byte {
	t.Helper()
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

// listDir returns the names in a directory, sorted.
func listDir(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}
