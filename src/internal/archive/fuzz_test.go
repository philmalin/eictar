package archive

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/philmalin/eictar/src/internal/crypt"
	"github.com/philmalin/eictar/src/internal/format"
	"github.com/philmalin/eictar/src/internal/fsutil"
	"github.com/philmalin/eictar/tools/ectread/compare"
	"github.com/philmalin/eictar/tools/ectread/ect"
)

// The fuzz target of step 4 (doc/testing.md 5): changed copies of the
// golden archives, listed, verified and extracted into a temporary root.

// fuzzGolden is a golden archive, and the fingerprint of the content of each
// prefix of it that opens: each generation, when a cut falls on its end.
type fuzzGolden struct {
	data     []byte
	contents map[string]bool
}

var (
	fuzzGoldens     []fuzzGolden
	fuzzGoldensOnce sync.Once
	fuzzGoldensErr  error
)

// fuzzOpen opens each golden archive: a passphrase is there when one is
// needed, and only then asked for.
var fuzzOpen = OpenOptions{Passphrase: passphrase("golden")}

func loadFuzzGoldens(dir string) ([]fuzzGolden, error) {
	var out []fuzzGolden
	for _, name := range []string{"plain.ect", "encrypted.ect", "dict.ect", "shared.ect"} {
		data, err := os.ReadFile(filepath.Join(goldenDir, name))
		if err != nil {
			return nil, err
		}
		g := fuzzGolden{data: data, contents: map[string]bool{}}
		for n := 1; n <= len(data); n++ {
			path := filepath.Join(dir, fmt.Sprintf("%s.%d", name, n))
			if err := os.WriteFile(path, data[:n], 0o600); err != nil {
				return nil, err
			}
			if _, err := Info(path, fuzzOpen); err != nil {
				os.Remove(path)
				continue
			}
			fp, err := extractFingerprint(path, filepath.Join(dir, "x"))
			if err != nil {
				return nil, fmt.Errorf("%s cut at %d opens, and does not extract: %w", name, n, err)
			}
			g.contents[fp] = true
			os.Remove(path)
		}
		if len(g.contents) == 0 {
			return nil, fmt.Errorf("%s gives no content", name)
		}
		out = append(out, g)
	}
	return out, nil
}

// extractFingerprint extracts archive into dest, which it makes empty
// first, and returns the fingerprint of what came out.
func extractFingerprint(archive, dest string) (string, error) {
	if err := os.RemoveAll(dest); err != nil {
		return "", err
	}
	if _, err := Extract(ExtractConfig{Archive: archive, Destination: dest, Passphrase: fuzzOpen.Passphrase, Workers: 1}); err != nil {
		return "", err
	}
	return treeFingerprint(dest)
}

// treeFingerprint is a digest of each path under root, with its type and its
// content or link target.
func treeFingerprint(root string) (string, error) {
	var lines []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		line := filepath.ToSlash(rel) + " " + d.Type().String()
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			line += " -> " + target
		case d.Type().IsRegular():
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			line += fmt.Sprintf(" %x", sha256.Sum256(b))
		}
		lines = append(lines, line)
		return nil
	})
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return fmt.Sprintf("%x", sum), err
}

// untrusted reports an error that a damaged or hostile archive may give:
// exit 3, or exit 4 for a key derivation that this machine refuses.
func untrusted(err error) bool {
	if IsDamage(err) {
		return true
	}
	for _, e := range []error{format.ErrUnsupportedVersion, fsutil.ErrUnsafePath, ErrUnsafeLink,
		crypt.ErrWrongPassphrase, ErrNotEncrypted} {
		if errors.Is(err, e) {
			return true
		}
	}
	return strings.Contains(err.Error(), "deriving the key needs")
}

// FuzzArchive changes a golden archive, then lists, verifies and extracts
// it. Each operation ends with an error of a damaged archive, or with
// success. A success of the extraction gives the content of a generation of
// a golden archive exactly, and verify and extraction agree. Nothing is
// written outside the root of the extraction, and nothing panics.
func FuzzArchive(f *testing.F) {
	fuzzGoldensOnce.Do(func() {
		dir, err := os.MkdirTemp("", "fuzz-goldens-")
		if err != nil {
			fuzzGoldensErr = err
			return
		}
		defer os.RemoveAll(dir)
		fuzzGoldens, fuzzGoldensErr = loadFuzzGoldens(dir)
	})
	if fuzzGoldensErr != nil {
		f.Fatal(fuzzGoldensErr)
	}
	// Each content that a generation of a golden archive has. The input is
	// bytes alone: the fuzzer changes one golden archive into another as
	// well, and the header of a plain archive is not authenticated.
	contents := map[string]bool{}
	for _, g := range fuzzGoldens {
		f.Add(g.data)
		for fp := range g.contents {
			contents[fp] = true
		}
	}
	saved := kdfMemory
	// A changed crypto header can ask for up to 4 GiB: refuse above 16 MiB.
	kdfMemory = func() int64 { return 32 << 20 }
	f.Cleanup(func() { kdfMemory = saved })

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<16 {
			return
		}
		dir := t.TempDir()
		path := filepath.Join(dir, "a.ect")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		check := func(op string, err error) {
			t.Helper()
			if err != nil && !untrusted(err) {
				t.Fatalf("%s: %v: not the error of a damaged archive", op, err)
			}
		}
		_, err := ListArchive(ListConfig{Archive: path, Passphrase: fuzzOpen.Passphrase})
		check("list", err)
		_, verifyErr := VerifyArchive(VerifyConfig{Archive: path, Open: fuzzOpen, Workers: 1})
		check("verify", verifyErr)
		root := filepath.Join(dir, "root")
		fp, extractErr := extractFingerprint(path, root)
		check("extract", extractErr)

		if (verifyErr == nil) != (extractErr == nil) {
			t.Fatalf("verify %v, extract %v: they disagree", verifyErr, extractErr)
		}
		if err := secondReaderAgrees(path, root, extractErr == nil); err != nil {
			t.Fatalf("%v\nchanged bytes from the nearest golden archive: %s", err, changedBytes(nearest(data), data))
		}
		if extractErr == nil && !contents[fp] {
			t.Fatalf("the extraction succeeded with content that no generation of a golden archive has\nchanged bytes from the nearest golden archive: %s\nextracted:\n%s",
				changedBytes(nearest(data), data), treeListing(root))
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.Name() != "a.ect" && e.Name() != "root" {
				t.Fatalf("%s was written outside the root", e.Name())
			}
		}
	})
}

// changedBytes says where data differs from the golden archive, for a
// report.
func changedBytes(golden, data []byte) string {
	var out []string
	for i := 0; i < max(len(golden), len(data)) && len(out) < 20; i++ {
		switch {
		case i >= len(data):
			out = append(out, fmt.Sprintf("cut at %d of %d", len(data), len(golden)))
			i = len(golden)
		case i >= len(golden):
			out = append(out, fmt.Sprintf("%d bytes added after %d", len(data)-len(golden), len(golden)))
			i = len(data)
		case golden[i] != data[i]:
			out = append(out, fmt.Sprintf("%d: %#02x -> %#02x", i, golden[i], data[i]))
		}
	}
	return strings.Join(out, ", ")
}

// treeListing lists what is under root, for a report.
func treeListing(root string) string {
	var lines []string
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		line := "  " + filepath.ToSlash(rel) + " " + d.Type().String()
		if d.Type().IsRegular() {
			b, _ := os.ReadFile(p)
			line += fmt.Sprintf(" %q", b)
		} else if d.Type()&fs.ModeSymlink != 0 {
			target, _ := os.Readlink(p)
			line += " -> " + target
		}
		lines = append(lines, line)
		return nil
	})
	return strings.Join(lines, "\n")
}

// nearest is the golden archive that data differs from in the fewest bytes,
// for a report.
func nearest(data []byte) []byte {
	best, bestDiff := fuzzGoldens[0].data, -1
	for _, g := range fuzzGoldens {
		diff := max(len(g.data), len(data)) - min(len(g.data), len(data))
		for i := range min(len(g.data), len(data)) {
			if g.data[i] != data[i] {
				diff++
			}
		}
		if bestDiff < 0 || diff < bestDiff {
			best, bestDiff = g.data, diff
		}
	}
	return best
}

// secondReaderAgrees runs the second reader (doc/testing.md 5, step 2) on
// the archive at path. It must read each member when eictar extracted the
// archive into root, with the content that eictar extracted, and refuse the
// archive when eictar refused it. As for eictar, the passphrase is given only
// to an encrypted archive.
func secondReaderAgrees(path, root string, eictarAccepts bool) error {
	opt := ect.Options{MaxKDFMemoryKiB: 16 << 10}
	a, err := ect.Open(path, opt)
	if errors.Is(err, ect.ErrNeedPassphrase) {
		opt.Passphrase = []byte("golden")
		a, err = ect.Open(path, opt)
	}
	if err == nil {
		defer a.Close()
		if eictarAccepts {
			err = compare.Tree(a, root)
		} else {
			for _, m := range a.Live() {
				if m.Type == "reg" || m.Type == "hardlink" {
					if err = a.Content(m, io.Discard); err != nil {
						break
					}
				}
			}
		}
	}
	switch {
	case eictarAccepts && err != nil:
		return fmt.Errorf("eictar extracts the archive, and the second reader: %w", err)
	case !eictarAccepts && err == nil:
		return errors.New("eictar refuses the archive, and the second reader reads each member")
	}
	return nil
}
