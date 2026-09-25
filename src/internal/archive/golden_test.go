package archive

import (
	"flag"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"eictar/src/internal/testutil"
)

// updateGolden rewrites the golden archives. Run it only for a deliberate
// format change, and say so in the change: every archive already written in
// the old format stops opening.
//
//	go test ./src/internal/archive/ -run TestGolden -update-golden
var updateGolden = flag.Bool("update-golden", false, "rewrite testdata/golden")

const goldenDir = "testdata/golden"

// goldenContent is what each golden archive must give back after its history:
// a create, a replacing append and a delete.
var goldenContent = map[string]string{
	"g":           "",
	"g/keep.txt":  "kept from generation 1",
	"g/new.txt":   "added in generation 2",
	"g/edit.txt":  "edited in generation 2",
	"g/link":      "", // a symlink to keep.txt
	"g/hard.txt":  "kept from generation 1",
	"g/sub":       "",
	"g/sub/z.txt": "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
}

func writeGolden(t *testing.T, path string, encrypted bool) {
	t.Helper()
	pinned := time.Date(2026, 1, 2, 3, 4, 5, 6, time.UTC)
	tree := testutil.NewTree(t)
	tree.Dir("g", 0o755).Dir("g/sub", 0o755)
	tree.Text("g/keep.txt", 0o644, "kept from generation 1")
	tree.Text("g/edit.txt", 0o644, "generation 1 text")
	tree.Text("g/gone.txt", 0o644, "deleted in generation 3")
	tree.Text("g/sub/z.txt", 0o600, goldenContent["g/sub/z.txt"])
	tree.Symlink("g/link", "keep.txt")
	tree.Hardlink("g/hard.txt", "g/keep.txt")
	for _, p := range []string{"g/keep.txt", "g/edit.txt", "g/gone.txt", "g/sub/z.txt", "g/sub", "g"} {
		tree.SetTimes(p, pinned, pinned)
	}

	cfg := CreateConfig{
		Archive:  path,
		Paths:    []string{"g"},
		BaseDir:  tree.Root,
		Options:  Options{Codec: "zstd", ChunkSize: 16},
		Metadata: MetadataOptions{NoOwner: true, NoXattrs: true, NoACLs: true},
		Workers:  1,
	}
	if encrypted {
		cfg.Encryption = &EncryptionConfig{Passphrase: []byte("golden"), Params: testKDF, EncryptIndex: true}
	}
	if _, err := CreateArchive(cfg); err != nil {
		t.Fatal(err)
	}

	tree.Text("g/edit.txt", 0o644, "edited in generation 2")
	tree.Text("g/new.txt", 0o644, "added in generation 2")
	for _, p := range []string{"g/edit.txt", "g/new.txt"} {
		tree.SetTimes(p, pinned, pinned.Add(time.Hour))
	}
	add := cfg
	add.Encryption = nil
	add.Paths = []string{"g/edit.txt", "g/new.txt"}
	add.Options.Codec = "none"
	if _, err := AppendArchive(AppendConfig{CreateConfig: add, Open: goldenOpen(encrypted)}); err != nil {
		t.Fatal(err)
	}
	if _, err := DeleteMembers(DeleteConfig{Archive: path, Patterns: []string{"g/gone.txt"}, Open: goldenOpen(encrypted)}); err != nil {
		t.Fatal(err)
	}
}

func goldenOpen(encrypted bool) OpenOptions {
	if encrypted {
		return OpenOptions{Passphrase: passphrase("golden"), RequireEncryption: true}
	}
	return OpenOptions{}
}

// TestGolden opens archives written by an earlier build. It is the guard
// against a format change that nobody meant: the round-trip tests pass with
// any format, as long as the reader and the writer change together.
func TestGolden(t *testing.T) {
	for _, tc := range []struct {
		file      string
		encrypted bool
	}{
		{"plain.eictar", false},
		{"encrypted.eictar", true},
	} {
		t.Run(tc.file, func(t *testing.T) {
			path := filepath.Join(goldenDir, tc.file)
			if *updateGolden {
				if err := os.MkdirAll(goldenDir, 0o755); err != nil {
					t.Fatal(err)
				}
				os.Remove(path)
				writeGolden(t, path, tc.encrypted)
			}

			in, err := Info(path, goldenOpen(tc.encrypted))
			if err != nil {
				t.Fatalf("the golden archive does not open: %v", err)
			}
			if in.Trailer.Generation != 3 || in.Dead != 2 || in.Live != len(goldenContent) {
				t.Errorf("generation %d, %d live, %d dead; want 3, %d, 2",
					in.Trailer.Generation, in.Live, in.Dead, len(goldenContent))
			}
			if (in.Crypto != nil) != tc.encrypted {
				t.Errorf("encrypted = %v, want %v", in.Crypto != nil, tc.encrypted)
			}
			if _, err := VerifyArchive(VerifyConfig{Archive: path, Open: goldenOpen(tc.encrypted)}); err != nil {
				t.Errorf("verify: %v", err)
			}

			dest := t.TempDir()
			if _, err := Extract(ExtractConfig{
				Archive: path, Destination: dest,
				Passphrase: goldenOpen(tc.encrypted).Passphrase, RequireEncryption: tc.encrypted,
			}); err != nil {
				t.Fatalf("extract: %v", err)
			}
			var got []string
			filepath.Walk(filepath.Join(dest, "g"), func(p string, fi os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				rel, _ := filepath.Rel(dest, p)
				got = append(got, rel)
				want, ok := goldenContent[rel]
				switch {
				case !ok:
					t.Errorf("unexpected %s", rel)
				case fi.Mode().IsRegular():
					if b, _ := os.ReadFile(p); string(b) != want {
						t.Errorf("%s = %q, want %q", rel, b, want)
					}
				case fi.Mode()&os.ModeSymlink != 0:
					if target, _ := os.Readlink(p); target != "keep.txt" {
						t.Errorf("%s -> %q", rel, target)
					}
				}
				return nil
			})
			if len(got) != len(goldenContent) {
				sort.Strings(got)
				t.Errorf("extracted %v", got)
			}
			if a, b := mustStat(t, filepath.Join(dest, "g/keep.txt")), mustStat(t, filepath.Join(dest, "g/hard.txt")); !os.SameFile(a, b) {
				t.Error("g/hard.txt is not a hardlink of g/keep.txt")
			}
		})
	}
}
