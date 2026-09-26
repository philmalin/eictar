package archive

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/philmalin/eictar/src/internal/format"
	"github.com/philmalin/eictar/src/internal/testutil"
)

// Tests of the identical content of doc/design.md 4.3.

// copyTree has one file in three places, one other file, and a hardlink to a
// copy, which must stay a hardlink.
func copyTree(t *testing.T) *testutil.Tree {
	t.Helper()
	text := strings.Repeat("the same content in three places\n", 3000)
	tree := testutil.NewTree(t)
	tree.Dir("c", 0o755).Dir("c/a", 0o755).Dir("c/b", 0o755)
	tree.Text("c/a/f.txt", 0o644, text)
	tree.Text("c/b/f.txt", 0o600, text)
	tree.Text("c/b/g.txt", 0o644, text)
	tree.Text("c/other.txt", 0o644, "something else")
	tree.Hardlink("c/b/h.txt", "c/b/g.txt")
	return tree
}

func createWith(t *testing.T, tree *testutil.Tree, encrypted, noDedup bool, paths ...string) string {
	t.Helper()
	cfg := CreateConfig{
		Archive: filepath.Join(t.TempDir(), "c.ect"),
		Paths:   paths,
		BaseDir: tree.Root,
		Options: Options{Codec: "zstd"},
		NoDedup: noDedup,
	}
	if encrypted {
		cfg.Encryption = &EncryptionConfig{Passphrase: []byte("correct horse"), Params: testKDF}
	}
	if _, err := CreateArchive(cfg); err != nil {
		t.Fatal(err)
	}
	return cfg.Archive
}

// blobs counts the members with a blob of their own, and those that share one.
func blobs(t *testing.T, archive string, encrypted bool) (owners, sharers int) {
	t.Helper()
	for _, m := range openDict(t, archive, encrypted).index.Members {
		switch {
		case m.Data != 0:
			sharers++
		case m.Length > 0:
			owners++
		}
	}
	return owners, sharers
}

func TestCopiesShareOneBlob(t *testing.T) {
	for _, enc := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "encrypted"}[enc], func(t *testing.T) {
			tree := copyTree(t)
			archive := createWith(t, tree, enc, false, "c")
			if o, s := blobs(t, archive, enc); o != 2 || s != 2 {
				t.Errorf("%d blobs and %d sharers, want 2 and 2", o, s)
			}
			// A second name of an inode is still a hardlink, not a sharer.
			for _, m := range openDict(t, archive, enc).index.Members {
				if m.Path == "c/b/h.txt" && m.Type != format.TypeHardlink {
					t.Errorf("c/b/h.txt is a %s", m.Type)
				}
			}
			res, err := VerifyArchive(VerifyConfig{Archive: archive, Open: openFor(enc)})
			if err != nil || res.Checked != 5 {
				t.Errorf("verify: %d checked, %v; want 5 files", res.Checked, err)
			}
			checkRoundTrip(t, archive, enc, tree, "c")

			full := createWith(t, tree, enc, true, "c")
			if o, s := blobs(t, full, enc); o != 4 || s != 0 {
				t.Errorf("--no-dedup: %d blobs and %d sharers, want 4 and 0", o, s)
			}
			if a, b := mustStat(t, archive).Size(), mustStat(t, full).Size(); a >= b {
				t.Errorf("shared %d bytes, in full %d", a, b)
			}
		})
	}
}

// TestAppendSharesOldContent: a file that an earlier generation stored is
// not stored again; and an unchanged file that -u takes again shares the
// content of its own earlier version, which compact keeps.
func TestAppendSharesOldContent(t *testing.T) {
	tree := copyTree(t)
	archive := createWith(t, tree, true, false, "c/a")
	tree.Text("c/new/f.txt", 0o644, strings.Repeat("the same content in three places\n", 3000))
	if _, err := appendTo(t, archive, tree, true, nil, "c/new"); err != nil {
		t.Fatal(err)
	}
	if o, s := blobs(t, archive, true); o != 1 || s != 1 {
		t.Errorf("after the append: %d blobs and %d sharers, want 1 and 1", o, s)
	}

	tree.SetTimes("c/a/f.txt", time.Unix(7, 0), time.Unix(8, 0))
	if _, err := appendTo(t, archive, tree, true, func(c *AppendConfig) { c.UpdateMode = UpdateDifferent }, "c/a"); err != nil {
		t.Fatal(err)
	}
	if o, s := blobs(t, archive, true); o != 1 || s != 2 {
		t.Errorf("after -u: %d blobs and %d sharers, want 1 and 2", o, s)
	}
	if _, err := CompactArchive(CompactConfig{Archive: archive, Open: openFor(true)}); err != nil {
		t.Fatal(err)
	}
	r := openDict(t, archive, true)
	var dead int
	for _, m := range r.index.Members {
		if m.Dead {
			dead++
		}
	}
	if dead != 1 {
		t.Errorf("after compact: %d tombstones, want the one that holds the content", dead)
	}
	checkRoundTrip(t, archive, true, tree, "c/a")
	checkRoundTrip(t, archive, true, tree, "c/new")
}

// TestDamagedOwnerIsNotShared: an append does not make a good file share a
// blob that has become damaged since it was written (doc/design.md 4.3).
func TestDamagedOwnerIsNotShared(t *testing.T) {
	tree := copyTree(t)
	archive := createWith(t, tree, false, false, "c/a")
	var owner format.Member
	for _, m := range openDict(t, archive, false).index.Members {
		if m.Path == "c/a/f.txt" {
			owner = m
		}
	}
	b := readAll(t, archive)
	b[owner.Offset+owner.Length/2] ^= 0x10
	if err := os.WriteFile(archive, b, 0o644); err != nil {
		t.Fatal(err)
	}

	rep := &recordingReporter{}
	if _, err := appendTo(t, archive, tree, false, func(c *AppendConfig) { c.Reporter = rep }, "c/b/f.txt", "c/b/g.txt"); err != nil {
		t.Fatal(err)
	}
	if len(rep.warnings) != 1 || !strings.Contains(rep.warnings[0], "damaged") {
		t.Errorf("warnings %q, want one about the damaged copy", rep.warnings)
	}
	// Both new files are whole: one stored in full, one sharing it.
	if o, s := blobs(t, archive, false); o != 2 || s != 1 {
		t.Errorf("%d blobs and %d sharers, want 2 and 1", o, s)
	}
	for _, p := range []string{"c/b/f.txt", "c/b/g.txt"} {
		if got := extractOne(t, archive, false, p); !strings.HasPrefix(got, "the same content") {
			t.Errorf("%s: %q", p, got[:min(len(got), 20)])
		}
	}
	// The damage itself is still found.
	if _, err := VerifyArchive(VerifyConfig{Archive: archive}); !IsDamage(err) {
		t.Errorf("verify: %v, want damage", err)
	}
}

// TestSharedContentSurvivesDeleteAndRecompress: deleting the owner keeps its
// blob for the sharers, compact keeps it, and --recompress keeps the sharing.
func TestSharedContentSurvivesDeleteAndRecompress(t *testing.T) {
	tree := copyTree(t)
	archive := createWith(t, tree, false, false, "c")
	var ownerPath string
	for _, m := range openDict(t, archive, false).index.Members {
		if m.Data == 0 && m.Length > 0 && strings.HasSuffix(m.Path, ".txt") && m.Path != "c/other.txt" {
			ownerPath = m.Path
		}
	}
	if _, err := DeleteMembers(DeleteConfig{Archive: archive, Patterns: []string{ownerPath}}); err != nil {
		t.Fatal(err)
	}
	if _, err := CompactArchive(CompactConfig{Archive: archive}); err != nil {
		t.Fatal(err)
	}
	if _, err := CompactArchive(CompactConfig{Archive: archive,
		Recompress: &RecompressConfig{Codec: "xz"}}); err != nil {
		t.Fatal(err)
	}
	if o, s := blobs(t, archive, false); o != 2 || s != 2 {
		t.Errorf("%d blobs and %d sharers, want 2 and 2", o, s)
	}
	res, err := VerifyArchive(VerifyConfig{Archive: archive})
	if err != nil || res.Checked != 4 {
		t.Errorf("verify: %d checked, %v; want the 4 live files", res.Checked, err)
	}
	dest := t.TempDir()
	if _, err := Extract(ExtractConfig{Archive: archive, Destination: dest}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"c/a/f.txt", "c/b/f.txt", "c/b/g.txt", "c/b/h.txt"} {
		if p == ownerPath {
			continue
		}
		if b, err := os.ReadFile(filepath.Join(dest, p)); err != nil || !strings.HasPrefix(string(b), "the same content") {
			t.Errorf("%s: %v", p, err)
		}
	}
}

// TestInfoCountsSharedContent: --info gives the sharers and what they saved.
func TestInfoCountsSharedContent(t *testing.T) {
	archive := createWith(t, copyTree(t), false, false, "c")
	in, err := Info(archive, OpenOptions{})
	if err != nil || in.Shared != 2 || in.NotStored == 0 {
		t.Errorf("info: %d shared, %d not stored, %v", in.Shared, in.NotStored, err)
	}
}
