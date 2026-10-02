package archive

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"lukechampine.com/blake3"

	"github.com/philmalin/eictar/src/internal/codec"
	"github.com/philmalin/eictar/src/internal/crypt"
	"github.com/philmalin/eictar/src/internal/format"
	"github.com/philmalin/eictar/src/internal/fsutil"
	"github.com/philmalin/eictar/src/internal/meta"
	"github.com/philmalin/eictar/src/internal/testutil"
)

// mutTree is a small tree for the mutation tests: two files, a nested one,
// and a hardlink pair.
func mutTree(t *testing.T) *testutil.Tree {
	t.Helper()
	tree := testutil.NewTree(t)
	tree.Dir("t", 0o755).Dir("t/sub", 0o755)
	tree.Text("t/a.txt", 0o644, "alpha")
	tree.Text("t/b.txt", 0o644, "bravo")
	tree.Text("t/sub/c.txt", 0o644, "charlie")
	return tree
}

// mkArchive creates an archive of paths, plain or encrypted.
func mkArchive(t *testing.T, tree *testutil.Tree, encrypted bool, paths ...string) string {
	t.Helper()
	cfg := CreateConfig{
		Archive: filepath.Join(t.TempDir(), "m.ect"),
		Paths:   paths,
		BaseDir: tree.Root,
		Options: Options{Codec: "zstd", ChunkSize: 4096},
	}
	if encrypted {
		cfg.Encryption = &EncryptionConfig{Passphrase: []byte("correct horse"), Params: testKDF, EncryptIndex: true}
	}
	if _, err := CreateArchive(cfg); err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}
	return cfg.Archive
}

// openFor returns the open options for an archive made by mkArchive.
func openFor(encrypted bool) OpenOptions {
	if encrypted {
		return OpenOptions{Passphrase: passphrase("correct horse")}
	}
	return OpenOptions{}
}

func appendTo(t *testing.T, archive string, tree *testutil.Tree, encrypted bool, mod func(*AppendConfig), paths ...string) (Stats, error) {
	t.Helper()
	cfg := AppendConfig{
		CreateConfig: CreateConfig{
			Archive: archive,
			Paths:   paths,
			BaseDir: tree.Root,
			Options: Options{Codec: "zstd", ChunkSize: 4096},
		},
		Open: openFor(encrypted),
	}
	if mod != nil {
		mod(&cfg)
	}
	return AppendArchive(cfg)
}

func readAll(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// state is what a test compares: the live paths, and the count of all
// members.
func state(t *testing.T, archive string, encrypted bool) (live []string, all int, gen uint64) {
	t.Helper()
	r, err := OpenWith(archive, openFor(encrypted))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer r.Close()
	for _, m := range r.Members() {
		live = append(live, m.Path)
	}
	sort.Strings(live)
	return live, len(r.AllMembers()), r.Trailer().Generation
}

func extractOne(t *testing.T, archive string, encrypted bool, member string) string {
	t.Helper()
	dest := t.TempDir()
	if _, err := Extract(ExtractConfig{
		Archive: archive, Destination: dest, Patterns: []string{member},
		Passphrase: openFor(encrypted).Passphrase,
	}); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	return string(readAll(t, filepath.Join(dest, member)))
}

func TestAppendAddsAGenerationAfterTheOldTrailer(t *testing.T) {
	for _, enc := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "encrypted"}[enc], func(t *testing.T) {
			tree := mutTree(t)
			archive := mkArchive(t, tree, enc, "t/a.txt")
			before := readAll(t, archive)

			stats, err := appendTo(t, archive, tree, enc, nil, "t/b.txt")
			if err != nil {
				t.Fatalf("append: %v", err)
			}
			if stats.Members != 1 || stats.Replaced != 0 {
				t.Errorf("stats = %+v, want 1 member and no replacement", stats)
			}

			after := readAll(t, archive)
			if !bytes.HasPrefix(after, before) {
				t.Fatal("the append changed bytes of the old generation, the old trailer included")
			}
			live, all, gen := state(t, archive, enc)
			if want := []string{"t/a.txt", "t/b.txt"}; !equalStrings(live, want) || all != 2 || gen != 2 {
				t.Errorf("live=%v all=%d gen=%d, want %v, 2, 2", live, all, gen, want)
			}
			if got := extractOne(t, archive, enc, "t/b.txt"); got != "bravo" {
				t.Errorf("t/b.txt = %q", got)
			}
		})
	}
}

func TestAppendReplacesByDefault(t *testing.T) {
	tree := mutTree(t)
	archive := mkArchive(t, tree, false, "t")
	tree.Text("t/a.txt", 0o644, "alpha, second edition")

	stats, err := appendTo(t, archive, tree, false, nil, "t/a.txt")
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if stats.Replaced != 1 {
		t.Errorf("replaced = %d, want 1", stats.Replaced)
	}
	live, all, _ := state(t, archive, false)
	count := 0
	for _, p := range live {
		if p == "t/a.txt" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("t/a.txt is live %d times, want once: %v", count, live)
	}
	if all != len(live)+1 {
		t.Errorf("all = %d, want one tombstone beside %d live", all, len(live))
	}
	if got := extractOne(t, archive, false, "t/a.txt"); got != "alpha, second edition" {
		t.Errorf("t/a.txt = %q, want the new content", got)
	}
}

func TestOnConflictSkipAndError(t *testing.T) {
	tree := mutTree(t)
	archive := mkArchive(t, tree, false, "t/a.txt")
	before := readAll(t, archive)

	stats, err := appendTo(t, archive, tree, false, func(c *AppendConfig) { c.OnConflict = ConflictSkip }, "t/a.txt")
	if err != nil {
		t.Fatalf("skip: %v", err)
	}
	if stats.Skipped != 1 || stats.Members != 0 {
		t.Errorf("skip stats = %+v", stats)
	}
	if !bytes.Equal(readAll(t, archive), before) {
		t.Error("a run that added nothing changed the file")
	}

	// error: the new path b would be fine, but a conflicts, so nothing lands.
	_, err = appendTo(t, archive, tree, false, func(c *AppendConfig) { c.OnConflict = ConflictError }, "t/b.txt", "t/a.txt")
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("error mode: got %v, want ErrConflict", err)
	}
	if !bytes.Equal(readAll(t, archive), before) {
		t.Error("a refused append changed the file")
	}
}

func TestPathNamedTwiceIsArchivedOnce(t *testing.T) {
	tree := mutTree(t)
	rep := &recordingReporter{}
	archive := filepath.Join(t.TempDir(), "d.ect")
	if _, err := CreateArchive(CreateConfig{
		Archive: archive, Paths: []string{"t/a.txt", "t"}, BaseDir: tree.Root,
		Options: Options{Codec: "zstd"}, Reporter: rep,
	}); err != nil {
		t.Fatal(err)
	}
	live, all, _ := state(t, archive, false)
	if all != len(live) {
		t.Fatalf("tombstones in a new archive: %d members, %d live", all, len(live))
	}
	seen := map[string]bool{}
	for _, p := range live {
		if seen[p] {
			t.Fatalf("%s is live twice", p)
		}
		seen[p] = true
	}
	if len(rep.warnings) != 1 {
		t.Errorf("warnings = %q, want one notice", rep.warnings)
	}
}

func TestUpdateModes(t *testing.T) {
	old := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	older := old.Add(-time.Hour)

	for _, tc := range []struct {
		name    string
		mode    string
		change  func(tree *testutil.Tree)
		replace bool
	}{
		{"newer skips an unchanged file", UpdateNewer, func(*testutil.Tree) {}, false},
		{"newer takes a newer file", UpdateNewer, func(tr *testutil.Tree) {
			tr.SetTimes("t/a.txt", old, old.Add(time.Hour))
		}, true},
		{"newer misses a restored older file", UpdateNewer, func(tr *testutil.Tree) {
			tr.Text("t/a.txt", 0o644, "restored").SetTimes("t/a.txt", older, older)
		}, false},
		{"different finds the restored file", UpdateDifferent, func(tr *testutil.Tree) {
			tr.Text("t/a.txt", 0o644, "restored").SetTimes("t/a.txt", older, older)
		}, true},
		{"different takes a touch", UpdateDifferent, func(tr *testutil.Tree) {
			tr.SetTimes("t/a.txt", old, old.Add(time.Second))
		}, true},
		{"digest ignores a touch", UpdateDigest, func(tr *testutil.Tree) {
			tr.SetTimes("t/a.txt", old, old.Add(time.Second))
		}, false},
		{"digest finds same-size, same-time content", UpdateDigest, func(tr *testutil.Tree) {
			tr.Text("t/a.txt", 0o644, "ALPHA").SetTimes("t/a.txt", old, old)
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := mutTree(t)
			tree.SetTimes("t/a.txt", old, old)
			archive := mkArchive(t, tree, false, "t/a.txt")
			tc.change(tree)

			stats, err := appendTo(t, archive, tree, false, func(c *AppendConfig) { c.UpdateMode = tc.mode }, "t/a.txt")
			if err != nil {
				t.Fatalf("update: %v", err)
			}
			if got := stats.Replaced == 1; got != tc.replace {
				t.Errorf("replaced = %v, want %v (stats %+v)", got, tc.replace, stats)
			}
			if !tc.replace && stats.Unchanged != 1 {
				t.Errorf("unchanged = %d, want 1", stats.Unchanged)
			}
		})
	}
}

func TestUpdateAddsNewPaths(t *testing.T) {
	tree := mutTree(t)
	archive := mkArchive(t, tree, false, "t/a.txt")
	stats, err := appendTo(t, archive, tree, false, func(c *AppendConfig) { c.UpdateMode = UpdateNewer }, "t/a.txt", "t/b.txt")
	if err != nil {
		t.Fatal(err)
	}
	if stats.Members != 1 || stats.Unchanged != 1 {
		t.Errorf("stats = %+v, want b added and a unchanged", stats)
	}
}

func TestDelete(t *testing.T) {
	tree := mutTree(t)
	archive := mkArchive(t, tree, false, "t")
	before := readAll(t, archive)

	if _, err := DeleteMembers(DeleteConfig{Archive: archive, Patterns: []string{"t/sub", "nope"}}); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("got %v, want ErrNoMatch", err)
	}
	if !bytes.Equal(readAll(t, archive), before) {
		t.Fatal("a refused delete changed the file")
	}

	stats, err := DeleteMembers(DeleteConfig{Archive: archive, Patterns: []string{"t/sub"}})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Members != 2 {
		t.Errorf("deleted %d, want the directory and its file", stats.Members)
	}
	live, _, gen := state(t, archive, false)
	if want := []string{"t", "t/a.txt", "t/b.txt"}; !equalStrings(live, want) || gen != 2 {
		t.Errorf("live = %v gen = %d, want %v, 2", live, gen, want)
	}
}

// TestHardlinkToATombstone is doc/design.md 9.2: replacing one name of a
// hardlink pair must not take the content from the other name, before or
// after a compact.
func TestHardlinkToATombstone(t *testing.T) {
	for _, enc := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "encrypted"}[enc], func(t *testing.T) {
			tree := mutTree(t)
			tree.Hardlink("t/link.txt", "t/a.txt") // sorted walk: a.txt holds the content
			archive := mkArchive(t, tree, enc, "t")

			if err := os.Remove(tree.Path("t/a.txt")); err != nil {
				t.Fatal(err)
			}
			tree.Text("t/a.txt", 0o644, "a new alpha")
			if _, err := appendTo(t, archive, tree, enc, nil, "t/a.txt"); err != nil {
				t.Fatal(err)
			}

			check := func(stage string) {
				if got := extractOne(t, archive, enc, "t/link.txt"); got != "alpha" {
					t.Errorf("%s: t/link.txt = %q, want the old content", stage, got)
				}
				if got := extractOne(t, archive, enc, "t/a.txt"); got != "a new alpha" {
					t.Errorf("%s: t/a.txt = %q", stage, got)
				}
				if _, err := VerifyArchive(VerifyConfig{Archive: archive, Open: openFor(enc)}); err != nil {
					t.Errorf("%s: verify: %v", stage, err)
				}
			}
			check("before compact")

			res, err := CompactArchive(CompactConfig{Archive: archive, Open: openFor(enc)})
			if err != nil {
				t.Fatal(err)
			}
			if res.Dropped != 0 {
				t.Errorf("compact dropped %d members; the tombstone behind the link must stay", res.Dropped)
			}
			check("after compact")
		})
	}
}

func TestCompact(t *testing.T) {
	for _, enc := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "encrypted"}[enc], func(t *testing.T) {
			tree := mutTree(t)
			archive := mkArchive(t, tree, enc, "t")
			tree.Text("t/a.txt", 0o644, "alpha again")
			if _, err := appendTo(t, archive, tree, enc, nil, "t/a.txt"); err != nil {
				t.Fatal(err)
			}
			if _, err := DeleteMembers(DeleteConfig{Archive: archive, Patterns: []string{"t/b.txt"}, Open: openFor(enc)}); err != nil {
				t.Fatal(err)
			}
			liveBefore, _, genBefore := state(t, archive, enc)
			uuidBefore := headerOf(t, archive).ArchiveUUID
			if err := os.Chmod(archive, 0o640); err != nil {
				t.Fatal(err)
			}

			res, err := CompactArchive(CompactConfig{Archive: archive, Open: openFor(enc)})
			if err != nil {
				t.Fatalf("compact: %v", err)
			}
			if res.NewSize >= res.OldSize || res.Dropped != 2 {
				t.Errorf("result = %+v, want a smaller file and 2 dropped", res)
			}
			if fi := mustStat(t, archive); fi.Size() != res.NewSize || fi.Mode().Perm() != 0o640 {
				t.Errorf("file size %d mode %v, want %d and 0640", fi.Size(), fi.Mode().Perm(), res.NewSize)
			}
			live, all, gen := state(t, archive, enc)
			if !equalStrings(live, liveBefore) || all != len(live) || gen != genBefore+1 {
				t.Errorf("live=%v all=%d gen=%d; want %v, no tombstones, gen %d", live, all, gen, liveBefore, genBefore+1)
			}
			if headerOf(t, archive).ArchiveUUID != uuidBefore {
				t.Error("compact changed the uuid; every sealed blob would be lost")
			}
			if got := extractOne(t, archive, enc, "t/a.txt"); got != "alpha again" {
				t.Errorf("t/a.txt = %q", got)
			}
			if _, err := VerifyArchive(VerifyConfig{Archive: archive, Open: openFor(enc)}); err != nil {
				t.Errorf("verify after compact: %v", err)
			}
			entries, _ := os.ReadDir(filepath.Dir(archive))
			if len(entries) != 1 {
				t.Errorf("compact left files behind: %v", entries)
			}

			again, err := CompactArchive(CompactConfig{Archive: archive, Open: openFor(enc)})
			if err != nil || !again.NothingToDo {
				t.Errorf("second compact = %+v, %v; want nothing to do", again, err)
			}

			// The compacted archive takes appends as any other does.
			if _, err := appendTo(t, archive, tree, enc, nil, "t/b.txt"); err != nil {
				t.Fatalf("append after compact: %v", err)
			}
		})
	}
}

// eventReporter records members and warnings in the order they come.
type eventReporter struct {
	events []string
}

func (r *eventReporter) Member(m *format.Member) { r.events = append(r.events, "ok "+m.Path) }
func (r *eventReporter) Warn(f string, args ...any) {
	r.events = append(r.events, "warn "+fmt.Sprintf(f, args...))
}

// TestVerifyInParallel: verify gives the same report, result and error with
// any number of workers. The workers finish in any order, but the report
// follows the index.
func TestVerifyInParallel(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Dir("p", 0o755)
	for i := range 60 {
		// Sizes from one byte to several 4 KiB chunks, so the workers
		// finish out of order.
		body := strings.Repeat(fmt.Sprintf("file %d line\n", i*7919%1000), 1+i*i%3000/12)
		tree.Text(fmt.Sprintf("p/f%02d.txt", i), 0o644, body)
	}
	// A copy of p/f07.txt shares its blob, so the report has a sharer too.
	tree.Text("p/copy.txt", 0o644, strings.Repeat(fmt.Sprintf("file %d line\n", 7*7919%1000), 1+7*7%3000/12))
	for _, enc := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "encrypted"}[enc], func(t *testing.T) {
			archive := mkArchive(t, tree, enc, "p")
			r, err := OpenWith(archive, openFor(enc))
			if err != nil {
				t.Fatal(err)
			}
			var damaged int
			for _, m := range r.Members() {
				if m.Length > 0 && m.ID%7 == 0 {
					flipByteAt(t, archive, int64(m.Offset)+int64(m.Length)/2)
					damaged++
				}
			}
			r.Close()
			if damaged < 5 {
				t.Fatalf("damaged %d blobs, want at least 5", damaged)
			}

			var want []string
			var wantRes VerifyResult
			var wantErr string
			for _, workers := range []int{1, 2, 4, 16} {
				rep := &eventReporter{}
				res, err := VerifyArchive(VerifyConfig{Archive: archive, Open: openFor(enc),
					Workers: workers, Reporter: rep})
				if !IsDamage(err) {
					t.Fatalf("workers=%d: %v, want damage", workers, err)
				}
				if workers == 1 {
					want, wantRes, wantErr = rep.events, res, err.Error()
					if res.Failed < damaged || res.Checked+res.Failed != 61 {
						t.Errorf("result %+v with %d damaged blobs of 61 files", res, damaged)
					}
					continue
				}
				if !slices.Equal(rep.events, want) {
					t.Errorf("workers=%d: report\n%q\nwant\n%q", workers, rep.events, want)
				}
				if res != wantRes || err.Error() != wantErr {
					t.Errorf("workers=%d: %+v, %v; want %+v, %s", workers, res, err, wantRes, wantErr)
				}
			}
		})
	}
}

func headerOf(t *testing.T, archive string) format.Header {
	t.Helper()
	var h format.Header
	if err := h.UnmarshalBinary(readAll(t, archive)[:format.HeaderSize]); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestVerifyFindsDamagedBlobs(t *testing.T) {
	for _, enc := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "encrypted"}[enc], func(t *testing.T) {
			tree := mutTree(t)
			archive := mkArchive(t, tree, enc, "t")

			if _, err := VerifyArchive(VerifyConfig{Archive: archive, Open: openFor(enc)}); err != nil {
				t.Fatalf("verify of a good archive: %v", err)
			}

			r, err := OpenWith(archive, openFor(enc))
			if err != nil {
				t.Fatal(err)
			}
			var target format.Member
			for _, m := range r.Members() {
				if m.Path == "t/b.txt" {
					target = m
				}
			}
			r.Close()
			flipByteAt(t, archive, int64(target.Offset)+int64(target.Length)/2)

			rep := &recordingReporter{}
			res, err := VerifyArchive(VerifyConfig{Archive: archive, Open: openFor(enc), Reporter: rep})
			if err == nil {
				t.Fatal("verify passed a damaged blob")
			}
			if !IsDamage(err) {
				t.Errorf("error %v is not a corruption error", err)
			}
			if res.Failed != 1 || len(rep.warnings) != 1 || !bytes.Contains([]byte(rep.warnings[0]), []byte("t/b.txt")) {
				t.Errorf("failed=%d warnings=%q, want one naming t/b.txt", res.Failed, rep.warnings)
			}

			if _, err := VerifyArchive(VerifyConfig{Archive: archive, Open: openFor(enc), Quick: true}); err != nil {
				t.Errorf("--quick reads no member data, so it must pass: %v", err)
			}
		})
	}
}

func TestInfo(t *testing.T) {
	tree := mutTree(t)
	archive := mkArchive(t, tree, false, "t")
	in, err := Info(archive, OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if in.Live != 5 || in.Dead != 0 || in.DeadSpace != 0 || in.Trailer.Generation != 1 {
		t.Errorf("fresh archive info = %+v", in)
	}
	if len(in.Codecs) != 1 || in.Codecs[0].Spec.Name != "zstd" || in.Codecs[0].Members+in.Stored != 3 {
		t.Errorf("codecs = %+v stored = %d", in.Codecs, in.Stored)
	}

	if _, err := DeleteMembers(DeleteConfig{Archive: archive, Patterns: []string{"t/a.txt"}}); err != nil {
		t.Fatal(err)
	}
	in, err = Info(archive, OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if in.Live != 4 || in.Dead != 1 || in.DeadSpace <= 0 {
		t.Errorf("after delete info = %+v", in)
	}
}

// TestCrashAtEveryCut is the crash-consistency property of doc/design.md 9.1:
// wherever an append stops, the file either opens as the new generation or
// is refused, and repair gives back the old generation exactly.
func TestCrashAtEveryCut(t *testing.T) {
	for _, enc := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "encrypted"}[enc], func(t *testing.T) {
			tree := mutTree(t)
			archive := mkArchive(t, tree, enc, "t/a.txt", "t/sub")
			before := readAll(t, archive)
			tree.Text("t/a.txt", 0o644, "alpha, changed")
			if _, err := appendTo(t, archive, tree, enc, nil, "t/a.txt", "t/b.txt"); err != nil {
				t.Fatal(err)
			}
			after := readAll(t, archive)

			// Every cut is too slow with a real KDF on each; the test KDF is
			// cheap, but the encrypted run still samples.
			step := 1
			if enc {
				step = 7
			}
			dir := t.TempDir()
			for cut := len(before) + 1; cut < len(after); cut += step {
				path := filepath.Join(dir, "cut.ect")
				if err := os.WriteFile(path, after[:cut], 0o644); err != nil {
					t.Fatal(err)
				}
				if r, err := OpenWith(path, openFor(enc)); err == nil {
					r.Close()
					t.Fatalf("cut at %d: a torn append opened", cut)
				}
				res, err := RepairArchive(path, openFor(enc))
				if err != nil {
					t.Fatalf("cut at %d: repair: %v", cut, err)
				}
				if res.Generation != 1 || res.Removed != int64(cut-len(before)) {
					t.Fatalf("cut at %d: repair = %+v", cut, res)
				}
				if !bytes.Equal(readAll(t, path), before) {
					t.Fatalf("cut at %d: repair did not restore the old generation exactly", cut)
				}
			}
		})
	}
}

func TestRepairTornTrailer(t *testing.T) {
	tree := mutTree(t)
	archive := mkArchive(t, tree, false, "t/a.txt")
	before := readAll(t, archive)
	if _, err := appendTo(t, archive, tree, false, nil, "t/b.txt"); err != nil {
		t.Fatal(err)
	}
	flipByteAt(t, archive, mustStat(t, archive).Size()-10)

	res, err := RepairArchive(archive, OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Generation != 1 || !bytes.Equal(readAll(t, archive), before) {
		t.Errorf("repair = %+v; the file is not the first generation", res)
	}
}

func TestRepairLeavesAGoodArchiveAlone(t *testing.T) {
	tree := mutTree(t)
	archive := mkArchive(t, tree, true, "t")
	before := readAll(t, archive)

	res, err := RepairArchive(archive, openFor(true))
	if err != nil || !res.AlreadyValid {
		t.Errorf("repair = %+v, %v; want already valid", res, err)
	}

	// Damage the end, then give the wrong passphrase: that is not damage the
	// scan can fix, and nothing may change.
	if err := os.WriteFile(archive, append(append([]byte(nil), before...), "junk"...), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := RepairArchive(archive, OpenOptions{Passphrase: passphrase("wrong")}); !errors.Is(err, crypt.ErrWrongPassphrase) {
		t.Errorf("wrong passphrase: got %v", err)
	}
	if got := readAll(t, archive); len(got) != len(before)+4 {
		t.Error("repair with a wrong passphrase changed the file")
	}
}

func TestRepairAsksForThePassphraseOnce(t *testing.T) {
	tree := mutTree(t)
	archive := mkArchive(t, tree, true, "t")
	if _, err := appendTo(t, archive, tree, true, nil, "t/a.txt"); err != nil {
		t.Fatal(err)
	}
	b := readAll(t, archive)
	if err := os.WriteFile(archive, b[:len(b)-50], 0o644); err != nil {
		t.Fatal(err)
	}
	asked := 0
	ask := func() ([]byte, error) { asked++; return []byte("correct horse"), nil }
	if _, err := RepairArchive(archive, OpenOptions{Passphrase: ask}); err != nil {
		t.Fatal(err)
	}
	if asked != 1 {
		t.Errorf("asked %d times, want once", asked)
	}
}

func TestFailedAppendLeavesTheArchiveAsItWas(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads unreadable files")
	}
	tree := mutTree(t)
	archive := mkArchive(t, tree, false, "t/a.txt")
	before := readAll(t, archive)
	tree.Unreadable("t/b.txt")

	if _, err := appendTo(t, archive, tree, false, nil, "t/sub", "t/b.txt"); err == nil {
		t.Fatal("append of an unreadable file succeeded")
	}
	if !bytes.Equal(readAll(t, archive), before) {
		t.Fatal("a failed append changed the archive")
	}
}

func TestAppendNeedsTheRightPassphrase(t *testing.T) {
	tree := mutTree(t)
	archive := mkArchive(t, tree, true, "t/a.txt")
	before := readAll(t, archive)
	_, err := appendTo(t, archive, tree, false, func(c *AppendConfig) {
		c.Open = OpenOptions{Passphrase: passphrase("wrong")}
	}, "t/b.txt")
	if !errors.Is(err, crypt.ErrWrongPassphrase) {
		t.Fatalf("got %v, want ErrWrongPassphrase", err)
	}
	if !bytes.Equal(readAll(t, archive), before) {
		t.Fatal("a refused append changed the archive")
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestKeepGoingReplaceKeepsTheOldCopy: when the new copy of a path cannot be
// read, the old member must stay live. Tombstoning it first loses both.
func TestKeepGoingReplaceKeepsTheOldCopy(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads unreadable files")
	}
	tree := mutTree(t)
	archive := mkArchive(t, tree, false, "t")
	tree.Text("t/a.txt", 0o644, "changed").Unreadable("t/a.txt")

	stats, err := appendTo(t, archive, tree, false, func(c *AppendConfig) { c.KeepGoing = true }, "t/a.txt", "t/b.txt")
	if err != nil {
		t.Fatal(err)
	}
	if stats.Failed != 1 || stats.Replaced != 1 {
		t.Errorf("stats = %+v, want a.txt failed and only b.txt replaced", stats)
	}
	if got := extractOne(t, archive, false, "t/a.txt"); got != "alpha" {
		t.Errorf("t/a.txt = %q, want the old copy", got)
	}
}

// TestKeepGoingHardlinkToAFailedFile: a hardlink must never point to a member
// that was not recorded. The unreadable first name used to register as the
// link target anyway, and the archive then failed to open.
func TestKeepGoingHardlinkToAFailedFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads unreadable files")
	}
	tree := mutTree(t)
	tree.Hardlink("t/z.txt", "t/a.txt").Unreadable("t/a.txt")
	archive := filepath.Join(t.TempDir(), "k.ect")
	stats, err := CreateArchive(CreateConfig{
		Archive: archive, Paths: []string{"t"}, BaseDir: tree.Root,
		Options: Options{Codec: "zstd"}, KeepGoing: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Failed != 2 {
		t.Errorf("failed = %d, want both names of the unreadable inode", stats.Failed)
	}
	if _, err := VerifyArchive(VerifyConfig{Archive: archive}); err != nil {
		t.Fatalf("the archive is broken: %v", err)
	}
}

// TestUpdateLeavesAnUnchangedHardlinkAlone: the second name of a hardlink
// pair has no content of its own, so -u must judge it by its target.
func TestUpdateLeavesAnUnchangedHardlinkAlone(t *testing.T) {
	for _, mode := range []string{UpdateNewer, UpdateDifferent, UpdateDigest} {
		t.Run(mode, func(t *testing.T) {
			tree := mutTree(t)
			tree.Hardlink("t/z.txt", "t/a.txt")
			archive := mkArchive(t, tree, false, "t")
			before := readAll(t, archive)

			stats, err := appendTo(t, archive, tree, false, func(c *AppendConfig) { c.UpdateMode = mode }, "t")
			if err != nil {
				t.Fatal(err)
			}
			if stats.Members != 0 || !bytes.Equal(readAll(t, archive), before) {
				t.Errorf("an update of an unchanged tree stored %d members (%+v)", stats.Members, stats)
			}
		})
	}
}

// TestCompactKeepsAnAppendBeforeItsLock: an append that commits after compact
// opens the archive and before it takes the lock is in the compacted archive.
// Compact read the index before it locked, and so wrote the archive again
// from the older index, without the append (doc/design.md 9.6).
func TestCompactKeepsAnAppendBeforeItsLock(t *testing.T) {
	tree := mutTree(t)
	archive := mkArchive(t, tree, false, "t")
	if _, err := DeleteMembers(DeleteConfig{Archive: archive, Patterns: []string{"t/b.txt"}}); err != nil {
		t.Fatal(err)
	}
	tree.Text("t/late.txt", 0o644, "appended meanwhile")
	testBeforeCompactLock = func() {
		testBeforeCompactLock = nil
		if _, err := appendTo(t, archive, tree, false, nil, "t/late.txt"); err != nil {
			t.Errorf("the append beside compact: %v", err)
		}
	}
	defer func() { testBeforeCompactLock = nil }()

	if _, err := CompactArchive(CompactConfig{Archive: archive}); err != nil {
		t.Fatalf("compact: %v", err)
	}
	if got := extractOne(t, archive, false, "t/late.txt"); got != "appended meanwhile" {
		t.Errorf("t/late.txt after compact = %q; the append was lost", got)
	}
}

func TestCompactThroughASymlink(t *testing.T) {
	tree := mutTree(t)
	archive := mkArchive(t, tree, false, "t")
	if _, err := DeleteMembers(DeleteConfig{Archive: archive, Patterns: []string{"t/a.txt"}}); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link.ect")
	if err := os.Symlink(archive, link); err != nil {
		t.Fatal(err)
	}
	if _, err := CompactArchive(CompactConfig{Archive: link}); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the symlink was replaced: %v, %v", fi.Mode(), err)
	}
	if _, _, gen := state(t, archive, false); gen != 3 {
		t.Errorf("the target is at generation %d, want 3", gen)
	}
}

// TestFailedCreateKeepsTheOldArchive: a create that fails must leave a file
// already at the path as it was. It used to truncate the file first and
// remove it on failure, so a mistyped source path destroyed a backup.
func TestFailedCreateKeepsTheOldArchive(t *testing.T) {
	tree := mutTree(t)
	archive := mkArchive(t, tree, false, "t")
	if err := os.Chmod(archive, 0o600); err != nil {
		t.Fatal(err)
	}
	before := readAll(t, archive)

	_, err := CreateArchive(CreateConfig{
		Archive: archive, Paths: []string{"no/such/path"}, BaseDir: tree.Root,
		Options: Options{Codec: "zstd"},
	})
	if err == nil {
		t.Fatal("a create of a missing path succeeded")
	}
	if !bytes.Equal(readAll(t, archive), before) {
		t.Fatal("a failed create changed the archive already at the path")
	}
	if entries, _ := os.ReadDir(filepath.Dir(archive)); len(entries) != 1 {
		t.Errorf("a failed create left files behind: %v", entries)
	}

	// A successful create replaces the file, and keeps its permissions.
	if _, err := CreateArchive(CreateConfig{
		Archive: archive, Paths: []string{"t/a.txt"}, BaseDir: tree.Root,
		Options: Options{Codec: "zstd"},
	}); err != nil {
		t.Fatal(err)
	}
	if fi := mustStat(t, archive); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want the old archive's 0600", fi.Mode().Perm())
	}
	if live, _, _ := state(t, archive, false); !equalStrings(live, []string{"t/a.txt"}) {
		t.Errorf("live = %v", live)
	}
}

func TestCreateThroughASymlink(t *testing.T) {
	tree := mutTree(t)
	archive := mkArchive(t, tree, false, "t")
	link := filepath.Join(t.TempDir(), "link.ect")
	if err := os.Symlink(archive, link); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateArchive(CreateConfig{
		Archive: link, Paths: []string{"t/b.txt"}, BaseDir: tree.Root,
		Options: Options{Codec: "zstd"},
	}); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the symlink was replaced: %v", err)
	}
	if live, _, _ := state(t, archive, false); !equalStrings(live, []string{"t/b.txt"}) {
		t.Errorf("the link's target holds %v", live)
	}
}

// TestCreateSkipsTheArchiveItReplaces: the old archive in the walked tree is
// not the file being written, but it must not go into the new one.
func TestCreateSkipsTheArchiveItReplaces(t *testing.T) {
	tree := mutTree(t)
	archive := tree.Path("t/self.ect")
	for range 2 {
		if _, err := CreateArchive(CreateConfig{
			Archive: archive, Paths: []string{"t"}, BaseDir: tree.Root,
			Options: Options{Codec: "zstd"},
		}); err != nil {
			t.Fatal(err)
		}
	}
	live, _, _ := state(t, archive, false)
	for _, p := range live {
		if strings.Contains(p, "eictar") {
			t.Errorf("%s was archived into the archive", p)
		}
	}
}

// TestEveryPatternMustMatch: a mistyped pattern among good ones is an error
// for every operation that takes patterns, not a quietly shorter result.
func TestEveryPatternMustMatch(t *testing.T) {
	tree := mutTree(t)
	archive := mkArchive(t, tree, false, "t")
	patterns := []string{"t/a.txt", "t/typo.txt"}

	if _, err := ListArchive(ListConfig{Archive: archive, Patterns: patterns}); !errors.Is(err, ErrNoMatch) {
		t.Errorf("list: %v", err)
	}
	dest := t.TempDir()
	if _, err := Extract(ExtractConfig{Archive: archive, Destination: dest, Patterns: patterns}); !errors.Is(err, ErrNoMatch) {
		t.Errorf("extract: %v", err)
	}
	if entries, _ := os.ReadDir(dest); len(entries) != 0 {
		t.Errorf("extract wrote %v before refusing", entries)
	}
	if _, err := VerifyArchive(VerifyConfig{Archive: archive, Patterns: patterns}); !errors.Is(err, ErrNoMatch) {
		t.Errorf("verify: %v", err)
	}
}

// TestHardlinksWithoutTheirTargetStayLinked: two names of a file, extracted
// without the member that holds the content, must still be one file.
func TestHardlinksWithoutTheirTargetStayLinked(t *testing.T) {
	tree := mutTree(t)
	tree.Hardlink("t/l1", "t/a.txt").Hardlink("t/l2", "t/a.txt") // a.txt holds the content
	archive := mkArchive(t, tree, false, "t")

	dest := t.TempDir()
	if _, err := Extract(ExtractConfig{Archive: archive, Destination: dest, Patterns: []string{"t/l1", "t/l2"}}); err != nil {
		t.Fatal(err)
	}
	l1, l2 := mustStat(t, filepath.Join(dest, "t/l1")), mustStat(t, filepath.Join(dest, "t/l2"))
	if !os.SameFile(l1, l2) {
		t.Error("t/l1 and t/l2 were extracted as two copies, not as links")
	}
	if got := string(readAll(t, filepath.Join(dest, "t/l2"))); got != "alpha" {
		t.Errorf("t/l2 = %q", got)
	}
}

// TestRecompress: --recompress encodes every member again with the new codec.
// The content, the digests and the ids stay; every sealed member gets a new
// salt, because new ciphertext under the old key would reuse its nonces. A
// tombstone that a hardlink needs, and the holes of a sparse file, survive.
func TestRecompress(t *testing.T) {
	for _, enc := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "encrypted"}[enc], func(t *testing.T) {
			tree := mutTree(t)
			tree.Hardlink("t/link.txt", "t/a.txt")
			tree.Sparse("t/holes.img", 0o644, 1<<20, testutil.Segment{Offset: 512 << 10, Data: []byte("data in the middle")})
			tree.Text("t/big.txt", 0o644, strings.Repeat("recompress me. ", 40000))
			archive := mkArchive(t, tree, enc, "t")
			// Replace a.txt so that link.txt points to a tombstone.
			if err := os.Remove(tree.Path("t/a.txt")); err != nil {
				t.Fatal(err)
			}
			tree.Text("t/a.txt", 0o644, "a new alpha")
			if _, err := appendTo(t, archive, tree, enc, nil, "t/a.txt"); err != nil {
				t.Fatal(err)
			}

			before := membersByID(t, archive, enc)
			res, err := CompactArchive(CompactConfig{
				Archive: archive, Open: openFor(enc),
				Recompress: &RecompressConfig{Codec: "xz", Params: codec.Params{"preset": "1"}, ChunkSize: 64 << 10},
			})
			if err != nil {
				t.Fatalf("recompress: %v", err)
			}
			if res.NothingToDo || res.Recompressed == 0 {
				t.Fatalf("result = %+v", res)
			}

			after := membersByID(t, archive, enc)
			if len(after) != len(before) {
				t.Fatalf("%d members after, %d before", len(after), len(before))
			}
			for id, b := range before {
				a, ok := after[id]
				if !ok {
					t.Errorf("member %d (%s) is gone", id, b.Path)
					continue
				}
				if a.Path != b.Path || a.Dead != b.Dead || !bytes.Equal(a.Digest, b.Digest) || a.Size != b.Size {
					t.Errorf("member %d changed: %+v -> %+v", id, b, a)
				}
				if !a.Type.HasPayload() {
					continue
				}
				if a.ChunkSize != 64<<10 {
					t.Errorf("%s: chunk size %d, want 65536", a.Path, a.ChunkSize)
				}
				if enc && bytes.Equal(a.Enc.Salt, b.Enc.Salt) {
					t.Errorf("%s kept its salt: its nonces would be used twice", a.Path)
				}
			}

			in, err := Info(archive, openFor(enc))
			if err != nil {
				t.Fatal(err)
			}
			if len(in.Codecs) != 1 || in.Codecs[0].Spec.String() != "xz:preset=1" {
				t.Errorf("catalog = %+v", in.Codecs)
			}
			if _, err := VerifyArchive(VerifyConfig{Archive: archive, Open: openFor(enc)}); err != nil {
				t.Fatalf("verify: %v", err)
			}
			if got := extractOne(t, archive, enc, "t/link.txt"); got != "alpha" {
				t.Errorf("t/link.txt = %q, want the tombstone's content", got)
			}

			dest := t.TempDir()
			if _, err := Extract(ExtractConfig{Archive: archive, Destination: dest, Passphrase: openFor(enc).Passphrase}); err != nil {
				t.Fatal(err)
			}
			testutil.CompareTrees(t, tree.Path("t"), filepath.Join(dest, "t"),
				testutil.CompareOptions{Mode: true,
					Holes: meta.Supports.Holes && tree.Holes("t/holes.img")})
		})
	}
}

func membersByID(t *testing.T, archive string, enc bool) map[uint64]format.Member {
	t.Helper()
	r, err := OpenWith(archive, openFor(enc))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	out := map[uint64]format.Member{}
	for _, m := range r.AllMembers() {
		out[m.ID] = m
	}
	return out
}

// TestCorruptChunkIsDamage: a chunk that its codec refuses is damage (exit 3),
// whichever check catches it - the codec's own, or the content digest. The
// stress tester found zstd's checksum error reported as an I/O error (exit 4).
func TestCorruptChunkIsDamage(t *testing.T) {
	for _, name := range codec.Names() {
		if name == "none" {
			continue // stored content has no codec to refuse it
		}
		t.Run(name, func(t *testing.T) {
			tree := testutil.NewTree(t)
			tree.Text("f.txt", 0o644, strings.Repeat("compressible text ", 4000))
			archive := filepath.Join(t.TempDir(), "c.ect")
			if _, err := CreateArchive(CreateConfig{Archive: archive, Paths: []string{"f.txt"},
				BaseDir: tree.Root, Options: Options{Codec: name}}); err != nil {
				t.Fatal(err)
			}
			r, err := OpenWith(archive, OpenOptions{})
			if err != nil {
				t.Fatal(err)
			}
			m := r.Members()[0]
			r.Close()
			flipByteAt(t, archive, int64(m.Offset)+int64(m.Length)/2)

			_, err = VerifyArchive(VerifyConfig{Archive: archive})
			if err == nil || !IsDamage(err) {
				t.Errorf("a corrupt %s chunk: %v; want an error that counts as damage", name, err)
			}
		})
	}
}

// TestNameMatchTakesTheDirectoryContents: a pattern with no slash matches a
// directory by its name at any depth, and then takes what is below it, as a
// full path does. It used to take the nested directory and leave its
// contents behind: live members under a deleted directory, and a listing
// that --exclude did not clean (doc/design.md 13.4).
func TestNameMatchTakesTheDirectoryContents(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Dir("t", 0o755).Dir("t/a", 0o755).Dir("t/a/cache", 0o755)
	tree.Text("t/a/cache/x.bin", 0o644, "x").Text("t/a/keep.txt", 0o644, "k")
	archive := mkArchive(t, tree, false, "t")

	l, err := ListArchive(ListConfig{Archive: archive, Exclude: []string{"cache"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range l.Members {
		if strings.Contains(m.Path, "cache") {
			t.Errorf("--exclude cache still lists %s", m.Path)
		}
	}

	if _, err := DeleteMembers(DeleteConfig{Archive: archive, Patterns: []string{"cache"}}); err != nil {
		t.Fatal(err)
	}
	live, _, _ := state(t, archive, false)
	if want := []string{"t", "t/a", "t/a/keep.txt"}; !equalStrings(live, want) {
		t.Errorf("after --delete cache: %v, want %v", live, want)
	}
}

// TestUpdateDigestComparesContentNotLayout: -u --update-mode=digest must
// judge a file by what it holds, not by where the filesystem says its holes
// are. The stress tester found an unchanged sparse file archived again when
// its data regions were reported differently.
func TestUpdateDigestComparesContentNotLayout(t *testing.T) {
	data := []byte("data in the middle of a sparse file")
	const size, at = 1 << 20, 512 << 10
	dense := make([]byte, size)
	copy(dense[at:], data)

	for _, tc := range []struct {
		name          string
		start, change func(tree *testutil.Tree)
		stale         bool
	}{
		{"sparse, then dense with the same bytes",
			func(tr *testutil.Tree) { tr.Sparse("t/f", 0o644, size, testutil.Segment{Offset: at, Data: data}) },
			func(tr *testutil.Tree) { tr.File("t/f", 0o644, dense) }, false},
		{"dense, then sparse with the same bytes",
			func(tr *testutil.Tree) { tr.File("t/f", 0o644, dense) },
			func(tr *testutil.Tree) { tr.Sparse("t/f", 0o644, size, testutil.Segment{Offset: at, Data: data}) }, false},
		{"sparse, then a byte where the hole was",
			func(tr *testutil.Tree) { tr.Sparse("t/f", 0o644, size, testutil.Segment{Offset: at, Data: data}) },
			func(tr *testutil.Tree) {
				tr.Sparse("t/f", 0o644, size, testutil.Segment{Offset: at, Data: data}, testutil.Segment{Offset: 7, Data: []byte{1}})
			}, true},
		{"sparse, then other data in the same place",
			func(tr *testutil.Tree) { tr.Sparse("t/f", 0o644, size, testutil.Segment{Offset: at, Data: data}) },
			func(tr *testutil.Tree) {
				tr.Sparse("t/f", 0o644, size, testutil.Segment{Offset: at, Data: bytes.ToUpper(data)})
			}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := testutil.NewTree(t)
			tree.Dir("t", 0o755)
			tc.start(tree)
			archive := mkArchive(t, tree, false, "t/f")
			os.Remove(tree.Path("t/f"))
			tc.change(tree)
			tree.SetTimes("t/f", time.Unix(1, 0), time.Unix(2, 0)) // a new time: digest must not care

			stats, err := appendTo(t, archive, tree, false, func(c *AppendConfig) { c.UpdateMode = UpdateDigest }, "t/f")
			if err != nil {
				t.Fatal(err)
			}
			if got := stats.Replaced == 1; got != tc.stale {
				t.Errorf("replaced = %v, want %v (stats %+v)", got, tc.stale, stats)
			}
		})
	}
}

func TestOutsideSegments(t *testing.T) {
	segs := []format.SparseSegment{{Offset: 10, Length: 10}, {Offset: 30, Length: 5}}
	got := outside(meta.Segment{Offset: 0, Length: 40}, segs)
	want := []meta.Segment{{Offset: 0, Length: 10}, {Offset: 20, Length: 10}, {Offset: 35, Length: 5}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("outside = %v, want %v", got, want)
	}
	if got := outside(meta.Segment{Offset: 12, Length: 5}, segs); len(got) != 0 {
		t.Errorf("a range inside a segment has parts outside it: %v", got)
	}
}

// TestEncryptedDigestIsKeyed is the point of the keyed digest (doc/design.md
// 6.2): in an encrypted archive whose index is not sealed, the plain BLAKE3
// of a file must be nowhere in the file, or anyone with a copy of the file
// could find out that the archive holds it. A plaintext archive keeps the
// plain digest.
func TestEncryptedDigestIsKeyed(t *testing.T) {
	content := []byte("a file that an observer also has a copy of")
	plain := blake3.Sum256(content)

	for _, enc := range []bool{false, true} {
		tree := testutil.NewTree(t)
		tree.File("f", 0o644, content)
		cfg := CreateConfig{Archive: filepath.Join(t.TempDir(), "k.ect"), Paths: []string{"f"},
			BaseDir: tree.Root, Options: Options{Codec: "none"}}
		if enc {
			// EncryptIndex false: the index, digests and all, is readable.
			cfg.Encryption = &EncryptionConfig{Passphrase: []byte("correct horse"), Params: testKDF}
		}
		if _, err := CreateArchive(cfg); err != nil {
			t.Fatal(err)
		}
		m := membersByID(t, cfg.Archive, enc)[1]
		if got := bytes.Equal(m.Digest, plain[:]); got == enc {
			t.Errorf("encrypted=%v: the member digest is the plain BLAKE3: %v", enc, got)
		}
		if enc {
			raw := readAll(t, cfg.Archive)
			// The index is compressed; decode it without a key, as an
			// observer can, and look for the plain digest there too.
			var tr format.Trailer
			if err := tr.UnmarshalBinary(raw); err != nil {
				t.Fatal(err)
			}
			ix, err := format.DecodeIndex(raw[tr.IndexOffset:tr.IndexOffset+tr.IndexLength], tr.Flags, nil)
			if err != nil {
				t.Fatalf("the unsealed index did not decode: %v", err)
			}
			if bytes.Equal(ix.Members[0].Digest, plain[:]) || bytes.Contains(raw, plain[:]) {
				t.Error("an observer can read the plain digest of the file")
			}
		}
		if _, err := VerifyArchive(VerifyConfig{Archive: cfg.Archive, Open: openFor(enc)}); err != nil {
			t.Errorf("encrypted=%v: verify: %v", enc, err)
		}
	}
}

// TestUpdateDigestOnAnEncryptedArchive: -u --update-mode=digest compares with
// the keyed digest, so it needs the key, and judges content as before.
func TestUpdateDigestOnAnEncryptedArchive(t *testing.T) {
	tree := mutTree(t)
	archive := mkArchive(t, tree, true, "t/a.txt")
	tree.SetTimes("t/a.txt", time.Unix(5, 0), time.Unix(6, 0)) // same content
	stats, err := appendTo(t, archive, tree, true, func(c *AppendConfig) { c.UpdateMode = UpdateDigest }, "t/a.txt")
	if err != nil || stats.Members != 0 {
		t.Fatalf("a touch: %+v, %v; want nothing archived", stats, err)
	}
	tree.Text("t/a.txt", 0o644, "ALPHA")
	stats, err = appendTo(t, archive, tree, true, func(c *AppendConfig) { c.UpdateMode = UpdateDigest }, "t/a.txt")
	if err != nil || stats.Replaced != 1 {
		t.Fatalf("new content: %+v, %v; want it replaced", stats, err)
	}
}

// TestChangePassphrase: the new passphrase opens the archive and the old one
// does not. The data key is the same, so ids, digests and content do not
// change, and the dead space of old generations goes.
func TestChangePassphrase(t *testing.T) {
	tree := mutTree(t)
	archive := mkArchive(t, tree, true, "t")
	tree.Text("t/a.txt", 0o644, "ALPHA")
	if _, err := appendTo(t, archive, tree, true, nil, "t/a.txt"); err != nil {
		t.Fatal(err)
	}
	before := membersByID(t, archive, true)
	live, _, _ := state(t, archive, true)
	oldSize := mustStat(t, archive).Size()

	newParams := crypt.KDFParams{Time: 2} // memory and threads stay
	res, err := CompactArchive(CompactConfig{Archive: archive, Open: openFor(true),
		Rewrap: &RewrapConfig{Passphrase: passphrase("battery staple"), Params: newParams}})
	if err != nil {
		t.Fatalf("change of passphrase: %v", err)
	}
	if res.Dropped != 1 || mustStat(t, archive).Size() >= oldSize {
		t.Errorf("result %+v, size %d (was %d): want the replaced member and dead space gone",
			res, mustStat(t, archive).Size(), oldSize)
	}

	if _, err := OpenWith(archive, openFor(true)); !errors.Is(err, crypt.ErrWrongPassphrase) {
		t.Fatalf("the old passphrase: %v, want ErrWrongPassphrase", err)
	}
	newOpen := OpenOptions{Passphrase: passphrase("battery staple")}
	r, err := OpenWith(archive, newOpen)
	if err != nil {
		t.Fatalf("the new passphrase: %v", err)
	}
	if got := (crypt.KDFParams{Time: r.crypto.Time, Memory: r.crypto.Memory, Threads: r.crypto.Threads}); got !=
		(crypt.KDFParams{Time: 2, Memory: testKDF.Memory, Threads: testKDF.Threads}) {
		t.Errorf("KDF parameters %+v: want time 2 and the others kept", got)
	}
	var got []string
	for _, m := range r.Members() {
		got = append(got, m.Path)
		old, ok := before[m.ID]
		if !ok || old.Path != m.Path || !bytes.Equal(old.Digest, m.Digest) {
			t.Errorf("%s (id %d): the member changed identity or digest", m.Path, m.ID)
		}
	}
	r.Close()
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(live, ",") {
		t.Errorf("members %q, want %q", got, live)
	}

	if _, err := VerifyArchive(VerifyConfig{Archive: archive, Open: newOpen}); err != nil {
		t.Errorf("verify: %v", err)
	}
	dest := t.TempDir()
	if _, err := Extract(ExtractConfig{Archive: archive, Destination: dest, Passphrase: newOpen.Passphrase}); err != nil {
		t.Fatal(err)
	}
	if b := readAll(t, filepath.Join(dest, "t/a.txt")); string(b) != "ALPHA" {
		t.Errorf("t/a.txt = %q, want the new content", b)
	}
}

func TestChangePassphraseRefusals(t *testing.T) {
	tree := mutTree(t)
	rewrap := &RewrapConfig{Passphrase: passphrase("battery staple")}

	plain := mkArchive(t, tree, false, "t")
	before := readAll(t, plain)
	if _, err := CompactArchive(CompactConfig{Archive: plain, Rewrap: rewrap}); !errors.Is(err, ErrNotEncrypted) {
		t.Errorf("a plaintext archive: %v, want ErrNotEncrypted", err)
	}
	if !bytes.Equal(before, readAll(t, plain)) {
		t.Error("a refused change of passphrase changed the archive")
	}

	enc := mkArchive(t, tree, true, "t")
	before = readAll(t, enc)
	for name, rw := range map[string]*RewrapConfig{
		"empty passphrase": {Passphrase: passphrase("")},
		"bad parameters":   {Passphrase: passphrase("x"), Params: crypt.KDFParams{Memory: 1}},
		"unaffordable":     {Passphrase: passphrase("x"), Params: crypt.KDFParams{Memory: 1<<32 - 1}},
	} {
		if _, err := CompactArchive(CompactConfig{Archive: enc, Open: openFor(true), Rewrap: rw}); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if !bytes.Equal(before, readAll(t, enc)) {
			t.Errorf("%s: a refused change of passphrase changed the archive", name)
		}
	}
	if _, err := CompactArchive(CompactConfig{Archive: enc, Open: OpenOptions{Passphrase: passphrase("wrong")},
		Rewrap: rewrap}); !errors.Is(err, crypt.ErrWrongPassphrase) {
		t.Errorf("the wrong old passphrase: %v, want ErrWrongPassphrase", err)
	}
	entries, _ := os.ReadDir(filepath.Dir(enc))
	if len(entries) != 1 {
		t.Errorf("files left beside the archive: %v", entries)
	}
}

func mustRegex(t *testing.T, exprs ...string) fsutil.Regexps {
	t.Helper()
	rs, err := fsutil.CompileRegexps(exprs)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

// regexTree has matches at several depths, and a directory to exclude.
func regexTree(t *testing.T) *testutil.Tree {
	t.Helper()
	tree := testutil.NewTree(t)
	tree.Dir("r", 0o755).Dir("r/dir", 0o755).Dir("r/deep", 0o755).Dir("r/deep/dir", 0o755).Dir("r/cache", 0o755)
	tree.Text("r/dir/a1.txt", 0o644, "a1")
	tree.Text("r/dir/g1.txt", 0o644, "g1")
	tree.Text("r/deep/dir/f42.txt", 0o644, "f42")
	tree.Text("r/cache/b2.txt", 0o644, "cached")
	tree.Text("r/top.txt", 0o644, "top")
	return tree
}

func livePaths(t *testing.T, archive string) []string {
	t.Helper()
	live, _, _ := state(t, archive, false)
	return live
}

// TestRegexFiltersTheWalk: -R stores only what matches, at any depth, and
// not the directories above it; --exclude-regex does not enter a directory
// (doc/design.md 10.11).
func TestRegexFiltersTheWalk(t *testing.T) {
	tree := regexTree(t)
	cfg := CreateConfig{
		Archive: filepath.Join(t.TempDir(), "r.ect"), Paths: []string{"r"}, BaseDir: tree.Root,
		Options:      Options{Codec: "zstd"},
		Regex:        mustRegex(t, `.*/dir/[a-f][0-9]+\.txt`, `.*/[a-z][0-9]\.txt`),
		ExcludeRegex: mustRegex(t, `.*/cache`),
	}
	if _, err := CreateArchive(cfg); err != nil {
		t.Fatal(err)
	}
	// g1 matches the second expression only; b2 matches it too, but its
	// directory is excluded, and an exclusion wins.
	want := "r/deep/dir/f42.txt,r/dir/a1.txt,r/dir/g1.txt"
	if got := strings.Join(livePaths(t, cfg.Archive), ","); got != want {
		t.Errorf("members %s, want %s", got, want)
	}
	// Extraction makes the parents that the archive does not hold.
	if got := extractOne(t, cfg.Archive, false, "r/deep/dir/f42.txt"); got != "f42" {
		t.Errorf("content %q", got)
	}

	// An expression whose only matches are in an excluded directory matches
	// nothing: the walk never sees them.
	cfg.Archive = filepath.Join(t.TempDir(), "r.ect")
	cfg.Regex = mustRegex(t, `.*/cache/.*`)
	if _, err := CreateArchive(cfg); !errors.Is(err, ErrNoMatch) {
		t.Errorf("-R inside an excluded directory: %v, want ErrNoMatch", err)
	}
}

// TestRegexThatMatchesNothingChangesNothing: on create no file is left, and
// on append the archive keeps every byte.
func TestRegexThatMatchesNothingChangesNothing(t *testing.T) {
	tree := regexTree(t)
	archive := filepath.Join(t.TempDir(), "r.ect")
	_, err := CreateArchive(CreateConfig{Archive: archive, Paths: []string{"r"}, BaseDir: tree.Root,
		Regex: mustRegex(t, `.*\.txt`, `nothing`)})
	if !errors.Is(err, ErrNoMatch) || !strings.Contains(err.Error(), `"nothing"`) {
		t.Fatalf("create: %v, want ErrNoMatch naming the expression", err)
	}
	if _, err := os.Stat(archive); !os.IsNotExist(err) {
		t.Errorf("a failed create left %s: %v", archive, err)
	}

	archive = mkArchive(t, tree, false, "r/top.txt")
	before := readAll(t, archive)
	_, err = appendTo(t, archive, tree, false, func(c *AppendConfig) { c.Regex = mustRegex(t, `.*\.md`) }, "r")
	if !errors.Is(err, ErrNoMatch) {
		t.Fatalf("append: %v, want ErrNoMatch", err)
	}
	if !bytes.Equal(before, readAll(t, archive)) {
		t.Error("a refused append changed the archive")
	}
}

// TestRegexSelectsMembers covers the reads: -R filters what the patterns
// select, each expression must match, and --exclude-regex on a directory
// takes its contents.
func TestRegexSelectsMembers(t *testing.T) {
	tree := regexTree(t)
	archive := mkArchive(t, tree, false, "r")
	list := func(patterns []string, re, ex fsutil.Regexps) ([]string, error) {
		ms, err := List(ListConfig{Archive: archive, Patterns: patterns, Regex: re, ExcludeRegex: ex})
		var out []string
		for _, m := range ms {
			out = append(out, m.Path)
		}
		return out, err
	}

	got, err := list(nil, mustRegex(t, `.*[0-9]\.txt`), nil)
	if err != nil || strings.Join(got, ",") != "r/cache/b2.txt,r/deep/dir/f42.txt,r/dir/a1.txt,r/dir/g1.txt" {
		t.Errorf("-R alone: %q, %v", got, err)
	}
	got, err = list([]string{"r/dir"}, mustRegex(t, `.*[0-9]\.txt`), nil)
	if err != nil || strings.Join(got, ",") != "r/dir/a1.txt,r/dir/g1.txt" {
		t.Errorf("a pattern and -R: %q, %v", got, err)
	}
	// A directory match does not take its contents.
	got, err = list(nil, mustRegex(t, `r/dir`), nil)
	if err != nil || strings.Join(got, ",") != "r/dir" {
		t.Errorf("-R on a directory: %q, %v", got, err)
	}
	got, err = list(nil, nil, mustRegex(t, `.*/cache`))
	if err != nil || strings.Contains(strings.Join(got, ","), "cache") {
		t.Errorf("--exclude-regex on a directory: %q, %v", got, err)
	}
	// Matched by the pattern's selection only: r/top.txt is outside r/dir.
	if _, err := list([]string{"r/dir"}, mustRegex(t, `r/top\.txt`), nil); !errors.Is(err, ErrNoMatch) {
		t.Errorf("an -R outside the patterns: %v, want ErrNoMatch", err)
	}

	dest := t.TempDir()
	if _, err := Extract(ExtractConfig{Archive: archive, Destination: dest, Regex: mustRegex(t, `.*/g1\.txt`)}); err != nil {
		t.Fatal(err)
	}
	if b := readAll(t, filepath.Join(dest, "r/dir/g1.txt")); string(b) != "g1" {
		t.Errorf("extracted %q", b)
	}
	if _, err := os.Stat(filepath.Join(dest, "r/dir/a1.txt")); !os.IsNotExist(err) {
		t.Errorf("-R extracted a file that it does not match: %v", err)
	}
	if _, err := VerifyArchive(VerifyConfig{Archive: archive, Regex: mustRegex(t, `.*\.txt`)}); err != nil {
		t.Errorf("verify: %v", err)
	}

	if _, err := DeleteMembers(DeleteConfig{Archive: archive, Regex: mustRegex(t, `r/(dir|deep)/.*`)}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(livePaths(t, archive), ","); got != "r,r/cache,r/cache/b2.txt,r/deep,r/dir,r/top.txt" {
		t.Errorf("after delete -R: %s", got)
	}
}
