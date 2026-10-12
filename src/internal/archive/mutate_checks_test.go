package archive

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/philmalin/eictar/src/internal/crypt"
	"github.com/philmalin/eictar/src/internal/format"
	"github.com/philmalin/eictar/src/internal/meta"
	"github.com/philmalin/eictar/src/internal/testutil"
)

// Tests of the operations that change an archive (mutate.go) for what the
// tests of each operation do not reach.

// TestKept: compact keeps each live member, and each tombstone that a kept
// member needs: the target of a live hardlink, and the owner of content that
// a kept member shares, through a chain of both (doc/design.md 4.3, 9.2).
func TestKept(t *testing.T) {
	reg := func(id uint64, dead bool) format.Member {
		return format.Member{ID: id, Type: format.TypeReg, Dead: dead}
	}
	link := func(id, to uint64, dead bool) format.Member {
		return format.Member{ID: id, Type: format.TypeHardlink, HardlinkTo: to, Dead: dead}
	}
	share := func(id, owner uint64, dead bool) format.Member {
		return format.Member{ID: id, Type: format.TypeReg, Data: owner, Dead: dead}
	}
	for _, tc := range []struct {
		name string
		all  []format.Member
		want []uint64
	}{
		{"a live hardlink keeps its dead target", []format.Member{reg(1, true), link(2, 1, false)}, []uint64{1, 2}},
		{"a dead hardlink keeps nothing", []format.Member{reg(1, true), link(2, 1, true)}, nil},
		{"a live sharer keeps its dead owner", []format.Member{reg(1, true), share(2, 1, false)}, []uint64{1, 2}},
		{"a dead sharer keeps nothing", []format.Member{reg(1, true), share(2, 1, true)}, nil},
		{"a chain", []format.Member{reg(1, true), share(2, 1, true), link(3, 2, false)}, []uint64{1, 2, 3}},
		{"live members stay", []format.Member{reg(1, false), reg(2, true)}, []uint64{1}},
	} {
		var got []uint64
		for _, m := range kept(tc.all) {
			got = append(got, m.ID)
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: kept %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestRepairAcrossWindows: repair reads the file from its end in windows. A
// trailer that falls across two windows must still be found, whatever the
// size of the window.
func TestRepairAcrossWindows(t *testing.T) {
	tree := mutTree(t)
	tree.Text("t/big.txt", 0o644, strings.Repeat("several chunks of text. ", 500))
	archive := mkArchive(t, tree, false, "t")
	tree.Text("t/a.txt", 0o644, "alpha again")
	if _, err := appendTo(t, archive, tree, false, nil, "t/a.txt"); err != nil {
		t.Fatal(err)
	}
	want, err := archiveState(archive, []OpenOptions{{}})
	if err != nil {
		t.Fatal(err)
	}
	torn := append(readAll(t, archive), []byte("the start of an append that a crash cut off")...)

	saved := repairWindow
	t.Cleanup(func() { repairWindow = saved })
	for _, w := range []int64{int64(len(trailerMagic)), int64(len(trailerMagic)) + 1, 37, 64, 1000, 1 << 20} {
		repairWindow = w
		path := filepath.Join(t.TempDir(), "x.ect")
		if err := os.WriteFile(path, torn, 0o644); err != nil {
			t.Fatal(err)
		}
		res, err := RepairArchive(path, OpenOptions{})
		if err != nil {
			t.Errorf("window %d: %v", w, err)
			continue
		}
		if got, err := archiveState(path, []OpenOptions{{}}); err != nil || got != want || res.Generation != 2 {
			t.Errorf("window %d: generation %d, %v; want the second generation", w, res.Generation, err)
		}
	}
}

// TestRepairChecks: repair asks for the passphrase once, gives its error,
// refuses a plain archive when encryption is required, and names a header
// that is short or damaged.
func TestRepairChecks(t *testing.T) {
	enc := mkArchive(t, mutTree(t), true, "t")
	torn := append(readAll(t, enc), []byte("cut off")...)
	write := func(b []byte) string {
		path := filepath.Join(t.TempDir(), "x.ect")
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}

	asked := 0
	if _, err := RepairArchive(write(torn), OpenOptions{Passphrase: func() ([]byte, error) {
		asked++
		return []byte("correct horse"), nil
	}}); err != nil || asked != 1 {
		t.Errorf("repair: %v, after %d questions; want 1", err, asked)
	}
	errNoTerminal := errors.New("no terminal")
	if _, err := RepairArchive(write(torn), OpenOptions{Passphrase: func() ([]byte, error) { return nil, errNoTerminal }}); !errors.Is(err, errNoTerminal) {
		t.Errorf("a passphrase that cannot be read: %v", err)
	}

	plain := append(readAll(t, mkArchive(t, mutTree(t), false, "t")), []byte("cut off")...)
	if _, err := RepairArchive(write(plain), OpenOptions{RequireEncryption: true}); !errors.Is(err, ErrNotEncrypted) {
		t.Errorf("a plain archive, encryption required: %v", err)
	}
	if _, err := RepairArchive(write(plain[:10]), OpenOptions{}); err == nil || !strings.Contains(err.Error(), "reading header") {
		t.Errorf("a file shorter than a header: %v", err)
	}
	bad := append([]byte(nil), plain...)
	bad[0] ^= 0xff
	if _, err := RepairArchive(write(bad), OpenOptions{}); !errors.Is(err, format.ErrBadMagic) {
		t.Errorf("a damaged header: %v", err)
	}
}

// TestAppendAndDeleteRefuse: options that cannot work are refused before
// the archive opens.
func TestAppendAndDeleteRefuse(t *testing.T) {
	tree := mutTree(t)
	archive := mkArchive(t, tree, false, "t")
	for _, tc := range []struct {
		name string
		mod  func(*AppendConfig)
		want string
	}{
		{"encryption of its own", func(c *AppendConfig) { c.Encryption = &EncryptionConfig{Passphrase: []byte("x")} }, "takes its encryption from the archive"},
		{"an unknown conflict policy", func(c *AppendConfig) { c.OnConflict = "maybe" }, "unknown conflict policy"},
		{"an unknown update mode", func(c *AppendConfig) { c.UpdateMode = "sometimes" }, "unknown update mode"},
	} {
		if _, err := appendTo(t, archive, tree, false, tc.mod, "t/a.txt"); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
	if _, err := DeleteMembers(DeleteConfig{Archive: archive}); err == nil || !strings.Contains(err.Error(), "at least one pattern") {
		t.Errorf("a delete with no pattern: %v", err)
	}
}

// TestCompactPaths: compact through a link that the program does not follow
// is refused, through a link that loops it names the loop, and an archive
// named with no directory is compacted where it is.
func TestCompactPaths(t *testing.T) {
	archive := mkArchive(t, mutTree(t), false, "t")
	tree := mutTree(t)
	if _, err := appendTo(t, archive, tree, false, nil, "t/a.txt"); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	link := filepath.Join(dir, "link.ect")
	if err := os.Symlink(archive, link); err != nil {
		t.Skipf("no symbolic links: %v", err)
	}
	saved := mayFollowLink
	mayFollowLink = func(string, fs.FileInfo) bool { return false }
	_, err := CompactArchive(CompactConfig{Archive: link})
	mayFollowLink = saved
	if !errors.Is(err, ErrUnsafeLink) {
		t.Errorf("through a planted link: %v, want %v", err, ErrUnsafeLink)
	}

	os.Symlink("b", filepath.Join(dir, "a"))
	os.Symlink("a", filepath.Join(dir, "b"))
	if _, err := CompactArchive(CompactConfig{Archive: filepath.Join(dir, "a")}); err == nil || !strings.Contains(err.Error(), "resolving") {
		t.Errorf("through a loop: %v", err)
	}

	t.Chdir(filepath.Dir(archive))
	res, err := CompactArchive(CompactConfig{Archive: filepath.Base(archive)})
	if err != nil || res.NothingToDo {
		t.Fatalf("in the current directory: %v, %+v", err, res)
	}
	if ents, _ := os.ReadDir("."); len(ents) != 1 {
		t.Errorf("the directory holds %d files after the compact, want 1", len(ents))
	}
}

// TestCompactWarnsWhenTheOwnerCannotBeKept: the compacted archive gets the
// owner of the old one where the process may set it, and a warning where it
// may not.
func TestCompactWarnsWhenTheOwnerCannotBeKept(t *testing.T) {
	archive := mkArchive(t, mutTree(t), false, "t")
	if _, err := appendTo(t, archive, mutTree(t), false, nil, "t/a.txt"); err != nil {
		t.Fatal(err)
	}
	if !meta.Stat(mustStat(t, archive)).OK {
		t.Skip("this platform records no owner, so compact does not set one")
	}
	rep := &recordingReporter{}
	ff := &faultFS{failOp: "chown"}
	if err := withFS(ff, func() error {
		_, err := CompactArchive(CompactConfig{Archive: archive, Reporter: rep})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(rep.warnings) != 1 || !strings.Contains(rep.warnings[0], "could not keep the owner") {
		t.Errorf("warnings %q, want one about the owner", rep.warnings)
	}
}

// TestCompactProgress: the meter of a compact gets the bytes of the blobs it
// copies, and that of a recompress the content it decodes.
func TestCompactProgress(t *testing.T) {
	tree := mutTree(t)
	tree.Text("t/big.txt", 0o644, strings.Repeat("several chunks of text. ", 2000))
	for _, rc := range []*RecompressConfig{nil, {Codec: "zstd"}} {
		archive := mkArchive(t, tree, false, "t")
		if _, err := appendTo(t, archive, tree, false, nil, "t/a.txt"); err != nil {
			t.Fatal(err)
		}
		r, err := Open(archive, nil)
		if err != nil {
			t.Fatal(err)
		}
		var blobs, payload int64
		for _, m := range kept(r.index.Members) {
			blobs += int64(m.Length)
			if m.Data == 0 { // a member that shares content is not decoded again
				payload += int64(m.PayloadSize())
			}
		}
		r.Close()
		want := blobs
		if rc != nil {
			want = payload
		}
		p := &progressRecorder{}
		if _, err := CompactArchive(CompactConfig{Archive: archive, Reporter: p, Recompress: rc}); err != nil {
			t.Fatal(err)
		}
		if p.total != want || p.advanced != want {
			t.Errorf("recompress %v: total %d, advanced %d; want %d each", rc != nil, p.total, p.advanced, want)
		}
	}
}

// TestRewrapChecks: a change of passphrase takes the new KDF parameters that
// are given, keeps the others, and refuses parameters that are not valid,
// that the format does not allow, or that this machine cannot afford, and a
// new passphrase that is empty or cannot be read.
func TestRewrapChecks(t *testing.T) {
	newPass := passphrase("battery staple")
	archive := mkArchive(t, mutTree(t), true, "t")

	path := copyArchive(t, archive)
	if _, err := CompactArchive(CompactConfig{Archive: path, Open: openFor(true),
		Rewrap: &RewrapConfig{Passphrase: newPass, Params: crypt.KDFParams{Threads: 2, Memory: 16 * 1024}}}); err != nil {
		t.Fatal(err)
	}
	r, err := Open(path, newPass)
	if err != nil {
		t.Fatal(err)
	}
	if c := r.crypto; c.Threads != 2 || c.Memory != 16*1024 || c.Time != testKDF.Time {
		t.Errorf("KDF parameters %d, %d KiB, %d threads; want the time kept, 16 MiB and 2 threads", c.Time, c.Memory, c.Threads)
	}
	r.Close()

	errNoTerminal := errors.New("no terminal")
	for _, tc := range []struct {
		name   string
		rw     RewrapConfig
		memory int64 // the RAM that checkAffordable sees; 0 is this machine's
		want   string
	}{
		{"memory below the minimum", RewrapConfig{Passphrase: newPass, Params: crypt.KDFParams{Memory: 1}}, 0, "kdf"},
		{"time past the format's limit", RewrapConfig{Passphrase: newPass, Params: crypt.KDFParams{Time: format.MaxKDFTime + 1}}, 0, "the format allows"},
		{"memory past the format's limit", RewrapConfig{Passphrase: newPass, Params: crypt.KDFParams{Memory: format.MaxKDFMemoryKiB + 1}}, 0, "the format allows"},
		{"memory this machine lacks", RewrapConfig{Passphrase: newPass, Params: crypt.KDFParams{Memory: 64 * 1024}}, 64 << 20, "deriving the key needs"},
		{"a passphrase that cannot be read", RewrapConfig{Passphrase: func() ([]byte, error) { return nil, errNoTerminal }}, 0, "the new passphrase"},
		{"an empty passphrase", RewrapConfig{Passphrase: func() ([]byte, error) { return nil, nil }}, 0, "empty passphrase"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.memory != 0 {
				saved := kdfMemory
				t.Cleanup(func() { kdfMemory = saved })
				kdfMemory = func() int64 { return tc.memory }
			}
			before := readAll(t, archive)
			_, err := CompactArchive(CompactConfig{Archive: archive, Open: openFor(true), Rewrap: &tc.rw})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("%v, want %q", err, tc.want)
			}
			if string(readAll(t, archive)) != string(before) {
				t.Error("the archive changed")
			}
		})
	}
}

// TestRecompressChoices: no codec stores the content, no chunk size takes the
// default, a codec compresses, the count is that of the members encoded
// again, and an unknown codec is refused.
func TestRecompressChoices(t *testing.T) {
	tree := mutTree(t)
	tree.Text("t/big.txt", 0o644, strings.Repeat("several chunks of text. ", 2000))
	tree.Text("t/copy.txt", 0o644, "alpha")
	archive := mkArchive(t, tree, false, "t")
	blobs := 0
	r, err := Open(archive, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range r.index.Members {
		if m.Length > 0 {
			blobs++
		}
	}
	r.Close()

	path := copyArchive(t, archive)
	res, err := CompactArchive(CompactConfig{Archive: path, Recompress: &RecompressConfig{}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Recompressed != blobs {
		t.Errorf("%d members encoded again, want %d", res.Recompressed, blobs)
	}
	r, err = Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range r.index.Members {
		if m.Length > 0 && (m.Codec != format.NoCodec || m.ChunkSize != DefaultChunkSize || m.Length != m.PayloadSize()) {
			t.Errorf("%s: codec %d, chunk %d, %d bytes of %d; want stored, in chunks of the default size", m.Path, m.Codec, m.ChunkSize, m.Length, m.PayloadSize())
		}
	}
	if len(r.index.Codecs) != 0 {
		t.Errorf("catalog %+v, want none", r.index.Codecs)
	}
	r.Close()

	if _, err := CompactArchive(CompactConfig{Archive: path, Recompress: &RecompressConfig{Codec: "zstd"}}); err != nil {
		t.Fatal(err)
	}
	r, err = Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range r.index.Members {
		if m.Path == "t/big.txt" && m.Length >= m.PayloadSize()/4 {
			t.Errorf("t/big.txt is %d bytes of %d after a recompress to zstd", m.Length, m.PayloadSize())
		}
	}
	r.Close()

	if _, err := CompactArchive(CompactConfig{Archive: path, Recompress: &RecompressConfig{Codec: "nonesuch"}}); err == nil {
		t.Error("an unknown codec was accepted")
	}
}

// TestVerifyCounts: a damaged member fails, and so does each selected member
// that shares its content. The counts, the warnings and the members reported
// are those of the selection. Many members go to the workers in several
// batches, and each is reported once.
func TestVerifyCounts(t *testing.T) {
	tree := testutil.NewTree(t)
	for i := range 150 {
		tree.Text(fmt.Sprintf("d/f%03d", i), 0o644, fmt.Sprintf("file %d", i))
	}
	tree.Text("d/owner", 0o644, "shared content")
	tree.Text("d/sharer", 0o644, "shared content")
	path := copyArchive(t, mkArchive(t, tree, false, "d"))

	rep := &memberRecorder{}
	res, err := VerifyArchive(VerifyConfig{Archive: path, Reporter: rep, Workers: 4})
	if err != nil || res.Checked != 152 || len(rep.members) != 152 {
		t.Fatalf("an archive with no damage: %v, %d checked, %d reported; want 152", err, res.Checked, len(rep.members))
	}

	r, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Of two files with the same content, the one that the pipeline emits
	// first holds the blob, and the other shares it.
	var off int64
	owner, sharer := "", ""
	for _, m := range r.index.Members {
		switch {
		case m.Path != "d/owner" && m.Path != "d/sharer":
		case m.Data != 0:
			sharer = m.Path
		default:
			owner, off = m.Path, int64(m.Offset)
		}
	}
	r.Close()
	if owner == "" || sharer == "" {
		t.Fatalf("owner %q, sharer %q: the two copies do not share", owner, sharer)
	}
	b := readAll(t, path)
	b[off] ^= 0xff
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}

	rep = &memberRecorder{}
	res, err = VerifyArchive(VerifyConfig{Archive: path, Reporter: rep})
	if !IsDamage(err) || res.Failed != 2 || res.Checked != 150 || !strings.Contains(err.Error(), "2 of 152 members") {
		t.Errorf("all members: %v, %d failed, %d checked", err, res.Failed, res.Checked)
	}
	rep = &memberRecorder{}
	res, err = VerifyArchive(VerifyConfig{Archive: path, Reporter: rep, Patterns: []string{sharer}})
	if !IsDamage(err) || res.Failed != 1 || res.Checked != 0 || !strings.Contains(err.Error(), "1 of 1 members") ||
		len(rep.warnings) != 2 || !strings.Contains(rep.warnings[1], "has the content of "+owner+", which failed") {
		t.Errorf("the sharer only: %v, %d failed, %d checked, warnings %q", err, res.Failed, res.Checked, rep.warnings)
	}
}

// TestInfoCounts: --info counts the members with no codec of their own, and
// the members of each codec.
func TestInfoCounts(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Text("d/a", 0o644, "alpha")
	tree.Text("d/b", 0o644, "bravo")
	tree.Text("d/copy", 0o644, "alpha")
	for _, tc := range []struct {
		codec   string
		stored  int
		members []int
	}{
		{"zstd", 1, []int{2}}, // the copy shares, with no codec
		{"none", 3, nil},
	} {
		archive := filepath.Join(t.TempDir(), "x.ect")
		if _, err := CreateArchive(CreateConfig{Archive: archive, Paths: []string{"d"}, BaseDir: tree.Root,
			Options: Options{Codec: tc.codec}}); err != nil {
			t.Fatal(err)
		}
		in, err := Info(archive, OpenOptions{})
		if err != nil {
			t.Fatal(err)
		}
		var members []int
		for _, c := range in.Codecs {
			members = append(members, c.Members)
		}
		if in.Stored != tc.stored || !slices.Equal(members, tc.members) {
			t.Errorf("%s: %d stored, codecs %v; want %d, %v", tc.codec, in.Stored, members, tc.stored, tc.members)
		}
	}
}

// TestRepairSkipsTheTrailersOfNestedArchives: an archive stored without
// compression holds the trailers of the archives in it, and a later version
// of eictar can have made them. Repair takes such a trailer as no
// generation of this archive, and goes on to the one before.
func TestRepairSkipsTheTrailersOfNestedArchives(t *testing.T) {
	newer, err := (&format.Trailer{VersionMajor: format.VersionMajor + 1}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	tree := testutil.NewTree(t)
	tree.Text("a.txt", 0o644, "alpha")
	tree.File("nested.ect", 0o644, append(append([]byte(strings.Repeat("x", 100)), newer...), strings.Repeat("y", 100)...))
	path := filepath.Join(t.TempDir(), "x.ect")
	if _, err := CreateArchive(CreateConfig{Archive: path, Paths: []string{"a.txt"}, BaseDir: tree.Root,
		Options: Options{Codec: "none"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := appendTo(t, path, tree, false, func(c *AppendConfig) { c.Options.Codec = "none" }, "nested.ect"); err != nil {
		t.Fatal(err)
	}
	// Damage the index of the second generation: the scan goes past its
	// trailer, to the one inside nested.ect, and then to the first.
	r, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	at := int64(r.Trailer().IndexOffset) + 5
	r.Close()
	b := readAll(t, path)
	b[at] ^= 0xff
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := RepairArchive(path, OpenOptions{})
	if err != nil || res.Generation != 1 {
		t.Fatalf("RepairArchive = generation %d, %v; want the first generation", res.Generation, err)
	}
}

// TestRepairAsksOnce: an index that fails authentication is found after the
// passphrase was asked for, and repair needs the keys again. It asks once.
func TestRepairAsksOnce(t *testing.T) {
	tree := mutTree(t)
	path := mkArchive(t, tree, true, "t")
	tree.Text("t/a.txt", 0o644, "alpha again")
	if _, err := appendTo(t, path, tree, true, nil, "t/a.txt"); err != nil {
		t.Fatal(err)
	}
	r, err := Open(path, passphrase("correct horse"))
	if err != nil {
		t.Fatal(err)
	}
	at := int64(r.Trailer().IndexOffset) + 5
	r.Close()
	b := readAll(t, path)
	b[at] ^= 0xff
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	asked := 0
	res, err := RepairArchive(path, OpenOptions{Passphrase: func() ([]byte, error) {
		asked++
		return []byte("correct horse"), nil
	}})
	if err != nil || res.Generation != 1 || asked != 1 {
		t.Errorf("RepairArchive = generation %d, %v, after %d questions; want generation 1 after 1", res.Generation, err, asked)
	}
}

// TestVerifyProgress: the meter of a verify gets the content that it
// decodes, and advances by all of it.
func TestVerifyProgress(t *testing.T) {
	tree := mutTree(t)
	tree.Text("t/big.txt", 0o644, strings.Repeat("several chunks of text. ", 2000))
	p := &progressRecorder{}
	if _, err := VerifyArchive(VerifyConfig{Archive: mkArchive(t, tree, false, "t"), Reporter: p}); err != nil {
		t.Fatal(err)
	}
	want := int64(len("alpha") + len("bravo") + len("charlie") + 48000)
	if p.total != want || p.advanced != want {
		t.Errorf("total %d, advanced %d; want %d each", p.total, p.advanced, want)
	}
}

// TestInfoOfNoArchive: --info of a path with no archive is its error.
func TestInfoOfNoArchive(t *testing.T) {
	if _, err := Info(filepath.Join(t.TempDir(), "none.ect"), OpenOptions{}); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Info = %v, want %v", err, os.ErrNotExist)
	}
}

// TestCompactKeepsTheOwner only runs as root, where the compacted archive can
// get the owner of the old one.
func TestCompactKeepsTheOwner(t *testing.T) {
	if !meta.IsRoot() {
		t.Skip("giving a file to another owner needs root")
	}
	path := mkArchive(t, mutTree(t), false, "t")
	if _, err := appendTo(t, path, mutTree(t), false, nil, "t/a.txt"); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 12345, 23456); err != nil {
		t.Fatal(err)
	}
	if _, err := CompactArchive(CompactConfig{Archive: path}); err != nil {
		t.Fatal(err)
	}
	if info := meta.Stat(mustStat(t, path)); info.UID != 12345 || info.GID != 23456 {
		t.Errorf("owner %d:%d, want 12345:23456", info.UID, info.GID)
	}
}

// TestRepairWithNoGeneration: an archive with no complete generation is
// damage that repair cannot mend, and the scan ends at the start of the body.
func TestRepairWithNoGeneration(t *testing.T) {
	path := copyArchive(t, mkArchive(t, mutTree(t), false, "t"))
	r, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	at := int64(r.Trailer().IndexOffset) + 5
	r.Close()
	b := readAll(t, path)
	b[at] ^= 0xff
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := RepairArchive(path, OpenOptions{}); !errors.Is(err, format.ErrCorruptIndex) || !strings.Contains(err.Error(), "no complete generation") {
		t.Errorf("RepairArchive = %v, want no complete generation", err)
	}
}
