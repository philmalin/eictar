package archive

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/philmalin/eictar/src/internal/codec"
	"github.com/philmalin/eictar/src/internal/testutil"
)

// Tests of the dictionaries of doc/design.md 4.2.

// trainParams asks for a small dictionary, which a test tree can fill.
var trainParams = codec.Params{"level": "19", "train": "16K"}

// dictTree is a source tree in miniature: many small files that repeat most
// of their text.
func dictTree(t *testing.T, dir string, n int) *testutil.Tree {
	t.Helper()
	tree := testutil.NewTree(t)
	tree.Dir(dir, 0o755)
	for i := 0; i < n; i++ {
		var b strings.Builder
		b.WriteString("// Copyright 2026 The Example Authors. All rights reserved.\n")
		b.WriteString("// Use of this source code is governed by a BSD-style license.\n\n")
		fmt.Fprintf(&b, "package pkg%d\n\nimport (\n\t\"fmt\"\n\t\"io\"\n)\n\n", i%5)
		for j := 0; j < 4+i%3; j++ {
			fmt.Fprintf(&b, "func helper%d_%d(w io.Writer) error {\n\t_, err := fmt.Fprintln(w, %d)\n\treturn err\n}\n\n", i, j, i*j)
		}
		tree.Text(fmt.Sprintf("%s/f%03d.go", dir, i), 0o644, b.String())
	}
	return tree
}

func dictCreate(t *testing.T, tree *testutil.Tree, encrypted bool, params codec.Params, rep Reporter, paths ...string) string {
	t.Helper()
	cfg := CreateConfig{
		Archive:  filepath.Join(t.TempDir(), "d.ect"),
		Paths:    paths,
		BaseDir:  tree.Root,
		Options:  Options{Codec: "zstd", Params: params},
		Reporter: rep,
	}
	if encrypted {
		cfg.Encryption = &EncryptionConfig{Passphrase: []byte("correct horse"), Params: testKDF}
	}
	if _, err := CreateArchive(cfg); err != nil {
		t.Fatalf("CreateArchive: %v", err)
	}
	return cfg.Archive
}

func openDict(t *testing.T, archive string, encrypted bool) *Reader {
	t.Helper()
	r, err := OpenWith(archive, openFor(encrypted))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r
}

// checkRoundTrip verifies the archive and extracts it, and compares the
// result with the tree.
func checkRoundTrip(t *testing.T, archive string, encrypted bool, tree *testutil.Tree, dir string) {
	t.Helper()
	if _, err := VerifyArchive(VerifyConfig{Archive: archive, Open: openFor(encrypted)}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	dest := t.TempDir()
	if _, err := Extract(ExtractConfig{Archive: archive, Destination: dest, Passphrase: openFor(encrypted).Passphrase}); err != nil {
		t.Fatalf("extract: %v", err)
	}
	testutil.CompareTrees(t, filepath.Join(tree.Root, dir), filepath.Join(dest, dir), testutil.CompareOptions{})
}

func TestDictionaryCreate(t *testing.T) {
	for _, enc := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "encrypted"}[enc], func(t *testing.T) {
			tree := dictTree(t, "src", 150)
			withDict := dictCreate(t, tree, enc, trainParams, nil, "src")
			without := dictCreate(t, tree, enc, codec.Params{"level": "19"}, nil, "src")

			r := openDict(t, withDict, enc)
			if len(r.index.Dicts) != 1 || len(r.index.Codecs) != 1 || r.index.Codecs[0].Dict != r.index.Dicts[0].ID {
				t.Fatalf("dicts %+v, codecs %+v", r.index.Dicts, r.index.Codecs)
			}
			d := r.index.Dicts[0]
			if (d.Enc != nil) != enc {
				t.Errorf("dictionary sealed = %v, want %v", d.Enc != nil, enc)
			}
			// A sealed dictionary does not show its magic, 37 A4 30 EC.
			raw := readAll(t, withDict)[d.Offset : d.Offset+4]
			if isMagic := bytes.Equal(raw, []byte{0x37, 0xa4, 0x30, 0xec}); isMagic == enc {
				t.Errorf("encrypted=%v: the blob starts with the dictionary magic: %v", enc, isMagic)
			}
			if a, b := mustStat(t, withDict).Size(), mustStat(t, without).Size(); a >= b {
				t.Errorf("with a dictionary %d bytes, without %d", a, b)
			}
			checkRoundTrip(t, withDict, enc, tree, "src")

			in, err := Info(withDict, openFor(enc))
			if err != nil || len(in.Dicts) != 1 || in.Dicts[0].Members != 150 {
				t.Errorf("info: %+v, %v", in.Dicts, err)
			}
		})
	}
}

// TestDictionaryAppend: -r with train reuses the archive's dictionary; -r
// without it uses none; and train on an archive with no dictionary makes one.
func TestDictionaryAppend(t *testing.T) {
	tree := dictTree(t, "src", 150)
	more := dictTree(t, "more", 40)
	if err := os.Rename(filepath.Join(more.Root, "more"), filepath.Join(tree.Root, "more")); err != nil {
		t.Fatal(err)
	}
	archive := dictCreate(t, tree, true, trainParams, nil, "src")
	id := openDict(t, archive, true).index.Dicts[0].ID

	appendDict := func(params codec.Params, paths ...string) {
		t.Helper()
		if _, err := appendTo(t, archive, tree, true, func(c *AppendConfig) { c.Options.Params = params }, paths...); err != nil {
			t.Fatal(err)
		}
	}
	appendDict(trainParams, "more/f000.go", "more/f001.go")
	r := openDict(t, archive, true)
	if len(r.index.Dicts) != 1 || len(r.index.Codecs) != 1 {
		t.Errorf("after -r with train: dicts %+v, codecs %+v; want the one dictionary reused", r.index.Dicts, r.index.Codecs)
	}

	appendDict(codec.Params{"level": "19"}, "more/f002.go")
	r = openDict(t, archive, true)
	if len(r.index.Dicts) != 1 || len(r.index.Codecs) != 2 || r.index.Codecs[1].Dict != 0 {
		t.Errorf("after -r without train: codecs %+v; want a second entry with no dictionary", r.index.Codecs)
	}
	if r.index.Dicts[0].ID != id {
		t.Error("the dictionary changed")
	}
	checkRoundTrip(t, archive, true, tree, "src")

	// An archive with no dictionary: train makes one, from the new files.
	plain := dictCreate(t, tree, false, codec.Params{"level": "19"}, nil, "src")
	if _, err := appendTo(t, plain, tree, false, func(c *AppendConfig) { c.Options.Params = trainParams }, "more"); err != nil {
		t.Fatal(err)
	}
	r = openDict(t, plain, false)
	if len(r.index.Dicts) != 1 || r.index.Dicts[0].Generation != 2 {
		t.Errorf("after -r with train on an archive without one: %+v", r.index.Dicts)
	}
	checkRoundTrip(t, plain, false, tree, "more")
}

// TestDictionaryCompact: compact keeps a dictionary while a member uses it,
// drops it after, and drops the catalog entry that named it.
func TestDictionaryCompact(t *testing.T) {
	tree := dictTree(t, "src", 150)
	archive := dictCreate(t, tree, false, trainParams, nil, "src")
	if _, err := DeleteMembers(DeleteConfig{Archive: archive, Patterns: []string{"src/f000.go"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := CompactArchive(CompactConfig{Archive: archive}); err != nil {
		t.Fatal(err)
	}
	r := openDict(t, archive, false)
	if len(r.index.Dicts) != 1 {
		t.Errorf("compact dropped a dictionary in use: %+v", r.index.Dicts)
	}
	r.Close()
	if _, err := VerifyArchive(VerifyConfig{Archive: archive}); err != nil {
		t.Fatal(err)
	}

	// Replace the whole tree without a dictionary, then compact. The content
	// is the same, so without --no-dedup the new members would share the old
	// blobs (doc/design.md 4.3), and those blobs need the dictionary.
	if _, err := appendTo(t, archive, tree, false, func(c *AppendConfig) { c.NoDedup = true }, "src"); err != nil {
		t.Fatal(err)
	}
	before, err := Info(archive, OpenOptions{})
	if err != nil || len(before.Dicts) != 1 || before.Dicts[0].Members != 0 {
		t.Fatalf("info before compact: %+v, %v", before.Dicts, err)
	}
	if before.DeadSpace < int64(before.Dicts[0].Dict.Length) {
		t.Errorf("dead space %d does not count the unused dictionary", before.DeadSpace)
	}
	if _, err := CompactArchive(CompactConfig{Archive: archive}); err != nil {
		t.Fatal(err)
	}
	r = openDict(t, archive, false)
	if len(r.index.Dicts) != 0 || len(r.index.Codecs) != 1 || r.index.Codecs[0].Dict != 0 {
		t.Errorf("after compact: dicts %+v, codecs %+v", r.index.Dicts, r.index.Codecs)
	}
	checkRoundTrip(t, archive, false, tree, "src")
}

// TestDictionaryRecompress: --recompress zstd:train trains a new dictionary
// from the members, and --recompress without train leaves none.
func TestDictionaryRecompress(t *testing.T) {
	for _, enc := range []bool{false, true} {
		tree := dictTree(t, "src", 150)
		archive := dictCreate(t, tree, enc, trainParams, nil, "src")
		old := openDict(t, archive, enc).index.Dicts[0].ID

		recompress := func(params codec.Params) {
			t.Helper()
			if _, err := CompactArchive(CompactConfig{Archive: archive, Open: openFor(enc),
				Recompress: &RecompressConfig{Codec: "zstd", Params: params}}); err != nil {
				t.Fatal(err)
			}
		}
		recompress(trainParams)
		r := openDict(t, archive, enc)
		if len(r.index.Dicts) != 1 || r.index.Dicts[0].ID == old || r.index.Codecs[0].Dict != r.index.Dicts[0].ID {
			t.Errorf("encrypted=%v: after --recompress with train: %+v, %+v", enc, r.index.Dicts, r.index.Codecs)
		}
		checkRoundTrip(t, archive, enc, tree, "src")

		recompress(codec.Params{"level": "3"})
		r = openDict(t, archive, enc)
		if len(r.index.Dicts) != 0 || r.index.Codecs[0].Dict != 0 {
			t.Errorf("encrypted=%v: after --recompress without train: %+v", enc, r.index.Dicts)
		}
		checkRoundTrip(t, archive, enc, tree, "src")
	}
}

// TestDictionaryDamage: a changed byte in a dictionary is damage, plain or
// sealed, for every member that uses it.
func TestDictionaryDamage(t *testing.T) {
	for _, enc := range []bool{false, true} {
		tree := dictTree(t, "src", 150)
		archive := dictCreate(t, tree, enc, trainParams, nil, "src")
		d := openDict(t, archive, enc).index.Dicts[0]
		b := readAll(t, archive)
		b[d.Offset+d.Length/2] ^= 0x40
		if err := os.WriteFile(archive, b, 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := VerifyArchive(VerifyConfig{Archive: archive, Open: openFor(enc)})
		if err == nil || !IsDamage(err) {
			t.Errorf("encrypted=%v: verify: %v, want damage", enc, err)
		}
	}
}

// TestDictionaryTrainingFails: with nothing to learn from, the archive is
// made without a dictionary, and the reporter says so.
func TestDictionaryTrainingFails(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Text("one.txt", 0o644, "x")
	rep := &recordingReporter{}
	archive := dictCreate(t, tree, false, codec.Params{"train": "on"}, rep, "one.txt")
	r := openDict(t, archive, false)
	if len(r.index.Dicts) != 0 || r.index.Codecs[0].Dict != 0 {
		t.Errorf("dicts %+v, codecs %+v", r.index.Dicts, r.index.Codecs)
	}
	if len(rep.warnings) != 1 || !strings.Contains(rep.warnings[0], "without a dictionary") {
		t.Errorf("warnings %q", rep.warnings)
	}
	if got := extractOne(t, archive, false, "one.txt"); got != "x" {
		t.Errorf("content %q", got)
	}
}

// TestPickSamples: every file within the budget, and every k-th file over it.
func TestPickSamples(t *testing.T) {
	if got := pickSamples([]int{10, 10, 10}, 100); len(got) != 3 {
		t.Errorf("within the budget: %v", got)
	}
	sizes := make([]int, 1000)
	for i := range sizes {
		sizes[i] = 1000
	}
	// 1,000,000 bytes, and a budget of 200,000: every 5th file.
	got := pickSamples(sizes, 200000)
	if len(got) != 200 || got[1] != 5 {
		t.Errorf("over the budget: %d files, the second is %d", len(got), got[1])
	}
}

// proseTree is a small tree where a large dictionary does not pay: each file
// has the same header, then text from a large vocabulary, which the files
// share little of.
func proseTree(t *testing.T, dir string, n int) *testutil.Tree {
	t.Helper()
	rnd := rand.New(rand.NewPCG(3, 4))
	vocab := make([]string, 3000)
	for i := range vocab {
		b := make([]byte, 3+rnd.IntN(6))
		for j := range b {
			b[j] = byte('a' + rnd.IntN(26))
		}
		vocab[i] = string(b)
	}
	tree := testutil.NewTree(t)
	tree.Dir(dir, 0o755)
	for i := range n {
		var b strings.Builder
		b.WriteString("// Copyright 2026 The Example Authors. All rights reserved.\n")
		b.WriteString("// Use of this source code is governed by a BSD-style license.\n\n")
		for b.Len() < 2000 {
			b.WriteString(vocab[rnd.IntN(len(vocab))] + " ")
		}
		tree.Text(fmt.Sprintf("%s/f%03d.txt", dir, i), 0o644, b.String())
	}
	return tree
}

// TestDictionaryAutoSize: train alone measures the size. On a small tree, it
// takes a small dictionary, and the archive is smaller than with the fixed
// 112 KiB that train alone meant before.
func TestDictionaryAutoSize(t *testing.T) {
	tree := proseTree(t, "src", 150)
	auto := dictCreate(t, tree, false, codec.Params{"level": "19", "train": "on"}, nil, "src")
	fixed := dictCreate(t, tree, false, codec.Params{"level": "19", "train": "112K"}, nil, "src")

	r := openDict(t, auto, false)
	if len(r.index.Dicts) != 1 {
		t.Fatalf("dicts %+v", r.index.Dicts)
	}
	if size := r.index.Dicts[0].Size; size > 64<<10 {
		t.Errorf("the dictionary is %d bytes", size)
	}
	a, b := mustStat(t, auto).Size(), mustStat(t, fixed).Size()
	t.Logf("auto %d bytes (dictionary %d), train=112K %d", a, r.index.Dicts[0].Size, b)
	if a >= b*9/10 {
		t.Errorf("auto %d bytes, train=112K %d: want 10%% smaller", a, b)
	}
	checkRoundTrip(t, auto, false, tree, "src")
}

// TestDictionaryAutoNone: on data that a dictionary cannot help, train alone
// makes no dictionary, and the reporter says why.
func TestDictionaryAutoNone(t *testing.T) {
	tree := testutil.NewTree(t)
	tree.Dir("bin", 0o755)
	rnd := rand.New(rand.NewPCG(1, 2))
	for i := range 40 {
		b := make([]byte, 8<<10)
		for j := range b {
			b[j] = byte(rnd.Uint32())
		}
		tree.File(fmt.Sprintf("bin/f%02d", i), 0o644, b)
	}
	rep := &recordingReporter{}
	archive := dictCreate(t, tree, false, codec.Params{"train": "on"}, rep, "bin")
	r := openDict(t, archive, false)
	if len(r.index.Dicts) != 0 || r.index.Codecs[0].Dict != 0 {
		t.Errorf("dicts %+v, codecs %+v", r.index.Dicts, r.index.Codecs)
	}
	if len(rep.warnings) != 1 || !strings.Contains(rep.warnings[0], "saves less than its own size") {
		t.Errorf("warnings %q", rep.warnings)
	}
	checkRoundTrip(t, archive, false, tree, "bin")
}

// TestChooseDictSizeScales: the samples may be every k-th file of a large
// tree. The saving is for the whole tree, so the same samples standing for
// more files ask for a dictionary at least as large. With one worker or
// many, the measurement gives a size.
func TestChooseDictSizeScales(t *testing.T) {
	var samples [][]byte
	for i := range 400 {
		samples = append(samples, []byte(fmt.Sprintf(
			"{\"id\": %d, \"type\": \"order\", \"status\": \"%s\", \"items\": [{\"sku\": \"SKU-%06d\", \"quantity\": %d}], \"shipping\": {\"method\": \"ground\", \"country\": \"AU\"}}\n",
			i, []string{"pending", "paid", "shipped"}[i%3], i*7919%1000000, i%9)))
	}
	total := 0
	for _, s := range samples {
		total += len(s)
	}
	size := func(concurrency, total int) int {
		w := &Writer{codecName: "zstd", params: codec.Params{"train": "on"}, concurrency: concurrency}
		n, err := w.chooseDictSize(samples, total)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	small := size(1, total)
	if small == 0 {
		t.Fatalf("no dictionary for %d similar samples", len(samples))
	}
	if large := size(8, 1000*total); large < small {
		t.Errorf("for %d bytes %d, for 1000 times as many %d", total, small, large)
	}
}

// TestBestTrial: the largest net gain wins, a larger size must win by the
// margin, and two misses in a row stop the measurement.
func TestBestTrial(t *testing.T) {
	tr := func(size int, net float64) dictTrial { return dictTrial{size: size, net: net, ok: true} }
	failed := dictTrial{size: 64, ok: false}
	for _, tc := range []struct {
		name   string
		trials []dictTrial
		best   int
		stop   bool
	}{
		{"none", nil, 0, false},
		{"no gain", []dictTrial{tr(4, -10), tr(8, -20)}, 0, true},
		{"rises", []dictTrial{tr(4, 100), tr(8, 200), tr(16, 300)}, 16, false},
		{"peak", []dictTrial{tr(4, 100), tr(8, 300), tr(16, 200), tr(32, 100), tr(64, 1000)}, 8, true},
		{"within the margin", []dictTrial{tr(4, 1000), tr(8, 1010), tr(16, 1015)}, 4, true},
		{"over the margin", []dictTrial{tr(4, 1000), tr(8, 1030)}, 8, false},
		{"a miss, then a gain", []dictTrial{tr(4, 100), tr(8, 90), tr(16, 200)}, 16, false},
		{"a failure is a miss", []dictTrial{tr(4, 100), failed, tr(16, 50)}, 4, true},
	} {
		best, stop := bestTrial(tc.trials)
		if best != tc.best || stop != tc.stop {
			t.Errorf("%s: %d, %v; want %d, %v", tc.name, best, stop, tc.best, tc.stop)
		}
	}
}
