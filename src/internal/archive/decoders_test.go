package archive

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"github.com/philmalin/eictar/src/internal/format"
)

// Tests of the pool of decoders in the Reader (doc/design.md 15.2).

// mixedArchive holds members with three kinds of decoder: zstd with a
// dictionary in 4 MiB chunks, gzip in 4 KiB chunks, and zstd with no
// dictionary in 4 KiB chunks.
func mixedArchive(t *testing.T) (string, string) {
	t.Helper()
	tree := dictTree(t, "src", 90)
	files := func(from, to int) []string {
		var out []string
		for i := from; i < to; i++ {
			out = append(out, fmt.Sprintf("src/f%03d.go", i))
		}
		return out
	}
	archive := dictCreate(t, tree, false, trainParams, nil, files(0, 50)...)
	if _, err := appendTo(t, archive, tree, false, func(c *AppendConfig) { c.Options.Codec = "gzip" }, files(50, 70)...); err != nil {
		t.Fatal(err)
	}
	if _, err := appendTo(t, archive, tree, false, nil, files(70, 90)...); err != nil {
		t.Fatal(err)
	}
	return archive, tree.Root
}

// checkMember decodes m and compares it with the file in root.
func checkMember(t *testing.T, r *Reader, m *format.Member, root string) {
	t.Helper()
	var got bytes.Buffer
	if err := r.WriteMember(m, &got); err != nil {
		t.Errorf("%s: %v", m.Path, err)
		return
	}
	want, err := os.ReadFile(filepath.Join(root, m.Path))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Errorf("%s: decoded content differs from the file", m.Path)
	}
}

// TestDecoderPoolReuse: one decoder serves each kind of member, members of
// different kinds do not share one, and the content is right in any order.
func TestDecoderPoolReuse(t *testing.T) {
	archive, root := mixedArchive(t)
	r := openDict(t, archive, false)
	var files []*format.Member
	for i := range r.index.Members {
		if m := &r.index.Members[i]; m.Type.HasPayload() {
			files = append(files, m)
		}
	}
	if len(files) != 90 {
		t.Fatalf("%d files, want 90", len(files))
	}
	// In index order, then each third in turn, so that the kinds alternate.
	for _, m := range files {
		checkMember(t, r, m, root)
	}
	for k := range 3 {
		for i := k; i < len(files); i += 3 {
			checkMember(t, r, files[i], root)
		}
	}
	if len(r.decoders) != 3 {
		t.Errorf("%d kinds of decoder, want 3: %v", len(r.decoders), slices.Collect(maps.Keys(r.decoders)))
	}
	for key, list := range r.decoders {
		if len(list) != 1 {
			t.Errorf("%+v: %d decoders, want 1 for one goroutine", key, len(list))
		}
	}

	// From several goroutines: each takes its own decoder.
	const workers = 8
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := w; i < len(files); i += workers {
				checkMember(t, r, files[i], root)
			}
		}()
	}
	wg.Wait()
	for key, list := range r.decoders {
		if len(list) < 1 || len(list) > workers {
			t.Errorf("%+v: %d decoders, want 1 to %d", key, len(list), workers)
		}
	}
}

// TestDecoderPoolDropsFailedDecoder: a decoder that returned an error is
// closed, and does not go back to the pool.
func TestDecoderPoolDropsFailedDecoder(t *testing.T) {
	tree := dictTree(t, "src", 2)
	archive := dictCreate(t, tree, false, nil, nil, "src")
	r := openDict(t, archive, false)
	good, bad := &r.index.Members[1], &r.index.Members[2]
	r.Close()
	if !good.Type.HasPayload() || !bad.Type.HasPayload() || good.Data != 0 || bad.Data != 0 {
		t.Fatalf("want two files with blobs of their own: %+v, %+v", good, bad)
	}
	// Bytes that are not a zstd frame, and are shorter than the plaintext,
	// so that the reader gives them to the decoder.
	f, err := os.OpenFile(archive, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(bytes.Repeat([]byte{0xff}, int(bad.Length)), int64(bad.Offset)); err != nil {
		t.Fatal(err)
	}
	f.Close()

	r = openDict(t, archive, false)
	checkMember(t, r, good, tree.Root)
	key := decoderKey{codec: "zstd", chunk: int(good.ChunkSize)}
	if len(r.decoders[key]) != 1 {
		t.Fatalf("after a good member: %d decoders, want 1", len(r.decoders[key]))
	}
	if err := r.WriteMember(bad, &bytes.Buffer{}); !errors.Is(err, format.ErrCorruptData) {
		t.Fatalf("damaged member: %v, want a decode error", err)
	}
	if len(r.decoders[key]) != 0 {
		t.Errorf("after a decode error: %d decoders in the pool, want 0", len(r.decoders[key]))
	}
	checkMember(t, r, good, tree.Root)
}

// closeCounter is a Decoder that records Close.
type closeCounter struct{ closed int }

func (c *closeCounter) Decode(dst, _ []byte, _ int) ([]byte, error) { return dst, nil }
func (c *closeCounter) Close() error                                { c.closed++; return nil }

// TestDecoderPoolClose: Close closes each free decoder, and a decoder that
// comes back after Close is closed at once.
func TestDecoderPoolClose(t *testing.T) {
	tree := dictTree(t, "src", 1)
	r := openDict(t, dictCreate(t, tree, false, nil, nil, "src"), false)
	key := decoderKey{codec: "zstd", chunk: 1}
	free, late := &closeCounter{}, &closeCounter{}
	r.giveDecoder(key, free)
	r.Close()
	if free.closed != 1 {
		t.Errorf("a free decoder was closed %d times by Close, want 1", free.closed)
	}
	r.giveDecoder(key, late)
	if late.closed != 1 || r.decoders != nil {
		t.Errorf("a decoder given back after Close: closed %d times, pool %v", late.closed, r.decoders)
	}
}

// TestDecoderSet: a worker's set keeps one decoder for each kind, drop closes
// the one that failed, and close closes the rest.
func TestDecoderSet(t *testing.T) {
	archive, root := mixedArchive(t)
	r := openDict(t, archive, false)
	set := r.newDecoderSet()
	for i := range r.index.Members {
		if m := &r.index.Members[i]; m.Type.HasPayload() {
			var got bytes.Buffer
			if err := r.writeMember(m, &got, set); err != nil {
				t.Fatalf("%s: %v", m.Path, err)
			}
			want, err := os.ReadFile(filepath.Join(root, m.Path))
			if err != nil || !bytes.Equal(got.Bytes(), want) {
				t.Errorf("%s: decoded content differs (%v)", m.Path, err)
			}
		}
	}
	if len(set.dec) != 3 || len(r.decoders) != 0 {
		t.Fatalf("set holds %d decoders and the pool %d kinds, want 3 and 0", len(set.dec), len(r.decoders))
	}
	failed, other := &closeCounter{}, &closeCounter{}
	set.dec[decoderKey{codec: "x"}] = failed
	set.dec[decoderKey{codec: "y"}] = other
	set.drop(decoderKey{codec: "x"})
	if failed.closed != 1 || len(set.dec) != 4 {
		t.Errorf("drop: closed %d times, %d left", failed.closed, len(set.dec))
	}
	set.close()
	if other.closed != 1 || len(set.dec) != 0 {
		t.Errorf("close: closed %d times, %d left", other.closed, len(set.dec))
	}
}

// TestDecoderKindsAreBounded: a hostile index can give each member a kind of
// decoder of its own, here a chunk size of its own. The pool and a worker's
// set keep at most maxDecoderKinds kinds, and each decode is still right.
func TestDecoderKindsAreBounded(t *testing.T) {
	tree := dictTree(t, "src", 1)
	r := openDict(t, dictCreate(t, tree, false, nil, nil, "src"), false)
	var file format.Member
	for _, m := range r.index.Members {
		if m.Type.HasPayload() {
			file = m
		}
	}
	if len(file.Chunks) != 1 {
		t.Fatalf("want a member of one chunk, got %d", len(file.Chunks))
	}
	set := r.newDecoderSet()
	defer set.close()
	const kinds = 40
	if kinds <= maxDecoderKinds {
		t.Fatalf("the test needs more than %d kinds", maxDecoderKinds)
	}
	for k := range kinds {
		// One chunk fits any chunk size at least as large as the content.
		m := file
		m.ChunkSize = uint32(m.Size) + uint32(k)
		checkMember(t, r, &m, tree.Root)
		var got bytes.Buffer
		if err := r.writeMember(&m, &got, set); err != nil {
			t.Fatalf("chunk size %d, with a set: %v", m.ChunkSize, err)
		}
	}
	if len(r.decoders) != maxDecoderKinds {
		t.Errorf("the pool keeps %d kinds after %d, want %d", len(r.decoders), kinds, maxDecoderKinds)
	}
	if len(set.dec) != maxDecoderKinds {
		t.Errorf("the set keeps %d kinds after %d, want %d", len(set.dec), kinds, maxDecoderKinds)
	}
}
