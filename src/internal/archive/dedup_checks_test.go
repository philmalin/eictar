package archive

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/philmalin/eictar/src/internal/format"
)

// Tests of the table of owners (dedup.go), by itself.

// TestIsOwner: only a regular file with a blob of its own, and a digest,
// owns content.
func TestIsOwner(t *testing.T) {
	digest := make([]byte, format.DigestSize)
	owner := format.Member{Type: format.TypeReg, Length: 10, Digest: digest}
	for _, tc := range []struct {
		name string
		edit func(*format.Member)
		want bool
	}{
		{"an owner", func(*format.Member) {}, true},
		{"not a file", func(m *format.Member) { m.Type = format.TypeSymlink }, false},
		{"a sharer", func(m *format.Member) { m.Data = 3 }, false},
		{"no blob", func(m *format.Member) { m.Length = 0 }, false},
		{"no digest", func(m *format.Member) { m.Digest = nil }, false},
	} {
		m := owner
		tc.edit(&m)
		if got := isOwner(&m); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestContentKey: the digest, the size and each data segment, in order. A
// file can have many segments.
func TestContentKey(t *testing.T) {
	m := &format.Member{
		Digest: bytes.Repeat([]byte{7}, format.DigestSize),
		Size:   100,
		Sparse: []format.SparseSegment{{Offset: 0, Length: 1}, {Offset: 10, Length: 2}, {Offset: 50, Length: 3}, {Offset: 60, Length: 4}, {Offset: 70, Length: 5}, {Offset: 80, Length: 6}},
	}
	want := append([]byte(nil), m.Digest...)
	for _, v := range []uint64{100, 0, 1, 10, 2, 50, 3, 60, 4, 70, 5, 80, 6} {
		want = binary.LittleEndian.AppendUint64(want, v)
	}
	if got := contentKey(m); got != string(want) {
		t.Errorf("key %x, want %x", got, want)
	}
}

// TestDedupOfThisRun: the first owner that a run writes, at firstNew, is
// shared at once, and its size is known.
func TestDedupOfThisRun(t *testing.T) {
	d := newDedup(nil, 5)
	file := func(id uint64) *format.Member {
		return &format.Member{ID: id, Type: format.TypeReg, Size: 10, Digest: bytes.Repeat([]byte{1}, format.DigestSize)}
	}
	if d.hasSize(10) {
		t.Error("a size before any owner")
	}
	if owner, share := d.atEmit(file(5)); share || owner != 0 {
		t.Errorf("the first: %d, %v; want it to own the content", owner, share)
	}
	if !d.hasSize(10) || d.hasSize(11) {
		t.Errorf("sizes %v; want 10 alone", d.sizes)
	}
	if owner, err := d.usable(file(6)); owner != 5 || err != nil {
		t.Errorf("usable: %d, %v; want 5", owner, err)
	}
	if owner, share := d.atEmit(file(6)); !share || owner != 5 {
		t.Errorf("a copy: %d, %v; want it to share 5", owner, share)
	}
}

// TestDedupOldOwnerThatFails: an old owner whose blob fails its check is not
// used, and it is not checked again.
func TestDedupOldOwnerThatFails(t *testing.T) {
	path := copyArchive(t, mkArchive(t, mutTree(t), false, "t"))
	r, err := OpenWith(path, OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var a format.Member
	for _, m := range r.Members() {
		if m.Path == "t/a.txt" {
			a = m
		}
	}
	r.Close()
	flipByteAt(t, path, int64(a.Offset))
	r, err = OpenWith(path, OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	d := newDedup(r, 100)
	copyOf := a
	copyOf.ID = 100
	if owner, err := d.usable(&copyOf); owner != 0 || err == nil {
		t.Errorf("first: %d, %v; want the failure of the check", owner, err)
	}
	if owner, err := d.usable(&copyOf); owner != 0 || err != nil {
		t.Errorf("again: %d, %v; want no owner, and no check", owner, err)
	}
	if owner, share := d.atEmit(&copyOf); share || owner != 0 {
		t.Errorf("at emit: %d, %v; want the copy to own the content", owner, share)
	}
}
