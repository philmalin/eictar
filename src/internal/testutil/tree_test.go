package testutil

import (
	"os"
	"testing"
	"time"
)

// The fixture machinery is itself tested: a comparison that silently passes
// would make every test above it worthless.

func TestSnapshotRecordsTypes(t *testing.T) {
	tr := NewTree(t)
	tr.Dir("d", 0o755).
		Text("d/file.txt", 0o644, "hello").
		Symlink("link", "d/file.txt").
		Hardlink("d/second", "d/file.txt")

	got := Snapshot(t, tr.Root)
	if len(got) != 4 {
		t.Fatalf("snapshot has %d entries, want 4: %+v", len(got), got)
	}

	byPath := map[string]Entry{}
	for _, e := range got {
		byPath[e.Path] = e
	}

	if !byPath["d"].Mode.IsDir() {
		t.Error("d should be a directory")
	}
	if string(byPath["d/file.txt"].Content) != "hello" {
		t.Errorf("content = %q, want %q", byPath["d/file.txt"].Content, "hello")
	}
	if byPath["link"].Target != "d/file.txt" {
		t.Errorf("symlink target = %q, want %q", byPath["link"].Target, "d/file.txt")
	}
	if byPath["link"].Mode&os.ModeSymlink == 0 {
		t.Error("link should be a symlink; Snapshot must not follow it")
	}
	if g := byPath["d/file.txt"].LinkGroup; g == 0 || g != byPath["d/second"].LinkGroup {
		t.Errorf("hardlinked files should share a link group, got %d and %d",
			g, byPath["d/second"].LinkGroup)
	}
}

func TestCompareTreesIdentical(t *testing.T) {
	build := func() *Tree {
		tr := NewTree(t)
		tr.Dir("sub", 0o750).
			Text("sub/a.txt", 0o600, "alpha").
			Text("b.bin", 0o644, "\x00\xff\x01").
			Symlink("sub/link", "../b.bin")
		// Every entry needs a pinned time, or the two trees differ by the
		// microseconds between building them.
		for _, p := range []string{"sub/a.txt", "b.bin", "sub"} {
			tr.SetTimes(p, time.Unix(1000, 0), time.Unix(2000, 0))
		}
		tr.SetLinkTimes("sub/link", time.Unix(1000, 0), time.Unix(3000, 0))
		return tr
	}
	a, b := build(), build()

	CompareTrees(t, a.Root, b.Root, CompareOptions{Mode: true, MTime: true, Hardlinks: true})
}

// TestCompareTreesDetects is the important one: each mutation must be caught.
// It runs the comparison against a throwaway TB so a detected difference is a
// pass rather than a failure.
func TestCompareTreesDetects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(tb testing.TB, tr *Tree)
		opt    CompareOptions
	}{
		{"missing file", func(tb testing.TB, tr *Tree) {
			os.Remove(tr.Path("a.txt"))
		}, CompareOptions{}},
		{"extra file", func(tb testing.TB, tr *Tree) {
			tr.Text("surprise.txt", 0o644, "x")
		}, CompareOptions{}},
		{"changed content", func(tb testing.TB, tr *Tree) {
			tr.Text("a.txt", 0o644, "different")
		}, CompareOptions{}},
		{"changed size", func(tb testing.TB, tr *Tree) {
			tr.Text("a.txt", 0o644, "alphaalpha")
		}, CompareOptions{}},
		{"changed mode", func(tb testing.TB, tr *Tree) {
			os.Chmod(tr.Path("a.txt"), 0o600)
		}, CompareOptions{Mode: true}},
		{"changed mtime", func(tb testing.TB, tr *Tree) {
			tr.SetTimes("a.txt", time.Unix(1, 0), time.Unix(999999, 0))
		}, CompareOptions{MTime: true}},
		{"symlink became a file", func(tb testing.TB, tr *Tree) {
			os.Remove(tr.Path("link"))
			tr.Text("link", 0o644, "alpha")
		}, CompareOptions{}},
		{"symlink retargeted", func(tb testing.TB, tr *Tree) {
			os.Remove(tr.Path("link"))
			tr.Symlink("link", "elsewhere")
		}, CompareOptions{}},
		{"link retimed", func(tb testing.TB, tr *Tree) {
			tr.SetLinkTimes("link", time.Unix(1, 0), time.Unix(424242, 0))
		}, CompareOptions{MTime: true}},
		{"xattr changed", func(tb testing.TB, tr *Tree) {
			tr.Xattr("a.txt", "user.comment", []byte("different"))
		}, CompareOptions{Xattrs: true}},
		{"setuid lost", func(tb testing.TB, tr *Tree) {
			tr.Chmod("a.txt", 0o644)
		}, CompareOptions{Special: true}},
		{"hardlink broken", func(tb testing.TB, tr *Tree) {
			os.Remove(tr.Path("second"))
			tr.Text("second", 0o644, "alpha")
		}, CompareOptions{Hardlinks: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			build := func() *Tree {
				tr := NewTree(t)
				tr.Text("a.txt", 0o644, "alpha").
					Symlink("link", "a.txt").
					Hardlink("second", "a.txt")
				// Only the case that tests xattrs needs one. Xattr skips on a
				// platform without them (OpenBSD), and in the shared fixture
				// it skipped every case there.
				if tc.opt.Xattrs {
					tr.Xattr("a.txt", "user.comment", []byte("original"))
				}
				tr.Chmod("a.txt", 0o755|os.ModeSetuid)
				tr.SetTimes("a.txt", time.Unix(1000, 0), time.Unix(2000, 0))
				tr.SetLinkTimes("link", time.Unix(1000, 0), time.Unix(3000, 0))
				return tr
			}
			want, got := build(), build()
			tc.mutate(t, got)

			spy := &spyTB{TB: t}
			CompareTrees(spy, want.Root, got.Root, tc.opt)
			if !spy.failed {
				t.Errorf("CompareTrees did not detect: %s", tc.name)
			}
		})
	}
}

func TestSparseFixture(t *testing.T) {
	tr := NewTree(t)
	const size = 1 << 20
	tr.Sparse("sparse.img", 0o644, size,
		Segment{Offset: 0, Data: []byte("head")},
		Segment{Offset: size - 4, Data: []byte("tail")})

	fi, err := os.Stat(tr.Path("sparse.img"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Size() != size {
		t.Errorf("logical size = %d, want %d", fi.Size(), size)
	}

	content, err := os.ReadFile(tr.Path("sparse.img"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(content[:4]) != "head" || string(content[size-4:]) != "tail" {
		t.Error("sparse fixture lost its data segments")
	}
	for _, b := range content[4 : size-4] {
		if b != 0 {
			t.Fatal("the hole should read as zeroes")
		}
	}
}

// spyTB records a failure instead of propagating it, so a test can assert
// that a comparison failed.
type spyTB struct {
	testing.TB
	failed bool
}

func (s *spyTB) Errorf(format string, args ...any) { s.failed = true }
func (s *spyTB) Error(args ...any)                 { s.failed = true }
func (s *spyTB) Fatalf(format string, args ...any) { s.failed = true }
func (s *spyTB) Fatal(args ...any)                 { s.failed = true }
