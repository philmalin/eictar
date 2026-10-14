package ect

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestExtract(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the golden archive has a symbolic link")
	}
	golden := readGolden(t, "plain.ect")
	a, err := openBytes(golden, Options{})
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "out")
	if err := Extract(a, dest, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := Extract(a, dest, io.Discard); !os.IsExist(err) {
		t.Errorf("a destination that exists: %v", err)
	}
	hard, err := os.Stat(filepath.Join(dest, "g/hard.txt"))
	if err != nil {
		t.Fatal(err)
	}
	keep, err := os.Stat(filepath.Join(dest, "g/keep.txt"))
	if err != nil || !os.SameFile(hard, keep) {
		t.Errorf("g/keep.txt is not one file with g/hard.txt: %v", err)
	}
	if target, err := os.Readlink(filepath.Join(dest, "g/link")); err != nil || target != "keep.txt" {
		t.Errorf("g/link: %q, %v", target, err)
	}
	if fi, err := os.Lstat(filepath.Join(dest, "g/link")); err != nil || fi.ModTime().UnixNano() != 1790170872152051644 {
		t.Errorf("the time of g/link: %v, %v", fi.ModTime(), err)
	}
	z, err := os.Stat(filepath.Join(dest, "g/sub/z.txt"))
	if err != nil || z.Mode().Perm() != 0o600 || z.ModTime().UnixNano() != 1767323045000000006 {
		t.Errorf("g/sub/z.txt: %v, %v", z, err)
	}
	if b, err := os.ReadFile(filepath.Join(dest, "g/new.txt")); err != nil || len(b) != 21 {
		t.Errorf("g/new.txt: %q, %v", b, err)
	}

	for _, tc := range []struct {
		name    string
		id      uint64
		path    string
		refusal string
	}{
		{"a path out of the destination", 7, "../evil", "not valid"},
		{"an absolute path", 7, "/evil", "not valid"},
		{"a path through a link", 8, "g/link/z.txt", "symbolic link"},
		{"the root", 7, ".", ""},
	} {
		idx := goldenIndex(t, golden)
		memberOf(idx, tc.id).set("path", text(tc.path))
		a, err := openBytes(withIndex(t, golden, idx, -1), Options{})
		if err != nil {
			t.Fatal(err)
		}
		err = Extract(a, filepath.Join(t.TempDir(), "out"), io.Discard)
		switch {
		case tc.refusal == "" && err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case tc.refusal != "" && !isRefusal(err, tc.refusal):
			t.Errorf("%s: %v, want a refusal with %q", tc.name, err, tc.refusal)
		}
	}
}
