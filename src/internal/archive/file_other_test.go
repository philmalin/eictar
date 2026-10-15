//go:build !windows

package archive

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// TestRenameNew: the rename of a create that found no archive makes the
// new name, or fails with fs.ErrExist and changes nothing. It must do so
// on a file system with no hard links too, where link(2) fails for every
// file, and the check before the rename decides (doc/design.md 9.6).
func TestRenameNew(t *testing.T) {
	for _, links := range []bool{true, false} {
		if !links {
			hardLink = func(string, string) error { return errors.New("operation not permitted") }
		}
		t.Cleanup(func() { hardLink = os.Link })
		dir := t.TempDir()
		old, path := filepath.Join(dir, "tmp"), filepath.Join(dir, "a.ect")
		write := func(name, s string) {
			if err := os.WriteFile(name, []byte(s), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		content := func(name string) string {
			b, err := os.ReadFile(name)
			if err != nil {
				return "none"
			}
			return string(b)
		}

		write(old, "new")
		if err := renameNew(old, path); err != nil {
			t.Fatalf("links %v: a free name: %v", links, err)
		}
		if content(path) != "new" || content(old) != "none" {
			t.Errorf("links %v: after the rename, the path has %q and the old name %q", links, content(path), content(old))
		}

		write(old, "mine")
		if err := renameNew(old, path); !errors.Is(err, fs.ErrExist) {
			t.Errorf("links %v: a name in use: got %v, want fs.ErrExist", links, err)
		}
		if content(path) != "new" || content(old) != "mine" {
			t.Errorf("links %v: a refused rename changed the files: %q and %q", links, content(path), content(old))
		}

		// A check that fails for another reason stops the rename too.
		under := filepath.Join(path, "x")
		if err := renameNew(old, under); err == nil || errors.Is(err, fs.ErrExist) {
			t.Errorf("links %v: a name under a file: got %v, want the error of the check", links, err)
		}
		if content(old) != "mine" {
			t.Errorf("links %v: the failed rename lost the file", links)
		}
	}
}
