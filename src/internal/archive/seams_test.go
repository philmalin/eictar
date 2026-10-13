package archive

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// TestSeamsOnTheDisk: each open of the seams on the disk (src.go and
// dest.go) gives the error of the disk, and no file or directory with it.
// The fault tests replace these seams, so they do not reach them.
func TestSeamsOnTheDisk(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")
	check := func(name string, v any, err error) {
		t.Helper()
		if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s: %v, want %v", name, err, fs.ErrNotExist)
		}
		if v != nil {
			t.Errorf("%s: %v, want nothing", name, v)
		}
	}
	d, err := openDest(missing)
	check("openDest", d, err)
	f, err := osSrcPaths{}.Open(missing)
	check("osSrcPaths.Open", f, err)
	f, err = osSrcPaths{}.OpenNoFollow(missing)
	check("osSrcPaths.OpenNoFollow", f, err)

	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	sf, err := osSrc{root}.Open("missing")
	check("osSrc.Open", sf, err)
	df, err := osDest{root}.Open("missing")
	check("osDest.Open", df, err)
	df, err = osDest{root}.OpenFile("missing", os.O_RDONLY, 0)
	check("osDest.OpenFile", df, err)
}
