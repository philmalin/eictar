package archive

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/philmalin/eictar/src/internal/fsutil"
)

// The tests of beneath, the destination with no link in a path
// (doc/Security_Audit_Pass_2.eml, findings 13 and 14).

// destCount counts the directories that a destination opens, the ones
// that are open, and the links that its top makes by their paths.
type destCount struct {
	mu                 sync.Mutex
	opened, open, link int
}

func (c *destCount) get() (opened, open, link int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.opened, c.open, c.link
}

// countDest is a destination that counts with c.
type countDest struct {
	destDir
	c   *destCount
	top bool
}

func (d countDest) OpenRoot(name string) (destDir, error) {
	r, err := d.destDir.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	d.c.mu.Lock()
	d.c.opened++
	d.c.open++
	d.c.mu.Unlock()
	return countDest{destDir: r, c: d.c}, nil
}

func (d countDest) Link(oldname, newname string) error {
	if d.top {
		d.c.mu.Lock()
		d.c.link++
		d.c.mu.Unlock()
	}
	return d.destDir.Link(oldname, newname)
}

func (d countDest) Close() error {
	d.c.mu.Lock()
	d.c.open--
	d.c.mu.Unlock()
	return d.destDir.Close()
}

// testBeneath gives a beneath on a new directory, counted by the second
// result. The test closes it.
func testBeneath(t *testing.T) (destDir, *destCount, string) {
	t.Helper()
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	c := &destCount{open: 1}
	b, err := newBeneath(countDest{destDir: osDest{root}, c: c, top: true})
	if err != nil {
		t.Fatal(err)
	}
	return b, c, dir
}

// mkfile writes a file at name under dir.
func mkfile(t *testing.T, dir, name string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Each operation refuses a path through a link, and each operation that
// follows its last name refuses a link there.
func TestBeneathRefusesALinkInEachOperation(t *testing.T) {
	b, _, dir := testBeneath(t)
	defer b.Close()
	mkfile(t, dir, "real/f")
	symlinkOrSkip(t, "real", filepath.Join(dir, "l"))
	symlinkOrSkip(t, "f", filepath.Join(dir, "real", "lf"))
	now := time.Now()
	for name, op := range map[string]func() error{
		"MkdirAll":       func() error { return b.MkdirAll("l/n", 0o700) },
		"Open":           func() error { f, err := b.Open("l/f"); closeIf(f); return err },
		"Open, last":     func() error { f, err := b.Open("real/lf"); closeIf(f); return err },
		"OpenRoot":       func() error { d, err := b.OpenRoot("l"); closeIf(d); return err },
		"OpenFile":       func() error { f, err := b.OpenFile("l/n", os.O_CREATE|os.O_WRONLY, 0o600); closeIf(f); return err },
		"OpenFile, last": func() error { f, err := b.OpenFile("real/lf", os.O_RDONLY, 0); closeIf(f); return err },
		"Lstat":          func() error { _, err := b.Lstat("l/f"); return err },
		"Lchown":         func() error { return b.Lchown("l/f", -1, -1) },
		"Chmod":          func() error { return b.Chmod("l/f", 0o600) },
		"Chmod, last":    func() error { return b.Chmod("real/lf", 0o600) },
		"Chtimes":        func() error { return b.Chtimes("l/f", now, now) },
		"Chtimes, last":  func() error { return b.Chtimes("real/lf", now, now) },
		"Symlink":        func() error { return b.Symlink("f", "l/n") },
		"Readlink":       func() error { _, err := b.Readlink("l/lf"); return err },
		"Link":           func() error { return b.Link("real/f", "l/n") },
		"Link, old":      func() error { return b.Link("l/f", "real/n") },
		"Link, one dir":  func() error { return b.Link("l/f", "l/n") },
		"Remove":         func() error { return b.Remove("l/f") },
		"Rename":         func() error { return b.Rename("l/f", "l/n") },
	} {
		if err := op(); !errors.Is(err, fsutil.ErrUnsafePath) {
			t.Errorf("%s: %v, want an unsafe path", name, err)
		}
	}
	if b, err := os.ReadFile(filepath.Join(dir, "real", "f")); err != nil || string(b) != "x" {
		t.Errorf("real/f: %q, %v", b, err)
	}
}

// closeIf closes what an operation opened, if it did.
func closeIf(c interface{ Close() error }) {
	switch v := c.(type) {
	case destFile:
		if v != nil {
			v.Close()
		}
	case destDir:
		if v != nil {
			v.Close()
		}
	}
}

// The operations work on a path with no link, and the destination itself
// needs nothing.
func TestBeneathOperations(t *testing.T) {
	b, c, dir := testBeneath(t)
	if err := b.MkdirAll(".", 0o700); err != nil {
		t.Errorf("MkdirAll(.): %v", err)
	}
	if err := b.MkdirAll("a/b", 0o700); err != nil {
		t.Fatal(err)
	}
	mkfile(t, dir, "a/b/f")
	if err := b.Link("a/b/f", "a/b/g"); err != nil {
		t.Fatal(err)
	}
	if _, _, link := c.get(); link != 0 {
		t.Errorf("a link in one directory went by its paths %d times; want through the directory", link)
	}
	if err := b.Link("a/b/f", "a/h"); err != nil {
		t.Fatal(err)
	}
	if _, _, link := c.get(); link != 1 {
		t.Errorf("a link between two directories went by its paths %d times; want 1", link)
	}
	if err := b.Rename("a/b/g", "a/b/i"); err != nil {
		t.Fatal(err)
	}
	// A file of the same name in the other directory: a rename of the last
	// names alone would succeed.
	mkfile(t, dir, "a/i")
	if err := b.Rename("a/b/i", "a/j"); err == nil {
		t.Error("a rename between two directories was done")
	}
	if err := b.Symlink("f", "a/b/s"); err != nil {
		t.Fatal(err)
	}
	if got, err := b.Readlink("a/b/s"); err != nil || got != "f" {
		t.Errorf("Readlink: %q, %v", got, err)
	}
	if err := b.Remove("a/b/s"); err != nil {
		t.Fatal(err)
	}
	if fi, err := b.Lstat("a/b/i"); err != nil || !fi.Mode().IsRegular() {
		t.Errorf("Lstat: %v, %v", fi, err)
	}

	// A file where a directory goes.
	if err := b.MkdirAll("a/b/f/x", 0o700); !errors.Is(err, syscall.ENOTDIR) {
		t.Errorf("a directory under a file: %v, want ENOTDIR", err)
	}

	// A directory of its own, from OpenRoot, walks its own paths.
	sub, err := b.OpenRoot("a")
	if err != nil {
		t.Fatal(err)
	}
	if err := sub.MkdirAll("c/d", 0o700); err != nil {
		t.Errorf("MkdirAll in a directory of its own: %v", err)
	}
	if fi, err := sub.Lstat("b/f"); err != nil || !fi.Mode().IsRegular() {
		t.Errorf("Lstat in a directory of its own: %v, %v", fi, err)
	}
	symlinkOrSkip(t, "c", filepath.Join(dir, "a", "l"))
	if err := sub.MkdirAll("l/e", 0o700); !errors.Is(err, fsutil.ErrUnsafePath) {
		t.Errorf("MkdirAll through a link in a directory of its own: %v", err)
	}
	if _, err := sub.Lstat("l/e/f"); !errors.Is(err, fsutil.ErrUnsafePath) {
		t.Errorf("Lstat through a link in a directory of its own: %v", err)
	}
	sub.Close()
	top, err := b.OpenRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	top.Close()

	b.Close()
	if _, open, _ := c.get(); open != 0 {
		t.Errorf("%d directories stay open after the close", open)
	}
}

// The cache keeps the directories that were used last, up to its bound,
// and a path in a cached directory opens nothing.
func TestBeneathCache(t *testing.T) {
	b, c, _ := testBeneath(t)
	if err := b.MkdirAll("keep/a", 0o700); err != nil {
		t.Fatal(err)
	}
	opened, _, _ := c.get()
	if _, err := b.Lstat("keep/a/x"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	if now, _, _ := c.get(); now != opened {
		t.Errorf("a path in a cached directory opened %d directories", now-opened)
	}

	// More directories than the cache holds. keep/a is used between them, so
	// it stays; d0 is not, so it goes.
	for i := range maxCachedDirs + 10 {
		if err := b.MkdirAll(fmt.Sprintf("d%d", i), 0o700); err != nil {
			t.Fatal(err)
		}
		b.Lstat("keep/a/x")
	}
	if _, open, _ := c.get(); open != maxCachedDirs+1 {
		t.Errorf("%d directories open; want the cache full, %d, and the destination", open, maxCachedDirs)
	}
	opened, _, _ = c.get()
	b.Lstat("keep/a/x")
	b.Lstat(fmt.Sprintf("d%d/x", maxCachedDirs+9))
	if now, _, _ := c.get(); now != opened {
		t.Errorf("the directories used last were dropped: %d opened", now-opened)
	}
	b.Lstat("d0/x")
	if now, _, _ := c.get(); now != opened+1 {
		t.Errorf("the directory used first stayed: %d opened", now-opened)
	}

	b.Close()
	if _, open, _ := c.get(); open != 0 {
		t.Errorf("%d directories stay open after the close", open)
	}
}

// closeDest is a directory that records its close.
type closeDest struct {
	destDir
	closed *bool
}

func (d closeDest) Close() error { *d.closed = true; return nil }

// The cache closes an entry that it drops only when no caller uses it, and
// an entry for a path that it holds already takes the place of the old one.
func TestDirCacheCloses(t *testing.T) {
	c := &dirCache{m: map[string]*cachedDir{}}
	var first, second bool
	e := c.put("a", closeDest{closed: &first})
	c.forget("a")
	if first {
		t.Error("an entry in use was closed")
	}
	c.release(e)
	if !first {
		t.Error("a dropped entry was not closed after its release")
	}

	first = false
	c.release(c.put("a", closeDest{closed: &first}))
	c.release(c.put("a", closeDest{closed: &second}))
	if !first || second {
		t.Errorf("closed: the first %v, the second %v; want the first only", first, second)
	}
	if e, p := c.get("a/b"); e == nil || p != "a" {
		t.Errorf("get(a/b) = %v, %q; want the entry at a", e, p)
	} else {
		c.release(e)
	}
	c.close()
	if !second {
		t.Error("close left an entry open")
	}
}

// swapOpen replaces the file swap with a link to other at the moment that
// it is opened.
type swapOpen struct {
	destDir
	t           *testing.T
	swap, other string
}

func (d swapOpen) Open(name string) (destFile, error) {
	if name == d.swap {
		if err := d.Rename(name, name+".moved"); err != nil {
			d.t.Fatal(err)
		}
		if err := d.Symlink(d.other, name); err != nil {
			d.t.Fatal(err)
		}
	}
	return d.destDir.Open(name)
}

// Open refuses a file that becomes a link between its check and its open.
func TestBeneathOpenRefusesASwap(t *testing.T) {
	dir := t.TempDir()
	mkfile(t, dir, "f")
	mkfile(t, dir, "other")
	symlinkOrSkip(t, "other", filepath.Join(dir, "probe"))
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := newBeneath(swapOpen{destDir: osDest{root}, t: t, swap: "f", other: "other"})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if f, err := b.Open("f"); !errors.Is(err, fsutil.ErrUnsafePath) {
		closeIf(f)
		t.Errorf("error %v, want an unsafe path", err)
	}
}

// failDest fails Lstat and OpenRoot of the directory itself.
type failDest struct {
	destDir
	closed *bool
}

var errFail = errors.New("the test fails it")

func (d failDest) Lstat(name string) (fs.FileInfo, error) {
	if name == "." {
		return nil, errFail
	}
	return d.destDir.Lstat(name)
}

func (d failDest) OpenRoot(name string) (destDir, error) {
	if name == "." {
		return nil, errFail
	}
	return d.destDir.OpenRoot(name)
}

func (d failDest) Close() error { *d.closed = true; return d.destDir.Close() }

// A destination that cannot be looked at is closed and refused, and a
// failed open of a directory of its own is an error.
func TestBeneathFailures(t *testing.T) {
	dir := t.TempDir()
	saved := openDest
	t.Cleanup(func() { openDest = saved })
	var closed bool
	openDest = func(dir string) (destDir, error) {
		r, err := os.OpenRoot(dir)
		if err != nil {
			return nil, err
		}
		return failDest{destDir: osDest{r}, closed: &closed}, nil
	}
	if b, err := openBeneath(dir); !errors.Is(err, errFail) || b != nil {
		t.Errorf("openBeneath: %v, %v; want the error", b, err)
	}
	if !closed {
		t.Error("the destination stayed open")
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	top, err := root.Lstat(".")
	if err != nil {
		t.Fatal(err)
	}
	b := beneath{d: failDest{destDir: osDest{root}, closed: &closed}, top: top}
	defer b.Close()
	if d, err := b.OpenRoot("."); !errors.Is(err, errFail) {
		closeIf(d)
		t.Errorf("OpenRoot(.): %v, want the error", err)
	}
}

// osDest gives the error of a directory that is not there, and no directory.
func TestOsDestOpenRootOfNothing(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if d, err := (osDest{root}).OpenRoot("missing"); !errors.Is(err, fs.ErrNotExist) || d != nil {
		t.Errorf("OpenRoot(missing) = %v, %v; want no directory and ErrNotExist", d, err)
	}
}

// A full cache drops the entry that was used longest ago: the oldest that
// was put, or, after a get of one, the others first.
func TestDirCacheDropsTheOldest(t *testing.T) {
	c := &dirCache{m: map[string]*cachedDir{}}
	closed := make([]bool, 2*maxCachedDirs+1)
	put := func(i int) { c.release(c.put(fmt.Sprint(i), closeDest{closed: &closed[i]})) }
	for i := range maxCachedDirs + 1 {
		put(i)
	}
	if !closed[0] || closed[1] {
		t.Errorf("after one more: 0 closed %v, 1 closed %v; want 0 dropped and 1 kept", closed[0], closed[1])
	}

	// A get of 1, the oldest now: the other 63 go before it.
	e, _ := c.get("1")
	c.release(e)
	for i := maxCachedDirs + 1; i < 2*maxCachedDirs; i++ {
		put(i)
	}
	if closed[1] {
		t.Error("the entry of the last get was dropped before the older ones")
	}
	put(2 * maxCachedDirs)
	if !closed[1] {
		t.Error("the entry of the last get stayed after all the others went")
	}
	c.close()
}
