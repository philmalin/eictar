package archive

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/philmalin/eictar/src/internal/fsutil"
	"github.com/philmalin/eictar/src/internal/meta"
)

// destDir is a directory of the destination of an extraction: the
// destination itself, or a directory below it that a worker opened. In
// production it is an *os.Root, so that no name can lead out of the
// destination. The fault tests wrap one, to make an operation fail
// (doc/testing.md 5, step 3).
type destDir interface {
	MkdirAll(name string, perm fs.FileMode) error
	// Open opens a directory or a file to read, and to change its metadata.
	Open(name string) (destFile, error)
	OpenRoot(name string) (destDir, error)
	OpenFile(name string, flag int, perm fs.FileMode) (destFile, error)
	Lstat(name string) (fs.FileInfo, error)
	Lchown(name string, uid, gid int) error
	Chmod(name string, mode fs.FileMode) error
	Chtimes(name string, atime, mtime time.Time) error
	Symlink(oldname, newname string) error
	Readlink(name string) (string, error)
	Link(oldname, newname string) error
	Remove(name string) error
	Rename(oldname, newname string) error
	Close() error
}

// destFile is a file that an extraction writes.
type destFile interface {
	io.Writer
	io.WriterAt
	Truncate(size int64) error
	Chown(uid, gid int) error
	Chmod(mode fs.FileMode) error
	Close() error
	// file gives the *os.File, for the extended attributes, which meta sets
	// on the descriptor.
	file() *os.File
}

// The calls of meta that an extraction makes on a descriptor: a call on the
// descriptor of a directory, with one name, cannot be sent out of it by a
// link. The fault tests replace them.
var (
	mkfifo       = meta.Mkfifo
	mknod        = meta.Mknod
	setLinkTimes = meta.SetLinkTimes
	setXattr     = meta.SetXattr
)

// openDest opens the destination of an extraction. Only the fault tests
// change it.
var openDest = func(dir string) (destDir, error) {
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return osDest{r}, nil
}

// osDest is a directory of the destination on the disk.
type osDest struct{ *os.Root }

func (d osDest) OpenRoot(name string) (destDir, error) {
	r, err := d.Root.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return osDest{r}, nil
}

func (d osDest) Open(name string) (destFile, error) {
	f, err := d.Root.Open(name)
	if err != nil {
		return nil, err
	}
	return osDestFile{f}, nil
}

func (d osDest) OpenFile(name string, flag int, perm fs.FileMode) (destFile, error) {
	f, err := d.Root.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return osDestFile{f}, nil
}

// osDestFile is a file of the destination on the disk.
type osDestFile struct{ *os.File }

func (f osDestFile) file() *os.File { return f.File }

// beneath is a destination in which no path goes through a symbolic link.
//
// os.Root refuses a path that leaves the destination, but it follows a
// relative link that stays inside it. A link that the archive made, or that
// another user put in a directory of the destination, then sends a write
// elsewhere: a directory x and a link x -> . gave the metadata of x to the
// destination itself, and a link alice/.ssh2 -> ../bob/.ssh sent a restore
// of alice's files into bob's directory (doc/Security_Audit_Pass_2.eml,
// findings 13 and 14). beneath opens each directory of a path one name at a
// time, refuses a link there, and checks that the directory it opened is the
// one that it looked at. An operation that follows the last name of its path
// refuses a link there too. Nothing below the destination can be the
// destination itself.
type beneath struct {
	d     destDir     // the directory, opened with no link
	top   fs.FileInfo // the destination itself
	cache *dirCache   // the destination only: directories below it
}

// dirCache holds the directories that beneath opened and checked, by their
// path from the destination, so that the next path in the same directory
// does not open and check each of its directories again. An open directory
// is the one that was checked: a link put at its name later does not change
// it. An entry is closed when no caller uses it. The cache drops the entries
// at and below a name that the extraction removes or replaces.
type dirCache struct {
	mu   sync.Mutex
	m    map[string]*cachedDir
	tick uint64
}

type cachedDir struct {
	d    destDir
	refs int    // the callers that use d
	used uint64 // the tick of the last use
	dead bool   // dropped: closed when refs is 0
}

// maxCachedDirs bounds the descriptors that the cache holds. macOS starts a
// process with a limit of 256 open files.
const maxCachedDirs = 64

// get gives the cached directory of the longest prefix of dir, and that
// prefix, or nil. The caller releases what it gets.
func (c *dirCache) get(dir string) (*cachedDir, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for p := dir; p != "."; p = path.Dir(p) {
		if e := c.m[p]; e != nil {
			c.tick++
			e.refs, e.used = e.refs+1, c.tick
			return e, p
		}
	}
	return nil, ""
}

// put adds d, the directory at p, for the caller, who releases it. A full
// cache drops the entry that was used longest ago.
func (c *dirCache) put(p string, d destDir) *cachedDir {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m[p] != nil {
		c.drop(p)
	}
	if len(c.m) >= maxCachedDirs {
		oldest := ""
		for q, e := range c.m {
			if oldest == "" || e.used < c.m[oldest].used {
				oldest = q
			}
		}
		c.drop(oldest)
	}
	c.tick++
	e := &cachedDir{d: d, refs: 1, used: c.tick}
	c.m[p] = e
	return e
}

func (c *dirCache) release(e *cachedDir) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e.refs--
	if e.dead && e.refs == 0 {
		e.d.Close()
	}
}

// drop removes the entry at p. The caller holds mu.
func (c *dirCache) drop(p string) {
	e := c.m[p]
	delete(c.m, p)
	e.dead = true
	if e.refs == 0 {
		e.d.Close()
	}
}

// forget drops the entries at and below name.
func (c *dirCache) forget(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for p := range c.m {
		if p == name || strings.HasPrefix(p, name+"/") {
			c.drop(p)
		}
	}
}

func (c *dirCache) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for p := range c.m {
		c.drop(p)
	}
}

// forget drops what the cache holds at and below name: the extraction is
// about to remove name, or to put something else there.
func (b beneath) forget(name string) {
	if b.cache != nil {
		b.cache.forget(name)
	}
}

// openBeneath opens the destination of an extraction, with no link in a
// path.
func openBeneath(dir string) (destDir, error) {
	d, err := openDest(dir)
	if err != nil {
		return nil, err
	}
	b, err := newBeneath(d)
	if err != nil {
		d.Close()
		return nil, err
	}
	return b, nil
}

// newBeneath gives d, the destination of an extraction, with no link in a
// path.
func newBeneath(d destDir) (destDir, error) {
	top, err := d.Lstat(".")
	if err != nil {
		return nil, err
	}
	return beneath{d: d, top: top, cache: &dirCache{m: map[string]*cachedDir{}}}, nil
}

// throughLink is the error for a path that would go through a link.
func throughLink(name string) error {
	return fmt.Errorf("%w: %q is a symbolic link, and extraction does not go through one", fsutil.ErrUnsafePath, name)
}

// notLink refuses a link, and on Windows a junction or another reparse
// point, at name.
func notLink(name string, fi fs.FileInfo) error {
	if fi.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
		return throughLink(name)
	}
	return nil
}

// enter opens the directory name in d, which is at the path at. With
// create, it makes the directory with perm when it does not exist.
func (b beneath) enter(d destDir, at, name string, create bool, perm fs.FileMode) (destDir, error) {
	p := path.Join(at, name)
	fi, err := d.Lstat(name)
	if create && errors.Is(err, fs.ErrNotExist) {
		if err = d.MkdirAll(name, perm); err == nil {
			fi, err = d.Lstat(name)
		}
	}
	if err != nil {
		return nil, err
	}
	if err := notLink(p, fi); err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, &fs.PathError{Op: "open", Path: p, Err: syscall.ENOTDIR}
	}
	sub, err := d.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	got, err := sub.Lstat(".")
	switch {
	case err != nil:
	case !os.SameFile(fi, got):
		err = fmt.Errorf("%w: %q changed while it was opened", fsutil.ErrUnsafePath, p)
	case os.SameFile(got, b.top):
		err = fmt.Errorf("%w: %q is the destination itself", fsutil.ErrUnsafePath, p)
	}
	if err != nil {
		sub.Close()
		return nil, err
	}
	return sub, nil
}

// walk opens the directory dir, a slash path that is not empty, with no
// link in it. The caller closes it.
func (b beneath) walk(dir string, create bool, perm fs.FileMode) (destDir, error) {
	cur, at := b.d, ""
	for name := range strings.SplitSeq(dir, "/") {
		next, err := b.enter(cur, at, name, create, perm)
		if cur != b.d {
			cur.Close()
		}
		if err != nil {
			return nil, err
		}
		cur, at = next, path.Join(at, name)
	}
	return cur, nil
}

// open gives the directory dir, a slash path, with no link in it. The caller
// calls done when it no longer needs the directory. The destination starts
// at the deepest directory of dir in its cache, and keeps each directory
// that it opens.
func (b beneath) open(dir string, create bool, perm fs.FileMode) (d destDir, done func(), err error) {
	if b.cache == nil {
		d, err := b.walk(dir, create, perm)
		if err != nil {
			return nil, nil, err
		}
		return d, func() { d.Close() }, nil
	}
	cur, at, release := b.d, "", func() {}
	if e, p := b.cache.get(dir); e != nil {
		cur, at, release = e.d, p, func() { b.cache.release(e) }
	}
	rest := dir
	if at != "" {
		if at == dir {
			return cur, release, nil
		}
		rest = dir[len(at)+1:]
	}
	for name := range strings.SplitSeq(rest, "/") {
		next, err := b.enter(cur, at, name, create, perm)
		release()
		if err != nil {
			return nil, nil, err
		}
		at = path.Join(at, name)
		e := b.cache.put(at, next)
		cur, release = next, func() { b.cache.release(e) }
	}
	return cur, release, nil
}

// at gives the directory that holds name, and the last name of name. The
// caller calls done when it no longer needs the directory.
func (b beneath) at(name string, create bool) (dir destDir, base string, done func(), err error) {
	parent, base := path.Split(name)
	if parent == "" {
		return b.d, base, func() {}, nil
	}
	d, done, err := b.open(path.Clean(parent), create, 0o700)
	if err != nil {
		return nil, "", nil, err
	}
	return d, base, done, nil
}

// last opens the directory that holds name, and refuses a link at name: the
// operation that follows would go through it.
func (b beneath) last(name string) (destDir, string, func(), error) {
	d, base, done, err := b.at(name, false)
	if err != nil {
		return nil, "", nil, err
	}
	fi, err := d.Lstat(base)
	if err == nil {
		err = notLink(name, fi)
	}
	if err != nil {
		done()
		return nil, "", nil, err
	}
	return d, base, done, nil
}

func (b beneath) MkdirAll(name string, perm fs.FileMode) error {
	if name == "." {
		return nil
	}
	_, done, err := b.open(name, true, perm)
	if err != nil {
		return err
	}
	done()
	return nil
}

func (b beneath) Open(name string) (destFile, error) {
	if name == "." {
		return b.d.Open(".")
	}
	d, base, done, err := b.last(name)
	if err != nil {
		return nil, err
	}
	defer done()
	fi, err := d.Lstat(base)
	if err != nil {
		return nil, err
	}
	f, err := d.Open(base)
	if err != nil {
		return nil, err
	}
	got, err := f.file().Stat()
	switch {
	case err != nil:
	case !os.SameFile(fi, got):
		err = fmt.Errorf("%w: %q changed while it was opened", fsutil.ErrUnsafePath, name)
	case os.SameFile(got, b.top):
		err = fmt.Errorf("%w: %q is the destination itself", fsutil.ErrUnsafePath, name)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func (b beneath) OpenRoot(name string) (destDir, error) {
	if name == "." {
		d, err := b.d.OpenRoot(".")
		if err != nil {
			return nil, err
		}
		return beneath{d: d, top: b.top}, nil
	}
	d, done, err := b.open(name, false, 0)
	if err != nil {
		return nil, err
	}
	defer done()
	// The caller closes what it gets: a directory of its own, not the one in
	// the cache.
	mine, err := d.OpenRoot(".")
	if err != nil {
		return nil, err
	}
	return beneath{d: mine, top: b.top}, nil
}

func (b beneath) OpenFile(name string, flag int, perm fs.FileMode) (destFile, error) {
	d, base, done, err := b.at(name, false)
	if err != nil {
		return nil, err
	}
	defer done()
	if fi, err := d.Lstat(base); err == nil {
		if err := notLink(name, fi); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	return d.OpenFile(base, flag, perm)
}

func (b beneath) Lstat(name string) (fs.FileInfo, error) {
	d, base, done, err := b.at(name, false)
	if err != nil {
		return nil, err
	}
	defer done()
	return d.Lstat(base)
}

func (b beneath) Lchown(name string, uid, gid int) error {
	d, base, done, err := b.at(name, false)
	if err != nil {
		return err
	}
	defer done()
	return d.Lchown(base, uid, gid)
}

func (b beneath) Chmod(name string, mode fs.FileMode) error {
	d, base, done, err := b.last(name)
	if err != nil {
		return err
	}
	defer done()
	return d.Chmod(base, mode)
}

func (b beneath) Chtimes(name string, atime, mtime time.Time) error {
	d, base, done, err := b.last(name)
	if err != nil {
		return err
	}
	defer done()
	return d.Chtimes(base, atime, mtime)
}

func (b beneath) Symlink(oldname, newname string) error {
	b.forget(newname)
	d, base, done, err := b.at(newname, false)
	if err != nil {
		return err
	}
	defer done()
	return d.Symlink(oldname, base)
}

func (b beneath) Readlink(name string) (string, error) {
	d, base, done, err := b.at(name, false)
	if err != nil {
		return "", err
	}
	defer done()
	return d.Readlink(base)
}

// Link checks the directories of both names, and then links by the paths:
// os.Root has no call that links between two directories that it holds. A
// directory that becomes a link between the check and the link can still
// move the link, but only inside the destination, where os.Root keeps it.
func (b beneath) Link(oldname, newname string) error {
	b.forget(newname)
	if path.Dir(oldname) == path.Dir(newname) {
		d, base, done, err := b.at(newname, false)
		if err != nil {
			return err
		}
		defer done()
		return d.Link(path.Base(oldname), base)
	}
	for _, name := range []string{oldname, newname} {
		_, _, done, err := b.at(name, false)
		if err != nil {
			return err
		}
		done()
	}
	return b.d.Link(oldname, newname)
}

func (b beneath) Remove(name string) error {
	b.forget(name)
	d, base, done, err := b.at(name, false)
	if err != nil {
		return err
	}
	defer done()
	return d.Remove(base)
}

// Rename renames in one directory: an extraction renames a temporary file
// to its name beside it, and nothing else.
func (b beneath) Rename(oldname, newname string) error {
	if path.Dir(oldname) != path.Dir(newname) {
		return fmt.Errorf("renaming %s to %s: not in one directory", oldname, newname)
	}
	d, base, done, err := b.at(newname, false)
	if err != nil {
		return err
	}
	defer done()
	return d.Rename(path.Base(oldname), base)
}

func (b beneath) Close() error {
	if b.cache != nil {
		b.cache.close()
	}
	return b.d.Close()
}
