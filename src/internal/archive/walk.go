package archive

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"

	"github.com/philmalin/eictar/src/internal/fsutil"
	"github.com/philmalin/eictar/src/internal/meta"
)

// entryKind is what the walker found.
type entryKind int

const (
	kindDir entryKind = iota
	kindFile
	kindSymlink
	kindFIFO
	kindCharDev
	kindBlockDev
	kindSocket
	kindUnsupported
)

// entry is one thing to archive.
type entry struct {
	Src        string // path on disk
	Stored     string // path inside the archive
	Kind       entryKind
	Info       os.FileInfo
	Sys        meta.Info // ownership, identity, device number, times
	LinkTarget string    // symlinks only
	Stripped   bool      // a leading "/" or ".." was removed from Stored
	Followed   bool      // reached through a symlink under -h

	// dir is the open directory that holds the entry, and name is the
	// entry's name in it. Each later operation on the entry - the open of
	// a file, the read of its attributes - goes through dir, one name at a
	// time. Thus a directory above the entry that becomes a link after the
	// walk passed it cannot lead the operation elsewhere
	// (doc/Security_Audit.md, finding 11). dir is nil for an entry that the
	// walk reached by its path: a requested path whose parent cannot be
	// opened, and a link that -h follows. Both are valid during the visit
	// only.
	dir  *os.Root
	name string
	// self is the directory itself, open, for a directory entry: its
	// attributes come from it. It is nil when the directory cannot be
	// opened for want of permission; the attributes then come from the path.
	self *os.File
}

// walkOptions controls what the walker includes.
type walkOptions struct {
	baseDir       string
	dereference   bool           // -h: archive what a link points at
	exclude       []string       // --exclude and -X patterns
	regex         fsutil.Regexps // -R: store only the paths that match
	excludeRegex  fsutil.Regexps // --exclude-regex
	oneFileSystem bool           // --one-file-system
	// root, when set, holds the requested paths: each one is a name inside
	// it, and the walk does not leave it. --diff walks the paths that the
	// archive names this way.
	root *os.Root
	// afterLstat, when set, runs after each lstat of the walk. Tests use it
	// to change the tree at that moment (doc/Security_Audit.md, finding 11).
	afterLstat func(src string)
	// onError decides what an error of the walk itself does: one lstat,
	// readdir or readlink that fails below a requested path. It returns nil
	// to skip the entry and go on (--keep-going), or the error to stop. nil
	// stops at the first error. A requested path that cannot be read always
	// stops: it is a mistake in what was asked for.
	onError func(src string, err error) error
}

// walker turns the requested paths into entries.
//
// It replaces filepath.Walk so that symbolic links are a decision rather than
// an accident: Walk reports them without following, which is right for the
// default, but -h has to follow them, and following needs loop detection that
// Walk does not offer.
type walker struct {
	opt   walkOptions
	visit func(entry) error

	// entered holds the resolved paths of directories already walked, so a
	// symlink loop under -h is reported rather than followed forever.
	entered map[string]bool
	// rootDev is the device of the path being walked, for --one-file-system.
	rootDev uint64
	// regexHit records which -R expressions matched a path.
	regexHit []bool
}

func newWalker(opt walkOptions, visit func(entry) error) *walker {
	return &walker{opt: opt, visit: visit, entered: map[string]bool{}, regexHit: make([]bool, len(opt.regex))}
}

// unmatched reports the first -R expression that matched no path: a mistyped
// expression must not give a quietly empty archive (doc/design.md 10.11).
func (w *walker) unmatched() error {
	for i, hit := range w.regexHit {
		if !hit {
			return fmt.Errorf("-R %q %w", w.opt.regex[i].Expr, ErrNoMatch)
		}
	}
	return nil
}

// Walk visits one requested path and everything beneath it.
func (w *walker) Walk(requested string) error {
	src := requested
	if w.opt.baseDir != "" && !filepath.IsAbs(requested) {
		src = filepath.Join(w.opt.baseDir, requested)
	}

	// --one-file-system is relative to where each requested path lives, as
	// in tar: naming /home and /home/other-mount walks both.
	stat := os.Stat
	if w.opt.root != nil {
		stat = func(string) (os.FileInfo, error) { return w.opt.root.Stat(requested) }
	}
	if fi, err := stat(src); err == nil {
		w.rootDev = meta.Stat(fi).Dev
	}

	parent, name, err := w.openParent(requested, src)
	if err != nil {
		return err
	}
	if parent != nil && parent != w.opt.root {
		defer parent.Close()
	}
	return w.walk(parent, name, src, requested, true)
}

// openParent opens the directory that holds a requested path, so that the
// walk handles the path as it handles each entry below it. The user chose the
// path, so its parent is opened by its path. A path with no parent of its own
// ("/", ".", "..") or a parent that cannot be opened is walked by its path,
// as before. Inside opt.root, the parent must open: the path came from an
// archive.
func (w *walker) openParent(requested, src string) (*os.Root, string, error) {
	if w.opt.root != nil {
		dir, name := path.Split(requested)
		if dir == "" {
			return w.opt.root, name, nil
		}
		parent, err := w.opt.root.OpenRoot(dir)
		if err != nil {
			return nil, "", atPath(err, filepath.Dir(src))
		}
		return parent, name, nil
	}
	clean := filepath.Clean(src)
	name := filepath.Base(clean)
	if name == "." || name == ".." || name == string(filepath.Separator) {
		return nil, "", nil
	}
	parent, err := os.OpenRoot(filepath.Dir(clean))
	if err != nil {
		return nil, "", nil
	}
	return parent, name, nil
}

// atPathErr is atPath for an error that can be nil.
func atPathErr(err error, src string) error {
	if err == nil {
		return nil
	}
	return atPath(err, src)
}

// atPath puts src in place of the name in an error of os.Root, which knows
// only the name inside its directory.
func atPath(err error, src string) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return &fs.PathError{Op: pe.Op, Path: src, Err: pe.Err}
	}
	return err
}

// fail applies onError to an error of the walk at src. top is the requested
// path itself.
func (w *walker) fail(src string, top bool, err error) error {
	if top || w.opt.onError == nil {
		return err
	}
	return w.opt.onError(src, err)
}

// walk handles one filesystem object: name in the open directory dir, or the
// path src when dir is nil. rel is the name as the user gave it, so that -C
// does not leak into the stored path.
func (w *walker) walk(dir *os.Root, name, src, rel string, top bool) error {
	stored, stripped, err := fsutil.StorePath(rel)
	if err != nil {
		return err
	}
	// An excluded directory is not entered: that is what excluding a
	// directory means, and it is how tar behaves.
	if stored != fsutil.RootPath && (fsutil.MatchAny(w.opt.exclude, stored) || w.opt.excludeRegex.MatchAny(stored)) {
		return nil
	}

	var fi os.FileInfo
	if dir != nil {
		fi, err = dir.Lstat(name)
	} else {
		fi, err = os.Lstat(src)
	}
	if err != nil {
		return w.fail(src, top, atPath(err, src))
	}
	if w.opt.afterLstat != nil {
		w.opt.afterLstat(src)
	}

	e := entry{Src: src, Stored: stored, Info: fi, Stripped: stripped, dir: dir, name: name}

	if fi.Mode()&os.ModeSymlink != 0 {
		if !w.opt.dereference {
			var target string
			if dir != nil {
				target, err = dir.Readlink(name)
			} else {
				target, err = os.Readlink(src)
			}
			if err != nil {
				return w.fail(src, top, fmt.Errorf("reading link %s: %w", src, err))
			}
			e.Kind, e.LinkTarget, e.Sys = kindSymlink, target, meta.Stat(fi)
			return w.emit(e)
		}
		// -h: archive what the link points at, under the link's own name.
		// Following the link is the point, so it is followed by its path.
		followed, err := os.Stat(src)
		if err != nil {
			return w.fail(src, top, fmt.Errorf("following link %s: %w", src, err))
		}
		e.Info, e.Followed = followed, true
		e.dir, e.name = nil, ""
		fi = followed
	}

	e.Sys = meta.Stat(fi)
	e.Kind = classify(fi.Mode())

	if e.Kind != kindDir {
		return w.emit(e)
	}

	// Open the directory, and make sure that it is the directory that the
	// lstat found. A link put in its place since then would take the walk
	// into the directory that the link points to (doc/Security_Audit.md,
	// finding 11).
	sub, err := w.openDir(e)
	if err != nil && !errors.Is(err, fs.ErrPermission) {
		return w.fail(src, top, err)
	}
	if sub != nil {
		defer sub.Close()
		if e.self, err = sub.Open("."); err != nil {
			return w.fail(src, top, atPath(err, src))
		}
		defer e.self.Close()
	}

	if err := w.emit(e); err != nil {
		return err
	}
	// A directory that cannot be opened is archived, as a file that cannot
	// be read is not: a directory has no content to lose. Its entries
	// cannot be listed, so that is an error of one member, even when it was
	// requested: under --keep-going it is archived empty, and the walk goes
	// on.
	if sub == nil {
		return w.fail(src, false, err)
	}

	// A directory on another filesystem is recorded, empty, but not
	// entered: the mount point exists in the tree, its contents belong to
	// something else.
	if w.opt.oneFileSystem && e.Sys.OK && e.Sys.Dev != w.rootDev {
		return nil
	}

	if e.Followed {
		// Following a directory link can loop. Resolve it and refuse to enter
		// a directory already on the current path.
		real, err := filepath.EvalSymlinks(src)
		if err != nil {
			return w.fail(src, top, fmt.Errorf("resolving %s: %w", src, err))
		}
		if w.entered[real] {
			return w.fail(src, top, fmt.Errorf("symlink loop: %s leads back to %s", src, real))
		}
		w.entered[real] = true
		defer delete(w.entered, real)
	}
	return w.walkChildren(sub, e.self, src, rel)
}

// openDir opens the directory of a walked entry as a root for the entries in
// it, and checks that it has the device and the inode that the walk found.
// An error that fs.ErrPermission matches means that the directory cannot be
// opened; any other means that it changed, or went away.
func (w *walker) openDir(e entry) (*os.Root, error) {
	var sub *os.Root
	var err error
	if e.dir != nil {
		sub, err = e.dir.OpenRoot(e.name)
	} else {
		sub, err = os.OpenRoot(e.Src)
	}
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return nil, atPath(err, e.Src)
		}
		return nil, fmt.Errorf("%s: %w (%v)", e.Src, errChangedDuringWalk, err)
	}
	fi, err := sub.Stat(".")
	if err == nil && !os.SameFile(fi, e.Info) {
		err = errChangedDuringWalk
	}
	if err != nil {
		sub.Close()
		return nil, fmt.Errorf("%s: %w", e.Src, err)
	}
	return sub, nil
}

// emit hands an entry to the visitor, unless it names the archived tree's
// root, which has no name of its own to store, or -R leaves it out. A
// directory that -R leaves out is still entered: a match can be deeper down.
func (w *walker) emit(e entry) error {
	if e.Stored == fsutil.RootPath {
		return nil
	}
	if len(w.opt.regex) > 0 {
		hit := false
		for i, re := range w.opt.regex {
			if re.Match(e.Stored) {
				w.regexHit[i], hit = true, true
			}
		}
		if !hit {
			return nil
		}
	}
	return w.visit(e)
}

// classify maps a file mode to the kind the archive stores.
func classify(mode fs.FileMode) entryKind {
	switch {
	case mode.IsDir():
		return kindDir
	case mode.IsRegular():
		return kindFile
	case mode&fs.ModeSymlink != 0:
		return kindSymlink
	case mode&fs.ModeNamedPipe != 0:
		return kindFIFO
	case mode&fs.ModeSocket != 0:
		return kindSocket
	case mode&fs.ModeDevice != 0 && mode&fs.ModeCharDevice != 0:
		return kindCharDev
	case mode&fs.ModeDevice != 0:
		return kindBlockDev
	default:
		return kindUnsupported
	}
}

// walkChildren visits a directory's entries in name order, so that an archive
// of the same tree always comes out in the same order. Each entry is found
// through sub, the open directory, by its name alone.
func (w *walker) walkChildren(sub *os.Root, d *os.File, src, rel string) error {
	list, err := d.ReadDir(-1)
	if err != nil {
		return w.fail(src, false, atPath(err, src))
	}
	names := make([]string, len(list))
	for i, de := range list {
		names[i] = de.Name()
	}
	sort.Strings(names)
	for _, name := range names {
		if err := w.walk(sub, name, filepath.Join(src, name), filepath.Join(rel, name), false); err != nil {
			return err
		}
	}
	return nil
}
