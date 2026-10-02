package archive

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

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
}

// walkOptions controls what the walker includes.
type walkOptions struct {
	baseDir       string
	dereference   bool           // -h: archive what a link points at
	exclude       []string       // --exclude and -X patterns
	regex         fsutil.Regexps // -R: store only the paths that match
	excludeRegex  fsutil.Regexps // --exclude-regex
	oneFileSystem bool           // --one-file-system
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
	if fi, err := os.Stat(src); err == nil {
		w.rootDev = meta.Stat(fi).Dev
	}
	return w.walk(src, requested, true)
}

// fail applies onError to an error of the walk at src. top is the requested
// path itself.
func (w *walker) fail(src string, top bool, err error) error {
	if top || w.opt.onError == nil {
		return err
	}
	return w.opt.onError(src, err)
}

// walk handles one filesystem object. rel is the name as the user gave it, so
// that -C does not leak into the stored path.
func (w *walker) walk(src, rel string, top bool) error {
	stored, stripped, err := fsutil.StorePath(rel)
	if err != nil {
		return err
	}
	// An excluded directory is not entered: that is what excluding a
	// directory means, and it is how tar behaves.
	if stored != fsutil.RootPath && (fsutil.MatchAny(w.opt.exclude, stored) || w.opt.excludeRegex.MatchAny(stored)) {
		return nil
	}

	fi, err := os.Lstat(src)
	if err != nil {
		return w.fail(src, top, err)
	}

	e := entry{Src: src, Stored: stored, Info: fi, Stripped: stripped}

	if fi.Mode()&os.ModeSymlink != 0 {
		if !w.opt.dereference {
			target, err := os.Readlink(src)
			if err != nil {
				return w.fail(src, top, fmt.Errorf("reading link %s: %w", src, err))
			}
			e.Kind, e.LinkTarget, e.Sys = kindSymlink, target, meta.Stat(fi)
			return w.emit(e)
		}
		// -h: archive what the link points at, under the link's own name.
		followed, err := os.Stat(src)
		if err != nil {
			return w.fail(src, top, fmt.Errorf("following link %s: %w", src, err))
		}
		e.Info, e.Followed = followed, true
		fi = followed
	}

	e.Sys = meta.Stat(fi)
	e.Kind = classify(fi.Mode())

	if e.Kind != kindDir {
		return w.emit(e)
	}

	if err := w.emit(e); err != nil {
		return err
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
	return w.walkChildren(src, rel)
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
// of the same tree always comes out in the same order.
//
// The directory itself is archived by now, so a directory that cannot be read
// is an error of one member even when it was requested: under --keep-going
// it is archived empty, and the walk goes on.
func (w *walker) walkChildren(src, rel string) error {
	names, err := os.ReadDir(src)
	if err != nil {
		return w.fail(src, false, err)
	}
	for _, de := range names {
		if err := w.walk(filepath.Join(src, de.Name()), filepath.Join(rel, de.Name()), false); err != nil {
			return err
		}
	}
	return nil
}
