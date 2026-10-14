package ect

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Extract writes each live member under dest (doc/format.md 9), which must
// not exist. It makes files, directories, symbolic links and hardlinks, with
// their modes and times (on Windows, a link gets no times). It does not make
// the other types: it writes a line for each to warn. It does not apply
// owners or extended attributes.
func Extract(a *Archive, dest string, warn io.Writer) error {
	if err := os.Mkdir(dest, 0o700); err != nil {
		return err
	}
	root, err := os.OpenRoot(dest)
	if err != nil {
		return err
	}
	defer root.Close()
	x := &extractor{a: a, root: root, made: map[uint64]string{}}
	for _, m := range a.Live() {
		if err := x.member(m, warn); err != nil {
			return fmt.Errorf("%q: %w", m.Path, err)
		}
	}
	// The times of a directory last, deepest first: each member above
	// changed them.
	for i := len(x.dirs) - 1; i >= 0; i-- {
		m := x.dirs[i]
		if err := x.finish(m, filepath.FromSlash(m.Path)); err != nil {
			return fmt.Errorf("%q: %w", m.Path, err)
		}
	}
	return nil
}

type extractor struct {
	a    *Archive
	root *os.Root
	made map[uint64]string // the path made for the content of a reg member
	dirs []*Member
}

// validPath is the rule of doc/format.md 9.1.
func validPath(p string) bool {
	if p == "." {
		return true
	}
	if p == "" || strings.HasPrefix(p, "/") {
		return false
	}
	for _, c := range strings.Split(p, "/") {
		if c == "" || c == "." || c == ".." || strings.ContainsRune(c, 0) {
			return false
		}
	}
	return true
}

// parents makes the directories above p, and refuses a symbolic link among
// them.
func (x *extractor) parents(p string) error {
	parts := strings.Split(p, "/")
	for i := 1; i < len(parts); i++ {
		dir := filepath.FromSlash(strings.Join(parts[:i], "/"))
		st, err := x.root.Lstat(dir)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			if err := x.root.Mkdir(dir, 0o755); err != nil {
				return err
			}
		case err != nil:
			return err
		case st.Mode()&fs.ModeSymlink != 0:
			return &RefusedError{Reason: "the path goes through a symbolic link"}
		case !st.IsDir():
			return fmt.Errorf("%s is not a directory", dir)
		}
	}
	return nil
}

func (x *extractor) member(m *Member, warn io.Writer) error {
	if !validPath(m.Path) {
		return &RefusedError{Reason: "the stored path is not valid"}
	}
	if m.Path == "." {
		return nil
	}
	if err := x.parents(m.Path); err != nil {
		return err
	}
	p := filepath.FromSlash(m.Path)
	switch m.Type {
	case "dir":
		if st, err := x.root.Lstat(p); err == nil && st.IsDir() {
			// Made above as a parent.
		} else if err := x.root.Mkdir(p, 0o700); err != nil {
			return err
		}
		x.dirs = append(x.dirs, m)
		return nil
	case "reg":
		if err := x.file(m, m, p); err != nil {
			return err
		}
	case "hardlink":
		t := x.a.ByID(m.Hardlink)
		if old, ok := x.made[t.ID]; ok {
			return x.root.Link(old, p)
		}
		// The target is a tombstone, or came later: this name has the
		// content, and the next names link to it.
		return x.file(m, t, p)
	case "symlink":
		if err := x.root.Symlink(m.Link, p); err != nil {
			return err
		}
		atime, mtime := times(m)
		return linkTimes(x.root, p, atime, mtime)
	default:
		fmt.Fprintf(warn, "%q: a %s is not extracted\n", m.Path, m.Type)
		return nil
	}
	return nil
}

// file writes the content of m at p, with the metadata of the reg member t,
// which is m or its hardlink target.
func (x *extractor) file(m, t *Member, p string) error {
	f, err := x.root.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	err = x.a.Content(m, f)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		x.root.Remove(p)
		return err
	}
	x.made[t.ID] = p
	return x.finish(t, p)
}

// finish sets the mode and the times of a file or a directory.
func (x *extractor) finish(m *Member, p string) error {
	mode := fs.FileMode(m.Mode & 0o777)
	for bit, fm := range map[uint64]fs.FileMode{0o4000: fs.ModeSetuid, 0o2000: fs.ModeSetgid, 0o1000: fs.ModeSticky} {
		if m.Mode&bit != 0 {
			mode |= fm
		}
	}
	if err := x.root.Chmod(p, mode); err != nil {
		return err
	}
	atime, mtime := times(m)
	return x.root.Chtimes(p, atime, mtime)
}

// times gives the access and modification times of a member. A member with
// no atime gets its mtime.
func times(m *Member) (atime, mtime time.Time) {
	mtime = time.Unix(0, m.Mtime)
	atime = mtime
	if m.Atime != nil {
		atime = time.Unix(0, *m.Atime)
	}
	return atime, mtime
}
