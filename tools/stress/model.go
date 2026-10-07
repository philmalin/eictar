package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// The model is what the archive must hold: for each live path, what an
// extraction must give back. It changes only as eictar's own rules say
// (doc/design.md 9.2 and 10.5), so that any difference from a real
// extraction is a fault in eictar, or a fault in this model to correct.

type kind int

const (
	kFile kind = iota
	kDir
	kLink
)

func (k kind) String() string { return [...]string{"file", "dir", "symlink"}[k] }

// Entry is one member as an extraction must restore it.
type Entry struct {
	Kind   kind
	Perm   fs.FileMode // permission bits
	MTime  int64       // nanoseconds
	Size   int64       // files only
	Hash   [32]byte    // SHA-256 of the content, files only
	Target string      // symlinks only
	// Link is the link group, files only. The names of one inode that one
	// run records share a group, and extraction must give them back as
	// one file (doc/design.md 7.7, 9.2). Names from other runs, or of other
	// inodes, have other groups, and must be other files.
	Link int
}

// Model maps a stored path to its entry.
type Model map[string]Entry

func (m Model) clone() Model { return maps.Clone(m) }

// readEntry records what is on disk at abs, as eictar would archive it.
func readEntry(abs string) (Entry, error) {
	fi, err := os.Lstat(abs)
	if err != nil {
		return Entry{}, err
	}
	e := Entry{Perm: fi.Mode().Perm(), MTime: fi.ModTime().UnixNano()}
	switch {
	case fi.Mode()&fs.ModeSymlink != 0:
		e.Kind = kLink
		e.Target, err = os.Readlink(abs)
		return e, err
	case fi.IsDir():
		e.Kind = kDir
		return e, nil
	case fi.Mode().IsRegular():
		e.Kind = kFile
		e.Size = fi.Size()
		e.Hash, err = hashFile(abs)
		return e, err
	}
	return Entry{}, fmt.Errorf("%s: unexpected file type %v", abs, fi.Mode().Type())
}

func hashFile(p string) ([32]byte, error) {
	var sum [32]byte
	f, err := os.Open(p)
	if err != nil {
		return sum, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return sum, err
	}
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

// walked returns the paths that eictar visits for the arguments, relative to
// src: each argument and everything below it, without following links. A
// path named twice is visited once, as eictar does.
func walked(src string, args []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, a := range args {
		err := filepath.WalkDir(filepath.Join(src, a), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(src, p)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			if !seen[rel] {
				seen[rel] = true
				out = append(out, rel)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// filter is -R and --exclude-regex for the walk of -r and -u, as eictar
// applies them (doc/design.md 10.11): each expression matches the whole
// stored path; an excluded path is left out, and an excluded directory is not
// entered; with -R, only the paths that match are kept, but every directory
// is still entered, because a match can be deeper down.
type filter struct {
	include, exclude *regexp.Regexp
}

func (f filter) String() string {
	var b strings.Builder
	if f.include != nil {
		fmt.Fprintf(&b, " -R %q", strings.TrimSuffix(strings.TrimPrefix(f.include.String(), "(?s)^(?:"), ")$"))
	}
	if f.exclude != nil {
		fmt.Fprintf(&b, " --exclude-regex %q", strings.TrimSuffix(strings.TrimPrefix(f.exclude.String(), "(?s)^(?:"), ")$"))
	}
	return b.String()
}

// The expressions that the steps choose from. The generated names are a
// word, digits and now and then an extension, so each one matches some
// paths of most trees, and none of some: both cases are tested.
var (
	includeRegexes = []string{`.*\.(txt|go)`, `.*/[a-m][^/]*`, `[^/]*`, `.*[0-9]`}
	excludeRegexes = []string{`.*/[n-z][^/]*`, `.*\.bin`, `[^/]*/[^/]*/.*`}
)

// walkedFiltered is walked with a filter.
func walkedFiltered(src string, args []string, f filter) ([]string, error) {
	if f.include == nil && f.exclude == nil {
		return walked(src, args)
	}
	seen := map[string]bool{}
	var out []string
	for _, a := range args {
		err := filepath.WalkDir(filepath.Join(src, a), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(src, p)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			if f.exclude != nil && f.exclude.MatchString(rel) {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if f.include != nil && !f.include.MatchString(rel) {
				return nil
			}
			if !seen[rel] {
				seen[rel] = true
				out = append(out, rel)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// stale is eictar's -u test for one path (doc/design.md 10.5).
func stale(old, cur Entry, mode string) bool {
	if old.Kind != cur.Kind {
		return true
	}
	if cur.Kind == kLink && old.Target != cur.Target {
		return true
	}
	switch mode {
	case "newer":
		return cur.MTime > old.MTime
	case "digest":
		if cur.Kind == kFile {
			return cur.Hash != old.Hash
		}
	}
	return cur.MTime != old.MTime || (cur.Kind == kFile && cur.Size != old.Size)
}

// matches is eictar's pattern rule for a literal pattern (no glob
// characters, which the generator never puts in a name): the path itself,
// everything below it, and - for a pattern without a slash - any path that
// has that name as one of its components, and so everything below a
// directory of that name at any depth.
func matches(pattern, p string) bool {
	if p == pattern || strings.HasPrefix(p, pattern+"/") {
		return true
	}
	if strings.Contains(pattern, "/") {
		return false
	}
	for _, name := range strings.Split(p, "/") {
		if name == pattern {
			return true
		}
	}
	return false
}

// selectPaths returns the model paths that any pattern matches.
func (m Model) selectPaths(patterns []string) Model {
	out := Model{}
	for p, e := range m {
		for _, pat := range patterns {
			if matches(pat, p) {
				out[p] = e
				break
			}
		}
	}
	return out
}

// linkGroups returns the paths of each link group with two names or more.
func (m Model) linkGroups() map[int][]string {
	all := map[int][]string{}
	for _, p := range m.paths() {
		if e := m[p]; e.Kind == kFile {
			all[e.Link] = append(all[e.Link], p)
		}
	}
	out := map[int][]string{}
	for g, ps := range all {
		if len(ps) > 1 {
			out[g] = ps
		}
	}
	return out
}

func (m Model) paths() []string {
	out := make([]string, 0, len(m))
	for p := range m {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// ancestors returns every directory above a model path. Extraction creates
// them when the archive has no member for them.
func (m Model) ancestors() map[string]bool {
	out := map[string]bool{}
	for p := range m {
		for d := path.Dir(p); d != "." && d != "/"; d = path.Dir(d) {
			out[d] = true
		}
	}
	return out
}
