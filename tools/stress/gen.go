//go:build unix

package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

// gen makes and changes the source tree. Everything comes from its random
// source and from a clock of its own, never from the system clock, so that a
// seed gives the same trees, the same times and thus the same decisions of
// -u on every run.
type gen struct {
	rnd     *rand.Rand
	src     string
	clock   int64 // nanoseconds; moves forward with each change
	nonUTF8 bool  // the filesystem takes names that are not UTF-8
}

// Chunk sizes that the steps choose from. File sizes cluster around them,
// because that is where chunking goes wrong.
var chunkSizes = []int{512, 4096, 65536, 1 << 20, 4 << 20}

var words = strings.Fields("archive chunk index member codec trailer header sparse " +
	"the of and to in is that for it with as was on be at by this")

func newGen(rnd *rand.Rand, src string) *gen {
	g := &gen{rnd: rnd, src: src, clock: 1_600_000_000 * 1e9}
	probe := filepath.Join(src, ".probe-\xe9")
	if os.WriteFile(probe, nil, 0o600) == nil {
		g.nonUTF8 = true
		os.Remove(probe)
	}
	return g
}

// tick moves the clock and returns it: each new or changed entry gets its own
// time.
func (g *gen) tick() int64 {
	g.clock += 1e9 + g.rnd.Int64N(1e9)
	return g.clock
}

// name makes a file name. It never holds a glob character, so that a path
// used as a pattern matches literally.
func (g *gen) name() string {
	var b strings.Builder
	switch g.rnd.IntN(12) {
	case 0:
		b.WriteString("with space ")
	case 1:
		b.WriteString("ünïcödé-")
	case 2:
		if g.nonUTF8 {
			b.WriteString("latin\xe9-")
		}
	case 3:
		b.WriteString("-dash-")
	case 4:
		b.WriteString(strings.Repeat("long", 20))
	}
	fmt.Fprintf(&b, "%s%d", words[g.rnd.IntN(len(words))], g.rnd.IntN(100000))
	if g.rnd.IntN(3) == 0 {
		b.WriteString([]string{".txt", ".bin", ".dat", ".go"}[g.rnd.IntN(4)])
	}
	return b.String()
}

// size picks a file size: mostly small, often at a chunk boundary, and now
// and then large.
func (g *gen) size() int {
	switch g.rnd.IntN(10) {
	case 0:
		return 0
	case 1, 2:
		cs := chunkSizes[g.rnd.IntN(3)] // the boundaries a small tree can reach
		return cs + g.rnd.IntN(3) - 1   // one below, at, one above
	case 3:
		return g.rnd.IntN(3<<20) + 1
	default:
		return g.rnd.IntN(8192) + 1
	}
}

// content makes n bytes of one of several kinds, because each kind takes a
// different path through the codecs: incompressible chunks are stored as
// they are, zeros compress to almost nothing, and text is in between.
func (g *gen) content(n int) []byte {
	out := make([]byte, 0, n)
	kind := g.rnd.IntN(5)
	for len(out) < n {
		switch kind {
		case 0: // random
			b := make([]byte, min(4096, n-len(out)))
			for i := range b {
				b[i] = byte(g.rnd.Uint32())
			}
			out = append(out, b...)
		case 1: // text
			out = append(out, words[g.rnd.IntN(len(words))]...)
			out = append(out, ' ')
		case 2: // a short pattern, repeated
			out = append(out, "0123456789abcdef"[:1+g.rnd.IntN(16)]...)
		case 3: // zeros
			out = append(out, make([]byte, min(4096, n-len(out)))...)
		default: // blocks of the other kinds, mixed
			kind = g.rnd.IntN(4)
		}
	}
	return out[:n]
}

// perm picks a file mode that the owner can read, without special bits.
func (g *gen) perm(dir bool) fs.FileMode {
	if dir {
		return []fs.FileMode{0o755, 0o750, 0o700}[g.rnd.IntN(3)]
	}
	return []fs.FileMode{0o644, 0o600, 0o640, 0o755, 0o400}[g.rnd.IntN(5)]
}

// writeFile makes a new file at rel: dense, or now and then sparse.
func (g *gen) writeFile(rel string) error {
	p := filepath.Join(g.src, rel)
	os.Remove(p) // a new inode: never write through a hardlink
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if g.rnd.IntN(12) == 0 {
		// Sparse: a logical size of a few MiB, with a few data regions.
		size := int64(1+g.rnd.IntN(8)) << 20
		for i := 0; i < 1+g.rnd.IntN(3); i++ {
			if _, err := f.WriteAt(g.content(1+g.rnd.IntN(16384)), g.rnd.Int64N(size)); err != nil {
				f.Close()
				return err
			}
		}
		err = f.Truncate(size)
	} else {
		_, err = f.Write(g.content(g.size()))
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Chmod(p, g.perm(false)); err != nil {
		return err
	}
	return g.setTime(rel, g.tick())
}

// setTime sets the modification time of rel, not following a link.
func (g *gen) setTime(rel string, nanos int64) error {
	ts := []unix.Timespec{unix.NsecToTimespec(nanos), unix.NsecToTimespec(nanos)}
	return unix.UtimesNanoAt(unix.AT_FDCWD, filepath.Join(g.src, rel), ts, unix.AT_SYMLINK_NOFOLLOW)
}

// populate fills an empty src with a tree of n entries.
func (g *gen) populate(n int) error {
	dirs := []string{"."}
	for i := 0; i < n; i++ {
		parent := dirs[g.rnd.IntN(len(dirs))]
		rel := path.Join(parent, g.name())
		if err := g.addEntry(rel, &dirs); err != nil {
			return err
		}
	}
	return g.fixDirTimes()
}

// addEntry makes one new entry: a directory, a file, a symbolic link or a
// hardlink to an existing file.
func (g *gen) addEntry(rel string, dirs *[]string) error {
	switch r := g.rnd.IntN(20); {
	case r < 4 && strings.Count(rel, "/") < 6:
		if err := os.Mkdir(filepath.Join(g.src, rel), g.perm(true)); err != nil {
			return err
		}
		*dirs = append(*dirs, rel)
		return nil
	case r < 6:
		target := []string{"elsewhere", "../up", "/absolute/target", g.name()}[g.rnd.IntN(4)]
		if err := os.Symlink(target, filepath.Join(g.src, rel)); err != nil {
			return err
		}
		return g.setTime(rel, g.tick())
	case r < 7:
		if files := g.files(); len(files) > 0 {
			return os.Link(filepath.Join(g.src, files[g.rnd.IntN(len(files))]), filepath.Join(g.src, rel))
		}
		fallthrough
	default:
		return g.writeFile(rel)
	}
}

// entries lists the source tree, relative, sorted: the order is part of what
// a seed decides.
func (g *gen) entries(pred func(fs.DirEntry) bool) []string {
	var out []string
	filepath.WalkDir(g.src, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == g.src {
			return nil
		}
		if pred(d) {
			rel, _ := filepath.Rel(g.src, p)
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	sort.Strings(out)
	return out
}

func (g *gen) files() []string {
	return g.entries(func(d fs.DirEntry) bool { return d.Type().IsRegular() })
}

func (g *gen) dirs() []string {
	return g.entries(func(d fs.DirEntry) bool { return d.IsDir() })
}

func (g *gen) all() []string {
	return g.entries(func(fs.DirEntry) bool { return true })
}

// mutate changes the source tree between steps, so that append, replace and
// update have real work. A directory never becomes a file or a link: eictar
// would keep the old directory's members live under a file of the same
// name, which no extraction can restore, and which is a separate question
// from correctness.
func (g *gen) mutate() (string, error) {
	var did []string
	for n := 1 + g.rnd.IntN(6); n > 0; n-- {
		files := g.files()
		switch r := g.rnd.IntN(10); {
		case r < 3 && len(files) > 0: // new content, a later time
			f := files[g.rnd.IntN(len(files))]
			did = append(did, "rewrite "+f)
			if err := g.writeFile(f); err != nil {
				return "", err
			}
		case r < 4 && len(files) > 0: // same content, another time
			f := files[g.rnd.IntN(len(files))]
			delta := g.rnd.Int64N(4e9) - 2e9 // earlier or later
			fi, err := os.Lstat(filepath.Join(g.src, f))
			if err != nil {
				return "", err
			}
			did = append(did, "touch "+f)
			if err := g.setTime(f, fi.ModTime().UnixNano()+delta); err != nil {
				return "", err
			}
		case r < 5 && len(files) > 0: // mode only
			f := files[g.rnd.IntN(len(files))]
			did = append(did, "chmod "+f)
			if err := os.Chmod(filepath.Join(g.src, f), g.perm(false)); err != nil {
				return "", err
			}
		case r < 6 && len(files) > 0: // gone from disk; the archive keeps it
			f := files[g.rnd.IntN(len(files))]
			did = append(did, "remove "+f)
			if err := os.Remove(filepath.Join(g.src, f)); err != nil {
				return "", err
			}
		case r < 7 && len(files) > 0: // a file becomes a link
			f := files[g.rnd.IntN(len(files))]
			did = append(did, "file to symlink "+f)
			os.Remove(filepath.Join(g.src, f))
			if err := os.Symlink("was-a-file", filepath.Join(g.src, f)); err != nil {
				return "", err
			}
			if err := g.setTime(f, g.tick()); err != nil {
				return "", err
			}
		default: // something new
			dirs := append([]string{"."}, g.dirs()...)
			rel := path.Join(dirs[g.rnd.IntN(len(dirs))], g.name())
			did = append(did, "add "+rel)
			if err := g.addEntry(rel, &dirs); err != nil {
				return "", err
			}
		}
	}
	return strings.Join(did, "; "), g.fixDirTimes()
}

// fixDirTimes gives every directory a time from the clock. A change inside a
// directory sets its time to now, which no seed can repeat.
func (g *gen) fixDirTimes() error {
	dirs := g.dirs()
	for i := len(dirs) - 1; i >= 0; i-- { // deepest first
		if err := g.setTime(dirs[i], g.tick()); err != nil {
			return err
		}
	}
	return nil
}

// pickArgs chooses paths in src for create, append or update: the whole
// tree, or a few entries.
func (g *gen) pickArgs() []string {
	all := g.all()
	if len(all) == 0 {
		return nil
	}
	if g.rnd.IntN(3) == 0 {
		var top []string
		for _, p := range all {
			if !strings.Contains(p, "/") {
				top = append(top, p)
			}
		}
		return top
	}
	var out []string
	for n := 1 + g.rnd.IntN(4); n > 0; n-- {
		out = append(out, all[g.rnd.IntN(len(all))])
	}
	return out
}

// sameBytes reports whether two files hold the same bytes, for the checks.
func sameBytes(a, b []byte) bool { return bytes.Equal(a, b) }
