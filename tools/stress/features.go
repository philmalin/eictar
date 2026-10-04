//go:build unix

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

// The steps of this file test --diff (doc/design.md 9.8), the dry run -n
// (9.9) and --strip-components (10.14) against the model.

// lines splits the output of a command into its lines.
func lines(out string) []string {
	out = strings.TrimRight(out, "\n")
	if out == "" {
		return nil
	}
	return strings.Split(out, "\n")
}

// dryRun is the dry run of an append, an update, a delete or an extraction.
func (s *sequence) dryRun() error {
	switch s.rnd.IntN(4) {
	case 0:
		return s.add("-r", true)
	case 1:
		return s.add("-u", true)
	case 2:
		return s.deleteDryRun()
	default:
		return s.extractDryRun()
	}
}

// checkDryRun checks a dry run that succeeded: its paths are want (in that
// order when ordered, as a set when not), and the archive is as before.
func (s *sequence) checkDryRun(res result, want []string, ordered bool, before []byte) error {
	got := lines(res.stdout)
	if !ordered {
		got = append([]string(nil), got...)
		want = append([]string(nil), want...)
		sort.Strings(got)
		sort.Strings(want)
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		return fmt.Errorf("the dry run's paths are not the paths of the real run:\n  got  %q\n  want %q\n%s", got, want, res)
	}
	if err := s.unchanged(before); err != nil {
		return fmt.Errorf("dry run: %w", err)
	}
	s.stats.checks["dry-run"]++
	return nil
}

// deleteDryRun is --delete -n: the paths are the members that the patterns
// select, and nothing changes.
func (s *sequence) deleteDryRun() error {
	paths := s.model.paths()
	if len(paths) == 0 {
		return nil
	}
	var patterns []string
	for n := 1 + s.rnd.IntN(2); n > 0; n-- {
		patterns = append(patterns, paths[s.rnd.IntN(len(paths))])
	}
	s.note("-n delete %q", patterns)
	s.stats.ops["-n delete"]++
	before, err := os.ReadFile(s.archive)
	if err != nil {
		return err
	}
	res, err := s.r.expect(true, withPaths([]string{"--delete", "-n", "-f", s.archive}, patterns)...)
	if err != nil {
		return err
	}
	return s.checkDryRun(res, s.model.selectPaths(patterns).paths(), false, before)
}

// extractDryRun is -x -n, of everything or by pattern: the paths come in
// path order, and the destination is not made.
func (s *sequence) extractDryRun() error {
	paths := s.model.paths()
	var patterns []string
	want := s.model
	if len(paths) > 0 && s.rnd.IntN(2) == 0 {
		for n := 1 + s.rnd.IntN(2); n > 0; n-- {
			patterns = append(patterns, paths[s.rnd.IntN(len(paths))])
		}
		want = s.model.selectPaths(patterns)
	}
	s.note("-n extract %q", patterns)
	s.stats.ops["-n extract"]++
	before, err := os.ReadFile(s.archive)
	if err != nil {
		return err
	}
	dest := filepath.Join(s.dir, "out-dry")
	if err := removeAll(dest); err != nil {
		return err
	}
	res, err := s.r.expect(true, withPaths([]string{"-xnf", s.archive, "-d", dest}, patterns)...)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(dest); !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("the dry run of an extraction made its destination (%v)", err)
	}
	return s.checkDryRun(res, want.paths(), true, before)
}

// diffStep extracts the archive, and runs --diff on the result: there must
// be no difference. Then it makes one change to the extracted tree, and
// --diff must report that path, with that kind of difference, and nothing
// else.
func (s *sequence) diffStep() error {
	s.stats.ops["diff"]++
	out := filepath.Join(s.dir, "out-diff")
	if err := removeAll(out); err != nil {
		return err
	}
	if _, err := s.r.expect(true, "-xf", s.archive, "-d", out); err != nil {
		return fmt.Errorf("extract for --diff: %w", err)
	}
	res, err := s.r.run(true, "--diff", "-f", s.archive, "-C", out)
	if err != nil {
		return err
	}
	if res.code != 0 || !strings.Contains(res.stdout, ": no differences, ") {
		return fmt.Errorf("--diff of a tree just extracted: exit %d, want 0 and no differences:\n%s", res.code, res)
	}
	s.stats.checks["diff-clean"]++

	p, want, err := s.changeExtracted(out)
	if err != nil || p == "" {
		s.note("diff: no change")
		return err
	}
	s.note("diff after a change of %q: want %q", p, want)
	res, err = s.r.run(true, "--diff", "-f", s.archive, "-C", out)
	if err != nil {
		return err
	}
	got := lines(res.stdout)
	if res.code != 1 || len(got) != 1 || !strings.HasPrefix(got[0], want) {
		return fmt.Errorf("--diff after one change: exit %d, want 1 and the one line %q...:\n%s", res.code, want, res)
	}
	s.stats.checks["diff-change"]++
	return nil
}

// changeExtracted makes one change under the extracted tree out, and keeps
// the time of the parent directory, so that the change is the one
// difference. It returns the path and the start of the line that --diff
// must give, or "" when the tree has nothing that it can change.
func (s *sequence) changeExtracted(out string) (string, string, error) {
	var files, dirs, links []string
	for _, p := range s.model.paths() {
		fi, err := os.Lstat(filepath.Join(out, p))
		if err != nil {
			return "", "", err
		}
		switch e := s.model[p]; e.Kind {
		case kFile:
			// One name only: a change to a file with two names is a change
			// of both paths.
			if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Nlink == 1 {
				files = append(files, p)
			}
		case kDir:
			dirs = append(dirs, p)
		case kLink:
			links = append(links, p)
		}
	}
	pick := func(from []string) string { return from[s.rnd.IntN(len(from))] }

	type change struct {
		from []string
		do   func(p string) (string, error)
	}
	changes := []change{
		{files, func(p string) (string, error) { // other bytes, the same size
			abs := filepath.Join(out, p)
			b, err := os.ReadFile(abs)
			if err != nil || len(b) == 0 {
				return "", err
			}
			b[s.rnd.IntN(len(b))] ^= 0x55
			// The file can be read-only: it is writable for the change only.
			return p + ": content differs", keepTimes(abs, func() error {
				if err := os.Chmod(abs, 0o600); err != nil {
					return err
				}
				if err := os.WriteFile(abs, b, 0); err != nil {
					return err
				}
				return os.Chmod(abs, s.model[p].Perm)
			})
		}},
		{files, func(p string) (string, error) {
			abs := filepath.Join(out, p)
			mode := s.model[p].Perm ^ 0o004
			return p + ": mode differs", os.Chmod(abs, mode)
		}},
		{append(files, dirs...), func(p string) (string, error) {
			mtime := s.model[p].MTime + 1e9
			return p + ": mtime differs", setTimeAbs(filepath.Join(out, p), mtime)
		}},
		{files, func(p string) (string, error) {
			abs := filepath.Join(out, p)
			return p + ": not on disk", keepTimes(filepath.Dir(abs), func() error { return os.Remove(abs) })
		}},
		{dirs, func(p string) (string, error) {
			n := path.Join(p, "added-by-stress")
			abs := filepath.Join(out, n)
			return n + ": not in the archive", keepTimes(filepath.Dir(abs), func() error { return os.WriteFile(abs, nil, 0o644) })
		}},
		{links, func(p string) (string, error) {
			abs := filepath.Join(out, p)
			mtime := s.model[p].MTime
			err := keepTimes(filepath.Dir(abs), func() error {
				if err := os.Remove(abs); err != nil {
					return err
				}
				return os.Symlink(s.model[p].Target+"-changed", abs)
			})
			if err == nil {
				err = setTimeAbs(abs, mtime)
			}
			return p + ": link target differs", err
		}},
	}
	var possible []change
	for _, c := range changes {
		if len(c.from) > 0 {
			possible = append(possible, c)
		}
	}
	if len(possible) == 0 {
		return "", "", nil
	}
	c := possible[s.rnd.IntN(len(possible))]
	p := pick(c.from)
	want, err := c.do(p)
	if want == "" || err != nil {
		return "", "", err
	}
	return p, want, nil
}

// keepTimes runs change, and then gives abs its times of before.
func keepTimes(abs string, change func() error) error {
	fi, err := os.Lstat(abs)
	if err != nil {
		return err
	}
	if err := change(); err != nil {
		return err
	}
	return setTimeAbs(abs, fi.ModTime().UnixNano())
}

// setTimeAbs sets the times of abs, and not of what a link points to.
func setTimeAbs(abs string, nanos int64) error {
	ts := []unix.Timespec{unix.NsecToTimespec(nanos), unix.NsecToTimespec(nanos)}
	return unix.UtimesNanoAt(unix.AT_FDCWD, abs, ts, unix.AT_SYMLINK_NOFOLLOW)
}

// stripPath is eictar's --strip-components for one path.
func stripPath(p string, n int) (string, bool) {
	parts := strings.Split(p, "/")
	if len(parts) <= n {
		return "", false
	}
	return strings.Join(parts[n:], "/"), true
}

// stripModel is what extraction with --strip-components n must give, and
// the collisions it must report, as pairs of the member left out and the
// member kept. ok is false when the result depends on more than the rule:
// a kept path below a file or a link of another release.
func (m Model) stripModel(n int) (want Model, collisions [][2]string, ok bool) {
	want = Model{}
	from := map[string]string{}
	for _, p := range m.paths() { // path order decides which member wins
		q, keep := stripPath(p, n)
		if !keep {
			continue
		}
		if prev, taken := from[q]; taken {
			if m[prev].Kind != kDir || m[p].Kind != kDir {
				collisions = append(collisions, [2]string{prev, p})
			}
		}
		from[q] = p
		want[q] = m[p]
	}
	for q := range want {
		for d := path.Dir(q); d != "."; d = path.Dir(d) {
			if e, in := want[d]; in && e.Kind != kDir {
				return nil, nil, false
			}
		}
	}
	return want, collisions, true
}

// plainName reports whether eictar writes the name as it is in a message:
// valid UTF-8 with no backslash, control character or direction mark
// (doc/design.md 10.13).
func plainName(p string) bool {
	if !utf8.ValidString(p) || strings.ContainsRune(p, '\\') {
		return false
	}
	for _, r := range p {
		if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) {
			return false
		}
	}
	return true
}

// stripStep extracts with --strip-components, after a dry run of it, and
// checks the result and --diff with the option. Half the time it first
// adds a twin of a path under a new top directory, so that two members get
// one path.
func (s *sequence) stripStep() error {
	n := 1
	if s.rnd.IntN(4) == 0 {
		n = 2
	}
	if s.rnd.IntN(2) == 0 {
		if err := s.addTwin(n); err != nil {
			return err
		}
	}
	want, collisions, ok := s.model.stripModel(n)
	if !ok {
		s.note("strip-components %d: a path of one release is below a file of another; not tested", n)
		return nil
	}
	s.note("strip-components %d: %d collisions", n, len(collisions))
	s.stats.ops["strip-components"]++
	if len(collisions) > 0 {
		s.stats.ops["strip-components with a collision"]++
	}
	strip := fmt.Sprint(n)
	wantCode := 0
	if len(collisions) > 0 {
		wantCode = 1
	}
	checkMessages := func(res result, what string) error {
		for _, c := range collisions {
			msg := c[0] + ": " + what + ": " + c[1] + " has the same path after --strip-components"
			if plainName(c[0]) && plainName(c[1]) && !strings.Contains(res.stderr, msg) {
				return fmt.Errorf("no warning %q:\n%s", msg, res)
			}
		}
		if len(collisions) > 0 && !strings.Contains(res.stderr, fmt.Sprintf("%d member(s) left out", len(collisions))) {
			return fmt.Errorf("the count of %d collisions is not given:\n%s", len(collisions), res)
		}
		return nil
	}

	// The dry run first: the paths after the strip, in path order.
	before, err := os.ReadFile(s.archive)
	if err != nil {
		return err
	}
	dry := filepath.Join(s.dir, "out-dry")
	if err := removeAll(dry); err != nil {
		return err
	}
	res, err := s.r.run(true, "-xnf", s.archive, "-d", dry, "--strip-components", strip)
	if err != nil {
		return err
	}
	if res.code != wantCode {
		return fmt.Errorf("-n --strip-components: exit %d, want %d:\n%s", res.code, wantCode, res)
	}
	if err := checkMessages(res, "not extracted"); err != nil {
		return fmt.Errorf("-n --strip-components: %w", err)
	}
	if err := s.checkDryRun(res, want.paths(), true, before); err != nil {
		return fmt.Errorf("-n --strip-components: %w", err)
	}

	out := filepath.Join(s.dir, "out-strip")
	if err := removeAll(out); err != nil {
		return err
	}
	res, err = s.r.run(true, "-xf", s.archive, "-d", out, "--strip-components", strip)
	if err != nil {
		return err
	}
	if res.code != wantCode {
		return fmt.Errorf("--strip-components: exit %d, want %d:\n%s", res.code, wantCode, res)
	}
	if err := checkMessages(res, "not extracted"); err != nil {
		return fmt.Errorf("--strip-components: %w", err)
	}
	if err := compareTree(out, want); err != nil {
		return fmt.Errorf("--strip-components %d: %w", n, err)
	}
	s.stats.checks["strip"]++

	res, err = s.r.run(true, "--diff", "-f", s.archive, "-C", out, "--strip-components", strip)
	if err != nil {
		return err
	}
	clean := strings.Contains(res.stdout, ": no differences, ")
	if len(collisions) > 0 {
		clean = res.stdout == ""
	}
	if res.code != wantCode || !clean {
		return fmt.Errorf("--diff --strip-components %d of that tree: exit %d, want %d and no differences:\n%s",
			n, res.code, wantCode, res)
	}
	if err := checkMessages(res, "not compared"); err != nil {
		return fmt.Errorf("--diff --strip-components: %w", err)
	}
	s.stats.checks["strip-diff"]++
	return nil
}

// addTwin copies one entry of the source tree under a new top directory,
// at the same depth as the original, so that the two have one path after
// --strip-components n. Then it appends the copy, as a step of its own.
func (s *sequence) addTwin(n int) error {
	var deep []string
	for _, p := range s.model.paths() {
		if strings.Count(p, "/") >= n {
			if _, err := os.Lstat(filepath.Join(s.src, p)); err == nil {
				deep = append(deep, p)
			}
		}
	}
	if len(deep) == 0 {
		return nil
	}
	orig := deep[s.rnd.IntN(len(deep))]
	rest, _ := stripPath(orig, n)
	prefix := make([]string, n)
	for i := range prefix {
		prefix[i] = "twin-" + s.g.name()
	}
	twin := path.Join(path.Join(prefix...), rest)
	if err := os.MkdirAll(filepath.Join(s.src, path.Dir(twin)), 0o755); err != nil {
		return err
	}
	abs := filepath.Join(s.src, twin)
	fi, err := os.Lstat(filepath.Join(s.src, orig))
	if err != nil {
		return err
	}
	switch {
	case fi.IsDir():
		err = os.Mkdir(abs, s.g.perm(true))
	case fi.Mode()&fs.ModeSymlink != 0:
		var target string
		if target, err = os.Readlink(filepath.Join(s.src, orig)); err == nil {
			err = os.Symlink(target, abs)
		}
	default:
		err = s.g.copyFile(orig, twin, s.rnd.IntN(2) == 0)
	}
	if err != nil {
		return err
	}
	if err := s.g.setTime(twin, s.g.tick()); err != nil {
		return err
	}
	if err := s.g.fixDirTimes(); err != nil {
		return err
	}

	top := prefix[0]
	s.note("add a twin of %q at %q, and append it", orig, twin)
	s.stats.ops["-r of a twin"]++
	spec := s.codecSpec()
	opts := append([]string{"-rf", s.archive, "-C", s.src, "--compress", spec}, s.tuning(spec)...)
	if _, err := s.r.expect(true, withPaths(opts, []string{top})...); err != nil {
		return fmt.Errorf("append a twin: %w", err)
	}
	if _, _, _, err := s.addToModel([]string{top}, "replace", "", filter{}); err != nil {
		return err
	}
	if err := s.checkArchive(); err != nil {
		return fmt.Errorf("after the append of a twin: %w", err)
	}
	return nil
}
