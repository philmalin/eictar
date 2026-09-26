//go:build unix

package main

import (
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// sequence is one archive and its history: a create, then steps of
// changes, each followed by the checks.
type sequence struct {
	seed        uint64
	rnd         *rand.Rand
	dir         string
	src         string
	archive     string
	encrypted   bool
	passphrases int // changes of passphrase so far
	g           *gen
	r           *runner
	model       Model
	steps       []string // what each step did, for the failure report
	faults      bool
	stats       *stats
	profile     string // the kind of tree (gen.go)
}

type stats struct {
	sequences, steps, commands  int
	crashes, flips, flipsCaught int
	ops                         map[string]int
	profiles                    map[string]int
	// withDict and withShared count the sequences that ended with a
	// dictionary, and with shared content: coverage, not assumed.
	withDict, withShared int
}

func newSequence(seed uint64, dir, bin string, faults bool, st *stats, profile string) (*sequence, error) {
	s := &sequence{
		seed:   seed,
		rnd:    rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)),
		dir:    dir,
		src:    filepath.Join(dir, "src"),
		faults: faults,
		stats:  st,
	}
	// The profile is the first draw, so that a seed gives the same one again;
	// -profile forces it, and the draw still happens.
	s.profile = pickProfile(s.rnd)
	if profile != "" {
		s.profile = profile
	}
	st.profiles[s.profile]++
	s.archive = filepath.Join(dir, "archive.ect")
	if err := os.MkdirAll(s.src, 0o755); err != nil {
		return nil, err
	}
	s.g = newGen(s.rnd, s.src, s.profile)
	s.r = &runner{bin: bin, dir: dir}
	s.encrypted = s.rnd.IntN(3) == 0
	if s.encrypted {
		pass := filepath.Join(dir, "passphrase")
		if err := os.WriteFile(pass, []byte("stress test passphrase\n"), 0o600); err != nil {
			return nil, err
		}
		s.r.crypt = []string{"--passphrase-file", pass}
	}
	return s, nil
}

// codecSpec picks a codec and its settings. The strongest settings of zstd
// and xz are left out: they are slow, and the codec tests cover them.
func (s *sequence) codecSpec() string {
	pick := s.rnd.IntN(7)
	if s.profile == "small" && s.rnd.IntN(2) == 0 {
		pick = 1 // zstd with a dictionary: what a tree of small files is for
	}
	switch pick {
	case 0:
		return "none"
	case 1:
		spec := "zstd:level=" + strconv.Itoa(1+s.rnd.IntN(15))
		// A dictionary on create, append and recompress (doc/design.md 4.2).
		// Small sizes, so that a generated tree can fill them, and the forms
		// alone and at the limit; a tree that cannot fill one gives a
		// notice and no dictionary, which is a case too.
		if s.rnd.IntN(2) == 0 || s.profile == "small" {
			spec += "," + []string{"train=4K", "train=8K", "train=16K", "train", "train=1M"}[s.rnd.IntN(5)]
		}
		// A window: alone (27), or one that a large chunk can hold.
		switch s.rnd.IntN(6) {
		case 0:
			spec += ",long"
		case 1:
			spec += ",long=" + strconv.Itoa(20+s.rnd.IntN(5))
		}
		return spec
	case 2:
		return "gzip:level=" + strconv.Itoa(1+s.rnd.IntN(9))
	case 3:
		return "flate:level=" + strconv.Itoa(1+s.rnd.IntN(9))
	case 4:
		return "xz:preset=" + strconv.Itoa(s.rnd.IntN(7))
	case 5:
		return "s2:mode=" + []string{"fast", "better", "best"}[s.rnd.IntN(3)]
	default:
		return "zstd"
	}
}

// tuning picks the options that change how the work is done, not what is
// stored: chunk size, workers, and a memory budget and spill threshold that
// are now and then small enough to force spilling and waiting.
func (s *sequence) tuning() []string {
	sizes := chunkSizes
	if s.profile == "large" {
		// Chunks as large as the files, which a window of long can use.
		sizes = append(append([]int(nil), chunkSizes...), 16<<20, 32<<20)
	}
	args := []string{
		"--chunk-size", strconv.Itoa(sizes[s.rnd.IntN(len(sizes))]),
		"-j", strconv.Itoa(1 + s.rnd.IntN(8)),
	}
	if s.rnd.IntN(4) == 0 {
		args = append(args, "--memory-limit", strconv.Itoa(1<<(10+s.rnd.IntN(12))))
	}
	if s.rnd.IntN(4) == 0 {
		args = append(args, "--spill-threshold", strconv.Itoa(1<<(10+s.rnd.IntN(12))))
	}
	return args
}

func (s *sequence) note(format string, args ...any) {
	s.steps = append(s.steps, fmt.Sprintf(format, args...))
}

// run creates the archive and takes n steps, checking after each.
func (s *sequence) run(n int) error {
	if err := s.g.populate(); err != nil {
		return err
	}
	if err := s.create(); err != nil {
		return err
	}
	for i := 0; i < n; i++ {
		s.stats.steps++
		if err := s.step(); err != nil {
			return err
		}
		if err := s.checkArchive(); err != nil {
			return fmt.Errorf("after step %d (%s): %w", len(s.steps), s.steps[len(s.steps)-1], err)
		}
		if s.faults && s.rnd.IntN(6) == 0 {
			if err := s.flipCheck(); err != nil {
				return fmt.Errorf("damage after step %d: %w", len(s.steps), err)
			}
		}
	}
	return s.coverage()
}

// coverage counts what the final archive holds that the features of M10 and
// M11 make: a dictionary, and shared content.
func (s *sequence) coverage() error {
	res, err := s.r.expect(true, "--info", "-f", s.archive)
	if err != nil {
		return fmt.Errorf("info: %w", err)
	}
	if strings.Contains(res.stdout, "\ndictionary:") {
		s.stats.withDict++
	}
	if strings.Contains(res.stdout, "\nshared content:") {
		s.stats.withShared++
	}
	return nil
}

func (s *sequence) create() error {
	args := s.g.pickArgs()
	opts := append([]string{"-cf", s.archive, "-C", s.src, "--compress", s.codecSpec()}, s.tuning()...)
	if s.encrypted {
		opts = append(opts, "-e", "--kdf-memory", "8192", "--kdf-time", "1", "--kdf-threads", "1")
		if s.rnd.IntN(2) == 0 {
			opts = append(opts, "--encrypt-index")
		}
	}
	if s.rnd.IntN(5) == 0 {
		opts = append(opts, "--no-dedup")
	}
	s.note("create %q encrypted=%v", args, s.encrypted)
	s.stats.ops["create"]++
	if _, err := s.r.expect(true, withPaths(opts, args)...); err != nil {
		return fmt.Errorf("create: %w", err)
	}
	s.model = Model{}
	if _, _, err := s.addToModel(args, "replace", "", filter{}); err != nil {
		return err
	}
	if err := s.checkArchive(); err != nil {
		return fmt.Errorf("after create: %w", err)
	}
	return nil
}

// step changes the source tree now and then, and does one operation.
func (s *sequence) step() error {
	if s.rnd.IntN(3) != 0 {
		did, err := s.g.mutate()
		if err != nil {
			return err
		}
		s.note("change the source: %s", did)
	}
	op := s.rnd.IntN(20)
	switch {
	case op < 5:
		return s.crashable(func() error { return s.add("-r") })
	case op < 9:
		return s.crashable(func() error { return s.add("-u") })
	case op < 12:
		return s.crashable(s.delete)
	case op < 14:
		return s.compact(false)
	case op < 15:
		return s.compact(true)
	case op < 16 && s.encrypted:
		return s.changePassphrase()
	default:
		return s.extractSome()
	}
}

// add is -r (with an --on-conflict policy) or -u (with an --update-mode).
func (s *sequence) add(op string) error {
	args := s.g.pickArgs()
	if len(args) == 0 {
		return nil
	}
	opts := append([]string{op + "f", s.archive, "-C", s.src, "--compress", s.codecSpec()}, s.tuning()...)
	var policy, mode string
	if op == "-r" {
		policy = []string{"replace", "skip", "error"}[s.rnd.IntN(3)]
		if policy != "replace" || s.rnd.IntN(2) == 0 {
			opts = append(opts, "--on-conflict", policy)
		}
	} else {
		policy = "update"
		mode = []string{"newer", "different", "digest"}[s.rnd.IntN(3)]
		opts = append(opts, "--update-mode", mode)
	}
	// Selection by regular expression (doc/design.md 10.11), and now and
	// then each copy stored in full (4.3).
	var f filter
	if s.rnd.IntN(6) == 0 {
		re := includeRegexes[s.rnd.IntN(len(includeRegexes))]
		f.include = regexp.MustCompile(`(?s)^(?:` + re + `)$`)
		opts = append(opts, "-R", re)
	}
	if s.rnd.IntN(8) == 0 {
		re := excludeRegexes[s.rnd.IntN(len(excludeRegexes))]
		f.exclude = regexp.MustCompile(`(?s)^(?:` + re + `)$`)
		opts = append(opts, "--exclude-regex", re)
	}
	if s.rnd.IntN(5) == 0 {
		opts = append(opts, "--no-dedup")
	}
	s.note("%s %q %s%s%s", op, args, policy, map[bool]string{true: " " + mode}[mode != ""], f)
	s.stats.ops[strings.TrimSpace(op+" "+policy+" "+mode)]++
	if f.include != nil || f.exclude != nil {
		s.stats.ops["-r/-u with a regex"]++
	}

	before, err := os.ReadFile(s.archive)
	if err != nil {
		return err
	}
	refused, why, err := s.addToModel(args, policy, mode, f)
	if err != nil {
		return err
	}
	res, err := s.r.run(true, withPaths(opts, args)...)
	if err != nil {
		return err
	}
	if refused {
		// A conflict under --on-conflict=error, or an -R that matches
		// nothing: exit 2, and the archive exactly as it was.
		if res.code != 2 {
			return fmt.Errorf("%s: exit %d, want 2:\n%s", why, res.code, res)
		}
		return s.unchanged(before)
	}
	if res.code != 0 {
		return fmt.Errorf("exit %d, want 0:\n%s", res.code, res)
	}
	return nil
}

// addToModel applies an append, update or create to the model, from the
// source tree as it is now. For --on-conflict=error with a conflict, or an -R
// that matches nothing, it reports a refusal and changes nothing.
func (s *sequence) addToModel(args []string, policy, mode string, f filter) (refused bool, why string, err error) {
	paths, err := walkedFiltered(s.src, args, f)
	if err != nil {
		return false, "", err
	}
	if f.include != nil && len(paths) == 0 {
		return true, "an -R that matches nothing", nil
	}
	if policy == "error" {
		for _, p := range paths {
			if _, ok := s.model[p]; ok {
				return true, "a conflict under --on-conflict=error", nil
			}
		}
	}
	for _, p := range paths {
		cur, err := readEntry(filepath.Join(s.src, p))
		if err != nil {
			return false, "", err
		}
		old, exists := s.model[p]
		switch {
		case !exists, policy == "replace", policy == "error":
			s.model[p] = cur
		case policy == "update" && stale(old, cur, mode):
			s.model[p] = cur
		}
	}
	return false, "", nil
}

// delete removes the members that match one or two paths, and now and then
// tries a pattern that matches nothing, which must change nothing.
func (s *sequence) delete() error {
	paths := s.model.paths()
	if len(paths) == 0 {
		return nil
	}
	before, err := os.ReadFile(s.archive)
	if err != nil {
		return err
	}
	if s.rnd.IntN(8) == 0 {
		s.note("delete a pattern that matches nothing")
		s.stats.ops["delete (no match)"]++
		res, err := s.r.run(true, "--delete", "-f", s.archive, "no/such/member")
		if err != nil {
			return err
		}
		if res.code != 2 {
			return fmt.Errorf("delete with no match: exit %d, want 2:\n%s", res.code, res)
		}
		return s.unchanged(before)
	}
	var patterns []string
	for n := 1 + s.rnd.IntN(2); n > 0; n-- {
		patterns = append(patterns, paths[s.rnd.IntN(len(paths))])
	}
	s.note("delete %q", patterns)
	s.stats.ops["delete"]++
	if _, err := s.r.expect(true, withPaths([]string{"--delete", "-f", s.archive}, patterns)...); err != nil {
		return err
	}
	for p := range s.model.selectPaths(patterns) {
		delete(s.model, p)
	}
	return nil
}

func (s *sequence) compact(recompress bool) error {
	args := []string{"--compact", "-f", s.archive}
	if recompress {
		spec := s.codecSpec()
		args = append(append(args, "--recompress", spec), s.tuning()...)
		s.note("compact --recompress %s", spec)
		s.stats.ops["compact --recompress"]++
	} else {
		s.note("compact")
		s.stats.ops["compact"]++
	}
	_, err := s.r.expect(true, args...)
	return err
}

// changePassphrase seals the archive's key under a new passphrase, now and
// then with new KDF parameters. The old passphrase must no longer open it;
// the checks after the step show that the new one does, and that the
// content is the same.
func (s *sequence) changePassphrase() error {
	s.passphrases++
	pass := filepath.Join(s.dir, fmt.Sprintf("passphrase-%d", s.passphrases))
	if err := os.WriteFile(pass, []byte(fmt.Sprintf("stress passphrase %d\n", s.passphrases)), 0o600); err != nil {
		return err
	}
	args := []string{"--change-passphrase", "-f", s.archive, "--new-passphrase-file", pass}
	if s.rnd.IntN(2) == 0 {
		args = append(args, "--kdf-time", strconv.Itoa(1+s.rnd.IntN(2)), "--kdf-memory", strconv.Itoa(8192<<s.rnd.IntN(2)))
	}
	s.note("change the passphrase %q", args[4:])
	s.stats.ops["change-passphrase"]++
	if _, err := s.r.expect(true, args...); err != nil {
		return err
	}
	old := s.r.crypt
	s.r.crypt = []string{"--passphrase-file", pass}
	res, err := s.r.run(false, append([]string{"-tf", s.archive}, old...)...)
	if err != nil {
		return err
	}
	if res.code != 3 {
		return fmt.Errorf("the old passphrase after a change: exit %d, want 3:\n%s", res.code, res)
	}
	return nil
}

// extractSome extracts one or two members by pattern, and checks that
// exactly the matching part of the model comes out.
func (s *sequence) extractSome() error {
	paths := s.model.paths()
	if len(paths) == 0 {
		return nil
	}
	var patterns []string
	for n := 1 + s.rnd.IntN(2); n > 0; n-- {
		patterns = append(patterns, paths[s.rnd.IntN(len(paths))])
	}
	if s.rnd.IntN(3) == 0 && allUTF8(patterns) {
		// -R with one expression for the chosen paths and everything below
		// them: the same members as the patterns with a slash rule, and a
		// test of the anchoring, since a name can be the prefix of another.
		quoted := make([]string, len(patterns))
		for i, p := range patterns {
			quoted[i] = regexp.QuoteMeta(p)
		}
		re := "(" + strings.Join(quoted, "|") + ")(/.*)?"
		want := Model{}
		for p, e := range s.model {
			for _, pat := range patterns {
				if p == pat || strings.HasPrefix(p, pat+"/") {
					want[p] = e
				}
			}
		}
		s.note("extract -R %q", re)
		s.stats.ops["extract by -R"]++
		return s.checkExtractArgs(s.archive, []string{"-R", re}, want)
	}
	s.note("extract %q", patterns)
	s.stats.ops["extract by pattern"]++
	return s.checkExtract(s.archive, patterns, s.model.selectPaths(patterns))
}

// allUTF8 reports whether every path is valid UTF-8. An expression cannot
// hold a byte that is not, so -R cannot name such a path exactly.
func allUTF8(paths []string) bool {
	for _, p := range paths {
		if !utf8.ValidString(p) {
			return false
		}
	}
	return true
}

// withPaths puts the paths or patterns after "--", so that a name that starts
// with a dash is a name and not an option, as with tar.
func withPaths(opts, paths []string) []string {
	return append(append(opts, "--"), paths...)
}

// unchanged checks that the archive holds exactly the bytes it held before.
func (s *sequence) unchanged(before []byte) error {
	after, err := os.ReadFile(s.archive)
	if err != nil {
		return err
	}
	if !sameBytes(before, after) {
		return fmt.Errorf("a refused operation changed the archive (%d bytes, was %d)", len(after), len(before))
	}
	return nil
}

func (s *sequence) report(err error) string {
	var b strings.Builder
	fmt.Fprintf(&b, "seed %d, profile %s, encrypted=%v\n\nsteps:\n", s.seed, s.profile, s.encrypted)
	for i, st := range s.steps {
		fmt.Fprintf(&b, "  %2d. %s\n", i+1, st)
	}
	fmt.Fprintf(&b, "\nfailure:\n%v\n", err)
	return b.String()
}
