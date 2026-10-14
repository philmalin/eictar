// Command mutate measures how strong the tests of a package are
// (doc/design.md 13.5).
//
// It makes one small change to the code at a time - a comparison, an
// operator, or a condition - and runs the tests. A change that no test finds
// is a survivor: code that the tests run, but do not check. A change in code
// that no test runs is reported as not covered, and its tests do not run.
//
// The source tree never changes: each mutant goes to the compiler through an
// overlay in GOFLAGS. Thus mutants can run in parallel, and an interrupted run
// leaves nothing behind. A go build that a test runs inherits GOFLAGS, so the
// binary that the operational tests build has the mutant too
// (testutil.Binary), and with -tags operational, those tests count. The
// coverage of the binary in the run without a mutant joins that of the
// tests: the binary writes it to GOCOVERDIR.
//
//	go run ./tools/mutate [-j N] [-run RE] [-test PKGS] [-tags T] [-files RE] PKG...
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

type config struct {
	goTool  string
	jobs    int
	run     string
	tags    string
	tests   []string
	files   *regexp.Regexp
	verbose bool
	tmp     string

	// accepted is the list of mutants that no test can find, by name.
	accepted map[string]*entry
	// mutated holds each file that this run changes, as the list names it.
	mutated map[string]bool
}

func main() {
	var cfg config
	var tests, files, acceptedList string
	flag.IntVar(&cfg.jobs, "j", max(1, runtime.NumCPU()/4), "mutants to test at the same time")
	flag.StringVar(&cfg.run, "run", "", "run only the tests that match this regular expression")
	flag.StringVar(&cfg.tags, "tags", "", "build tags for the tests, such as operational for the tests of the binary")
	flag.StringVar(&tests, "test", "", "the packages whose tests run, separated by commas; default: the package itself")
	flag.StringVar(&files, "files", "", "mutate only the files whose base name matches this regular expression")
	flag.BoolVar(&cfg.verbose, "v", false, "also list the mutants that the tests found")
	flag.StringVar(&acceptedList, "accepted", "", "the list of mutants that no test can find, each with its reason")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: mutate [flags] PKG...")
		flag.PrintDefaults()
		os.Exit(2)
	}
	if tests != "" {
		cfg.tests = strings.Split(tests, ",")
	}
	if files != "" {
		re, err := regexp.Compile(files)
		if err != nil {
			fmt.Fprintln(os.Stderr, "mutate: -files:", err)
			os.Exit(2)
		}
		cfg.files = re
	}
	cfg.accepted, cfg.mutated = map[string]*entry{}, map[string]bool{}
	if acceptedList != "" {
		f, err := os.Open(acceptedList)
		if err == nil {
			cfg.accepted, err = readAccepted(f)
			f.Close()
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "mutate: %s: %v\n", acceptedList, err)
			os.Exit(2)
		}
	}
	cfg.goTool = os.Getenv("GOTOOL")
	if cfg.goTool == "" {
		cfg.goTool = "go"
	}
	tmp, err := os.MkdirTemp("", "mutate-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "mutate:", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmp)
	cfg.tmp = tmp

	survivors := 0
	for _, pkg := range flag.Args() {
		s, err := mutatePackage(cfg, pkg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mutate: %s: %v\n", pkg, err)
			os.RemoveAll(tmp)
			os.Exit(1)
		}
		survivors += s
	}
	survivors += staleEntries(cfg, acceptedList)
	if survivors > 0 {
		os.RemoveAll(tmp)
		os.Exit(1)
	}
}

// outcome is what the tests did with one mutant.
type outcome int

const (
	killed      outcome = iota // a test failed
	timedOut                   // the tests did not end; that counts as found
	survived                   // every test passed
	notCovered                 // no test runs the code
	notCompiled                // the change does not compile, and does not count
	accepted                   // in the accepted list: no test can find it, and it does not count
)

var outcomeNames = [...]string{"killed", "timed out", "SURVIVED", "not covered", "did not compile", "accepted"}

// mutatePackage tests each mutant of one package, prints the report, and
// returns the number of survivors and mutants that no test covers.
func mutatePackage(cfg config, pkg string) (int, error) {
	info, err := listPackage(cfg, pkg)
	if err != nil {
		return 0, err
	}
	tests := cfg.tests
	if len(tests) == 0 {
		tests = []string{pkg}
	}

	// The baseline must pass, and gives the coverage and the time.
	profile := filepath.Join(cfg.tmp, "cover.out")
	args := append([]string{"test", "-count=1", "-vet=off", "-coverpkg=" + info.ImportPath, "-coverprofile=" + profile}, runArgs(cfg)...)
	start := time.Now()
	if out, err := goCmd(context.Background(), cfg, append(args, tests...)...); err != nil {
		return 0, fmt.Errorf("the tests fail without a mutant:\n%s", out)
	}
	baseline := time.Since(start)
	cov, err := readProfileFile(profile)
	if err != nil {
		return 0, err
	}

	// A binary that a test builds writes its coverage to GOCOVERDIR. With
	// -cover, go test gives each test process a directory of its own, so
	// this is a second run, without it, as make cover does. Only the tests
	// with a tag, the operational tests, build the binary.
	binCover := filepath.Join(cfg.tmp, "bincover")
	if err := os.MkdirAll(binCover, 0o755); err != nil {
		return 0, err
	}
	if cfg.tags != "" {
		args := append([]string{"test", "-count=1", "-vet=off"}, runArgs(cfg)...)
		if out, err := goCmdEnv(context.Background(), cfg, []string{"GOCOVERDIR=" + binCover}, append(args, tests...)...); err != nil {
			return 0, fmt.Errorf("the tests fail without a mutant:\n%s", out)
		}
	}
	if entries, _ := os.ReadDir(binCover); len(entries) > 0 {
		binProfile := filepath.Join(cfg.tmp, "bincover.out")
		if out, err := goCmd(context.Background(), cfg, "tool", "covdata", "textfmt",
			"-i="+binCover, "-pkg="+info.ImportPath, "-o="+binProfile); err != nil {
			return 0, fmt.Errorf("the coverage of the binary: %v\n%s", err, out)
		}
		bin, err := readProfileFile(binProfile)
		if err != nil {
			return 0, err
		}
		cov.add(bin)
	}

	type job struct {
		m    mutant
		src  []byte
		line string
	}
	cwd, err := os.Getwd()
	if err != nil {
		return 0, err
	}
	rel := map[string]string{}
	var jobs []job
	for _, name := range info.GoFiles {
		if cfg.files != nil && !cfg.files.MatchString(name) {
			continue
		}
		file := filepath.Join(info.Dir, name)
		if r, err := filepath.Rel(cwd, file); err == nil {
			rel[file] = filepath.ToSlash(r)
		} else {
			rel[file] = file
		}
		cfg.mutated[rel[file]] = true
		src, err := os.ReadFile(file)
		if err != nil {
			return 0, err
		}
		ms, err := mutants(file, src)
		if err != nil {
			return 0, err
		}
		for _, m := range ms {
			jobs = append(jobs, job{m, src, lineOf(src, m.start)})
		}
	}

	// A mutant that loops for ever stops at three times the baseline, and
	// counts as found: a user sees a hang.
	limit := max(30*time.Second, 3*baseline)
	results := make([]outcome, len(jobs))
	var wg sync.WaitGroup
	next := make(chan int)
	for w := 0; w < cfg.jobs; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := range next {
				j := jobs[i]
				if !j.m.always && !cov.has(filepath.Base(j.m.file), j.m.covLine, j.m.covCol) {
					results[i] = notCovered
					continue
				}
				results[i] = testMutant(cfg, w, j.m, j.src, tests, limit)
			}
		}(w)
	}
	for i := range jobs {
		next <- i
	}
	close(next)
	wg.Wait()
	if cfg.jobs > 1 {
		n := confirmTimeouts(results, func(i int) outcome {
			return testMutant(cfg, 0, jobs[i].m, jobs[i].src, tests, limit)
		})
		if n > 0 {
			fmt.Fprintf(os.Stderr, "mutate: %d mutants timed out with -j %d, and ran again alone\n", n, cfg.jobs)
		}
	}

	// The report: each survivor and each mutant that no test covers, in the
	// order of the source.
	order := make([]int, len(jobs))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		ma, mb := jobs[order[a]].m, jobs[order[b]].m
		if ma.file != mb.file {
			return ma.file < mb.file
		}
		return ma.start < mb.start
	})
	ordered := make([]mutant, len(order))
	for n, i := range order {
		ordered[n] = jobs[i].m
	}
	names := keys(ordered, rel)

	var counts [len(outcomeNames)]int
	fmt.Printf("=== %s\n", info.ImportPath)
	for n, i := range order {
		r := results[i]
		if e := cfg.accepted[names[n]]; e != nil {
			switch r {
			case survived, notCovered:
				r, e.used = accepted, true
			case killed, timedOut:
				e.found = true
			}
		}
		counts[r]++
		if r == survived || r == notCovered || cfg.verbose && r != notCompiled {
			j := jobs[i]
			fmt.Printf("%s:%s  [%s]\n    %s\n    name: %s\n", filepath.Base(j.m.file), j.m, outcomeNames[r], j.line, names[n])
		}
	}
	found := counts[killed] + counts[timedOut]
	scored := found + counts[survived] + counts[notCovered]
	score := 100.0
	if scored > 0 {
		score = 100 * float64(found) / float64(scored)
	}
	fmt.Printf("%s: %d mutants: %d killed, %d timed out, %d survived, %d not covered, %d accepted, %d did not compile; score %.1f%%\n",
		info.ImportPath, len(jobs), counts[killed], counts[timedOut], counts[survived], counts[notCovered], counts[accepted], counts[notCompiled], score)
	return counts[survived] + counts[notCovered], nil
}

// confirmTimeouts runs each mutant that timed out again, one at a time, and
// returns their number. With -j, the tests of each mutant share the machine
// with the others, so a slow run can pass the limit with no hang. Each such
// run counted as found, and could hide a survivor. Only a mutant that also
// times out alone counts as a hang.
func confirmTimeouts(results []outcome, run func(i int) outcome) int {
	n := 0
	for i, r := range results {
		if r == timedOut {
			results[i] = run(i)
			n++
		}
	}
	return n
}

// testMutant runs the tests with one mutant in place of its file.
func testMutant(cfg config, worker int, m mutant, src []byte, tests []string, limit time.Duration) outcome {
	dir := filepath.Join(cfg.tmp, fmt.Sprint(worker))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return notCompiled
	}
	mutated := filepath.Join(dir, filepath.Base(m.file))
	overlay := filepath.Join(dir, "overlay.json")
	ov, _ := json.Marshal(map[string]map[string]string{"Replace": {m.file: mutated}})
	if os.WriteFile(mutated, m.apply(src), 0o644) != nil || os.WriteFile(overlay, ov, 0o644) != nil {
		return notCompiled
	}
	// The test binary stops itself at the limit, with its own message. The
	// context is a second stop, for the go command itself, with time to
	// build.
	ctx, cancel := context.WithTimeout(context.Background(), 2*limit+time.Minute)
	defer cancel()
	args := append([]string{"test", "-count=1", "-vet=off", "-failfast", "-timeout=" + limit.String()}, runArgs(cfg)...)
	out, err := goCmdEnv(ctx, cfg, []string{withGoflags("-overlay=" + overlay)}, append(args, tests...)...)
	return classify(err, out, ctx.Err() != nil)
}

// classify turns the result of go test into an outcome.
func classify(err error, out []byte, timedOutCtx bool) outcome {
	switch {
	case err == nil:
		return survived
	case timedOutCtx || bytes.Contains(out, []byte("panic: test timed out")):
		return timedOut
	case bytes.Contains(out, []byte("[build failed]")) || bytes.Contains(out, []byte("[setup failed]")):
		return notCompiled
	}
	return killed
}

func runArgs(cfg config) []string {
	var args []string
	if cfg.tags != "" {
		args = append(args, "-tags="+cfg.tags)
	}
	if cfg.run != "" {
		args = append(args, "-run", cfg.run)
	}
	return args
}

// goCmd runs the go command, and returns its output.
func goCmd(ctx context.Context, cfg config, args ...string) ([]byte, error) {
	return goCmdEnv(ctx, cfg, nil, args...)
}

// goCmdEnv is goCmd with more variables in the environment.
func goCmdEnv(ctx context.Context, cfg config, env []string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, cfg.goTool, args...)
	if env != nil {
		cmd.Env = append(os.Environ(), env...)
	}
	cmd.WaitDelay = 5 * time.Second
	ownGroup(cmd)
	out, err := cmd.CombinedOutput()
	// A test can start a process that a mutant makes run for ever: the
	// eictar binary of the operational tests. When the test stops at its
	// limit, that process stays. The group goes with the command.
	killGroup(cmd)
	return out, err
}

type pkgInfo struct {
	ImportPath string
	Dir        string
	GoFiles    []string
}

// listPackage gives the files of pkg that build on this platform, without
// the tests.
func listPackage(cfg config, pkg string) (pkgInfo, error) {
	out, err := goCmd(context.Background(), cfg, "list", "-json", pkg)
	if err != nil {
		return pkgInfo{}, fmt.Errorf("go list: %v\n%s", err, out)
	}
	var info pkgInfo
	dec := json.NewDecoder(bytes.NewReader(out))
	if err := dec.Decode(&info); err != nil {
		return pkgInfo{}, err
	}
	if dec.More() {
		return pkgInfo{}, errors.New("give one package at a time, not a pattern")
	}
	return info, nil
}

// staleEntries reports each entry of the accepted list that is wrong for a
// file of this run: the tests find its mutant, or no mutant has its name
// because the code changed. It returns their number. A stale entry fails the
// run, so that the list stays true.
func staleEntries(cfg config, list string) int {
	var stale []*entry
	for _, e := range cfg.accepted {
		file, _, _ := strings.Cut(e.key, ": ")
		if e.found || !e.used && cfg.mutated[file] {
			stale = append(stale, e)
		}
	}
	sort.Slice(stale, func(a, b int) bool { return stale[a].line < stale[b].line })
	for _, e := range stale {
		why := "no mutant has this name now: the code changed"
		if e.found {
			why = "the tests find this mutant now: remove the entry"
		}
		fmt.Printf("%s:%d: %s\n    %s\n", list, e.line, why, e.key)
	}
	return len(stale)
}

// withGoflags is the GOFLAGS of the environment with flag added to it.
func withGoflags(flag string) string {
	if g := os.Getenv("GOFLAGS"); g != "" {
		return "GOFLAGS=" + g + " " + flag
	}
	return "GOFLAGS=" + flag
}
