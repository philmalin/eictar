//go:build unix

// Command stress tests eictar end to end with random data and random
// operations, and compares every result with a model of what the archive
// must hold (doc/design.md 13.4).
//
//	make stress                                 # a few minutes
//	make stress STRESS="-duration 30m"
//	make stress STRESS="-seed 1234 -sequences 1" # replay one failure
//	make stress STRESS="-profile large"          # one kind of tree only
//
// make stress-build builds the tester alone, as .build/stress, to run it
// without make. Its defaults, -eictar .build/eictar and -dir .tmp/stress,
// are relative to the project root.
//
// Each sequence creates an archive from a generated tree of one profile
// (mixed, small, large or versions; see gen.go), then takes random steps:
// changes to the tree, append with each --on-conflict, update with each
// --update-mode, both now and then with -R, --exclude-regex or --no-dedup,
// delete, compact, recompress, change of passphrase, extraction by pattern
// or by -R, --diff of an extracted tree before and after one change, the dry
// run (-n) of -r, -u, --delete and -x, and --strip-components with its dry
// run and its --diff (features.go). The codecs vary their settings,
// dictionaries and windows included.
// After each step it lists, verifies and extracts the archive, and compares
// the result with the model. In the fault mode it also cuts the archive as a
// crash would, and flips bits in a copy.
//
// The summary starts with the result, PASS or FAIL, and then gives each
// check with the number of times that it held. It ends with the slowest
// commands, which are not failures: a command fails only as a hang, after
// two minutes.
//
// The first failure stops the run. Its directory stays, with failure.txt,
// which gives the seed and the steps, and replay.sh, which repeats the
// eictar commands.
package main

import (
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func main() {
	bin := flag.String("eictar", ".build/eictar", "the eictar binary to test")
	dir := flag.String("dir", ".tmp/stress", "where the sequences work")
	duration := flag.Duration("duration", 3*time.Minute, "how long to run")
	sequences := flag.Int("sequences", 0, "stop after this many sequences (0: run for -duration)")
	steps := flag.Int("steps", 20, "steps in each sequence")
	seed := flag.Uint64("seed", 0, "the seed of the first sequence (0: from the clock)")
	faults := flag.Bool("faults", true, "also simulate crashes and damage")
	keep := flag.Bool("keep", false, "keep the directories of sequences that passed")
	profile := flag.String("profile", "", "the kind of tree for every sequence: mixed, small, large or versions (default: each seed chooses)")
	flag.Parse()

	abs, err := filepath.Abs(*bin)
	if err != nil {
		fatal(err)
	}
	if _, err := os.Stat(abs); err != nil {
		fatal(fmt.Errorf("%w (build it with make build)", err))
	}
	if *seed == 0 {
		*seed = uint64(time.Now().UnixNano())
	}
	fmt.Printf("stress: eictar %s, seed %d, faults %v\n", abs, *seed, *faults)

	if *profile != "" && profileWeights[*profile] == 0 {
		fatal(fmt.Errorf("unknown profile %q: want one of %v", *profile, profiles))
	}
	st := &stats{ops: map[string]int{}, profiles: map[string]int{}, checks: map[string]int{}}
	// On a terminal the progress line is rewritten in place. To a file or a
	// pipe, a line is written once a minute.
	tty := false
	if fi, err := os.Stdout.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		tty = true
	}
	lastLine := time.Now()
	seeds := rand.New(rand.NewPCG(*seed, 0))
	start := time.Now()
	for n := 0; ; n++ {
		if *sequences > 0 && n >= *sequences {
			break
		}
		if *sequences == 0 && time.Since(start) > *duration {
			break
		}
		s := *seed
		if n > 0 {
			s = seeds.Uint64()
		}
		seqDir, err := filepath.Abs(filepath.Join(*dir, fmt.Sprintf("seq-%d", s)))
		if err != nil {
			fatal(err)
		}
		removeAll(seqDir)
		seq, err := newSequence(s, seqDir, abs, *faults, st, *profile)
		if err != nil {
			fatal(err)
		}
		err = seq.run(*steps)
		st.sequences++
		st.commands += seq.r.calls
		if err != nil {
			report := seq.report(err)
			os.WriteFile(filepath.Join(seqDir, "failure.txt"), []byte(report), 0o644)
			seq.r.writeReplay()
			fmt.Printf("\nFAIL in sequence %d\n%s\nkept in %s (failure.txt, replay.sh)\n", st.sequences, report, seqDir)
			fmt.Printf("replay: make stress STRESS=\"-seed %d -sequences 1 -profile %s\"\n", s, seq.profile)
			summary(st, start, err)
			os.Exit(1)
		}
		if !*keep {
			removeAll(seqDir)
		}
		progress := fmt.Sprintf("%d sequences, %d steps, %d commands, %v", st.sequences, st.steps, st.commands,
			time.Since(start).Round(time.Second))
		switch {
		case tty:
			fmt.Printf("\r%s", progress)
		case time.Since(lastLine) >= time.Minute:
			fmt.Println(progress)
			lastLine = time.Now()
		}
	}
	if tty {
		fmt.Println()
	}
	summary(st, start, nil)
}

// checkNames are the checks that the summary reports, in order, by their
// key in stats.checks. Each is a rule that held each time it was counted.
var checkNames = []struct{ key, rule string }{
	{"state", "after each step: -t lists the model, --verify passes, and a full extraction gives back the model"},
	{"hardlinks", "after each step with hardlinks in the model: the extraction gives each link group as one file, and other names as other files"},
	{"partial", "extraction by pattern or -R gives exactly the matching members"},
	{"refused", "an operation that must be refused exits with 2, and leaves the archive byte for byte as it was"},
	{"passphrase", "after a change of passphrase, the old passphrase is refused with exit 3"},
	{"crash", "crash: the cut archive is refused with exit 3, and --repair gives back the archive of before, byte for byte"},
	{"damage-refused", "damage: --verify and extraction both refuse the damaged copy with exit 3"},
	{"damage-dead", "damage: --verify and extraction both accept the damaged copy, and extraction gives back the model (the bits were in dead space)"},
	{"diff-clean", "--diff of a tree just extracted finds no difference"},
	{"diff-change", "--diff after one change to that tree reports that path and that kind of change, and nothing else"},
	{"dry-run", "-n lists exactly the paths of the real run (-r, -u, --delete, -x), changes nothing, and makes no destination"},
	{"strip", "--strip-components gives the stripped model; each collision has its warning, and the run exits with 1"},
	{"strip-diff", "--diff --strip-components of that tree finds no difference"},
}

// summary reports the run: the result first, then each check with the
// number of times that it held, the operations, the coverage, and the
// slowest commands. failed is
// the error that stopped the run, or nil.
func summary(st *stats, start time.Time, failed error) {
	took := time.Since(start).Round(time.Second)
	if failed == nil {
		fmt.Printf("\nRESULT: PASS. %d sequences, %d steps and %d eictar commands in %v. Every check held.\n",
			st.sequences, st.steps, st.commands, took)
	} else {
		fmt.Printf("\nRESULT: FAIL in sequence %d, after %d steps and %d eictar commands in %v (see above).\n",
			st.sequences, st.steps, st.commands, took)
		fmt.Println("The counts below are the checks that held before the failure.")
	}
	fmt.Println("\nChecks (the number of times that each one held):")
	for _, c := range checkNames {
		n := st.checks[c.key]
		note := ""
		if n == 0 {
			note = "  [not reached in this run]"
		}
		fmt.Printf("  %6d  %s%s\n", n, c.rule, note)
	}

	fmt.Println("\nOperations:")
	names := make([]string, 0, len(st.ops))
	for k := range st.ops {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		fmt.Printf("  %6d  %s\n", st.ops[k], k)
	}

	var kinds []string
	for _, p := range profiles {
		if st.profiles[p] > 0 {
			kinds = append(kinds, fmt.Sprintf("%s %d", p, st.profiles[p]))
		}
	}
	fmt.Printf("\nCoverage: trees %s; %d archives ended with a dictionary, %d with shared content.\n",
		strings.Join(kinds, ", "), st.withDict, st.withShared)

	st.slow.report()
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "stress:", err)
	os.Exit(2)
}
