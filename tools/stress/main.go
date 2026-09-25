//go:build unix

// Command stress tests eictar end to end with random data and random
// operations, and compares every result with a model of what the archive
// must hold (doc/design.md 13.4).
//
//	make stress                                 # a few minutes
//	make stress STRESS="-duration 30m"
//	make stress STRESS="-seed 1234 -sequences 1" # replay one failure
//
// Each sequence creates an archive from a generated tree, then takes random
// steps: changes to the tree, append with each --on-conflict, update with
// each --update-mode, delete, compact, recompress and extraction by pattern.
// After each step it lists, verifies and extracts the archive, and compares
// the result with the model. In the fault mode it also cuts the archive as a
// crash would, and flips bits in a copy.
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

	st := &stats{ops: map[string]int{}}
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
		seq, err := newSequence(s, seqDir, abs, *faults, st)
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
			fmt.Printf("replay: make stress STRESS=\"-seed %d -sequences 1\"\n", s)
			summary(st, start)
			os.Exit(1)
		}
		if !*keep {
			removeAll(seqDir)
		}
		fmt.Printf("\r%d sequences, %d steps, %d commands, %v", st.sequences, st.steps, st.commands,
			time.Since(start).Round(time.Second))
	}
	fmt.Println()
	summary(st, start)
}

func summary(st *stats, start time.Time) {
	fmt.Printf("\n%d sequences, %d steps, %d eictar commands in %v\n",
		st.sequences, st.steps, st.commands, time.Since(start).Round(time.Second))
	fmt.Printf("faults: %d crashes repaired, %d damaged copies (%d refused, %d damage only in dead space)\n",
		st.crashes, st.flips, st.flipsCaught, st.flips-st.flipsCaught)
	names := make([]string, 0, len(st.ops))
	for k := range st.ops {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		fmt.Printf("  %-26s %d\n", k, st.ops[k])
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "stress:", err)
	os.Exit(2)
}
