//go:build unix

package main

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// slowestKept is how many of the slowest commands the summary gives.
const slowestKept = 5

// slowCommand is one eictar command that took a long time. It is not a
// failure: the summary lists the slowest, so that a slow case is seen before
// it becomes a hang (doc/design.md 13.4).
type slowCommand struct {
	took    time.Duration
	seed    uint64
	call    int    // the number of the command in its sequence, from 1
	profile string // the kind of tree
	srcSize int64  // the size of the source tree, with sparse files at their full size
	line    string // the command, with the paths of the sequence made short
}

// slowest keeps the slowest commands of the run, the slowest first.
type slowest struct{ list []slowCommand }

// admits reports whether a command that took d goes into the list.
func (s *slowest) admits(d time.Duration) bool {
	return len(s.list) < slowestKept || d > s.list[len(s.list)-1].took
}

func (s *slowest) add(c slowCommand) {
	s.list = append(s.list, c)
	sort.SliceStable(s.list, func(i, j int) bool { return s.list[i].took > s.list[j].took })
	if len(s.list) > slowestKept {
		s.list = s.list[:slowestKept]
	}
}

// record adds the command that r has just run, when it is one of the
// slowest. The size of the tree is found only then, as it needs a walk.
func (r *runner) record(args []string, took time.Duration) {
	if r.slow == nil || !r.slow.admits(took) {
		return
	}
	r.slow.add(slowCommand{
		took: took, seed: r.seed, call: r.calls, profile: r.profile,
		srcSize: treeSize(filepath.Join(r.dir, "src")),
		line:    shortLine(r.dir, args),
	})
}

// shortLine gives the options of a command without --no-config and the
// passphrase options, with the sequence's directory left out of each path,
// and the paths after "--" as a count.
func shortLine(dir string, args []string) string {
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--no-config":
			continue
		case a == "--passphrase-file":
			i++
			continue
		case a == "--":
			if n := len(args) - i - 1; n > 0 {
				out = append(out, fmt.Sprintf("-- (%d paths)", n))
			}
			i = len(args)
			continue
		}
		out = append(out, shellQuote(strings.TrimPrefix(a, dir+"/")))
	}
	return strings.Join(out, " ")
}

// treeSize is the total size of the regular files under root. A file that
// is gone counts as nothing: the size is a guide, not a check.
func treeSize(root string) int64 {
	var total int64
	filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if fi, err := d.Info(); err == nil {
				total += fi.Size()
			}
		}
		return nil
	})
	return total
}

// report prints the slowest commands, for the summary.
func (s *slowest) report() {
	if len(s.list) == 0 {
		return
	}
	fmt.Println("\nSlowest commands (not a failure; a slow case to look at, before it becomes a hang):")
	for _, c := range s.list {
		fmt.Printf("  %7.1fs  %s\n", c.took.Seconds(), c.line)
		fmt.Printf("            tree %s, %.1f MiB; command %d of make stress STRESS=\"-seed %d -sequences 1 -profile %s\"\n",
			c.profile, float64(c.srcSize)/(1<<20), c.call, c.seed, c.profile)
	}
}
