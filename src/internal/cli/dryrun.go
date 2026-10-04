package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/philmalin/eictar/src/internal/archive"
)

// dryRunOps are the operations that -n applies to: those that write.
var dryRunOps = []Operation{OpCreate, OpAppend, OpUpdate, OpExtract, OpDelete}

// runDryRun is -n (doc/design.md 9.9): it prints the paths that the
// operation would write or delete, and changes nothing.
//
// The paths are the result, so -q does not hide them, as it does not hide
// the differences of --diff. Each line is one path, for a pipe. -v puts what
// would happen to the path before it.
func runDryRun(o *Options, stdout, stderr io.Writer) error {
	rep := &reporter{out: stdout, errOut: stderr, verbose: o.Verbose, quiet: o.Quiet}
	added, replaced := "add", "replace"
	show := namesFor(stdout)
	var (
		stats archive.Stats
		err   error
	)
	plan := func(p archive.Planned) {
		if o.Verbose == 0 {
			fmt.Fprintln(stdout, show(p.Path))
			return
		}
		what := added
		if p.Replaces {
			what = replaced
		}
		fmt.Fprintf(stdout, "%-8s %s\n", what, show(p.Path))
	}

	switch o.Op {
	case OpCreate, OpAppend, OpUpdate:
		if err := checkCompress(o, stderr); err != nil {
			return err
		}
		cfg, err := addConfig(o, rep)
		if err != nil {
			return err
		}
		acfg := archive.AppendConfig{CreateConfig: cfg, Open: openFor(o, rep)}
		if o.Op == OpUpdate {
			acfg.UpdateMode = o.UpdateMode
		} else if o.Op == OpAppend {
			acfg.OnConflict = o.OnConflict
		}
		if stats, err = archive.PlanAdd(acfg, o.Op != OpCreate, plan); err != nil {
			return err
		}
	case OpExtract:
		added = "extract"
		cfg, err := extractConfig(o, stdout, rep)
		if err != nil {
			return err
		}
		if stats, err = archive.PlanExtract(cfg, plan); err != nil {
			return err
		}
	case OpDelete:
		added = "delete"
		stats, err = archive.PlanDelete(archive.DeleteConfig{
			Archive:  o.Archive,
			Patterns: o.Args,
			Regex:    o.regex,
			Open:     openFor(o, rep),
			Reporter: rep,
		}, plan)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("internal: no dry run for %v", o.Op)
	}
	if !o.Quiet {
		fmt.Fprintln(stderr, "eictar: "+dryRunSummary(o.Op, stats))
	}
	if stats.Failed > 0 {
		return &partialError{failed: stats.Failed}
	}
	if stats.Collided > 0 {
		return &collisionError{collided: stats.Collided}
	}
	return nil
}

// dryRunSummary is the line that ends a dry run, on stderr so that stdout
// holds only paths.
func dryRunSummary(op Operation, s archive.Stats) string {
	verb := "written"
	if op == OpDelete {
		verb = "deleted"
	}
	parts := []string{fmt.Sprintf("dry run, nothing %s: %s, %s of file content",
		verb, plural(s.Members, "path"), humanBytes(int64(s.Bytes)))}
	if s.Replaced > 0 {
		parts = append(parts, fmt.Sprintf("%d replace a member", s.Replaced))
	}
	if s.Unchanged > 0 {
		parts = append(parts, fmt.Sprintf("%d unchanged", s.Unchanged))
	}
	if s.Skipped > 0 {
		parts = append(parts, fmt.Sprintf("%d skipped", s.Skipped))
	}
	if s.Failed > 0 {
		parts = append(parts, fmt.Sprintf("%d failed", s.Failed))
	}
	if s.Collided > 0 {
		parts = append(parts, fmt.Sprintf("%d left out (same path)", s.Collided))
	}
	return strings.Join(parts, "; ")
}
