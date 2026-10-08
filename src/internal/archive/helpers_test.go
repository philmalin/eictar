package archive

// The test helpers that the tests of every platform use. diff_test.go and
// plan_test.go are for Unix only, and strip_test.go is not.

import (
	"os"
	"path/filepath"
	"time"

	"github.com/philmalin/eictar/src/internal/testutil"
)

// diffStamp is the time of each entry of a settled fixture.
var diffStamp = time.Unix(1_600_000_000, 0)

// settle gives every entry of the tree the fixture's times.
func settle(tree *testutil.Tree) {
	filepath.Walk(tree.Root, func(p string, fi os.FileInfo, err error) error {
		if err != nil || p == tree.Root {
			return err
		}
		rel, _ := filepath.Rel(tree.Root, p)
		if fi.Mode()&os.ModeSymlink != 0 {
			tree.SetLinkTimes(rel, diffStamp, diffStamp)
		} else {
			tree.SetTimes(rel, diffStamp, diffStamp)
		}
		return nil
	})
}

// planned collects the paths of a dry run, as "path" or "path replaces".
type planned struct{ lines []string }

func (p *planned) add(pl Planned) {
	line := pl.Path
	if pl.Replaces {
		line += " replaces"
	}
	p.lines = append(p.lines, line)
}

// found renders the differences as "path kind" lines, for comparison.
func found(res DiffResult) []string {
	var out []string
	for _, d := range res.Differences {
		out = append(out, d.Path+" "+d.Kind)
	}
	return out
}
