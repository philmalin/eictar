package archive

import (
	"sort"
	"strings"

	"github.com/philmalin/eictar/src/internal/format"
	"github.com/philmalin/eictar/src/internal/fsutil"
)

// stripPath removes the first n components of the stored path p, as
// --strip-components does (doc/design.md 10.14). It reports false when p
// has n components or fewer: nothing of it is left to write.
func stripPath(p string, n int) (string, bool) {
	for range n {
		i := strings.IndexByte(p, '/')
		if i < 0 {
			return "", false
		}
		p = p[i+1:]
	}
	return p, p != ""
}

// stripMembers gives the members of a selection their paths after
// --strip-components, in path order. members is the caller's own copy, as
// selectMembers takes, and comes in path order: the order of the stored
// paths decides which member of a collision is kept.
//
// A member with n components or fewer is left out. A member whose path is
// not in the stored form keeps it, and the check before the write refuses
// it. When two members get one path, the later one is kept and the earlier
// one is left out with a warning; it counts as collided. Two directories
// with one path are not a collision: the contents of both go into the one
// directory, which takes the metadata of the later one. what says what
// happens to a member that is left out, for the warning: "not extracted" or
// "not compared".
func stripMembers(members []format.Member, n int, rep Reporter, what string) ([]format.Member, int) {
	type stripped struct {
		m    format.Member
		from string
	}
	kept := make([]stripped, 0, len(members))
	for _, m := range members {
		from := m.Path
		// A path that is not in the stored form keeps it, so that the
		// check before each write refuses the member (checkPath). Stripped,
		// "../../etc/x" would become a path that passes.
		if fsutil.IsStoredPath(m.Path) {
			p, ok := stripPath(m.Path, n)
			if !ok {
				continue
			}
			m.Path = p
		}
		kept = append(kept, stripped{m, from})
	}
	sort.SliceStable(kept, func(i, j int) bool { return kept[i].m.Path < kept[j].m.Path })

	out := members[:0] // in place, as selectMembers
	collided := 0
	for i, s := range kept {
		if i+1 < len(kept) && kept[i+1].m.Path == s.m.Path {
			next := kept[i+1]
			if s.m.Type != format.TypeDir || next.m.Type != format.TypeDir {
				collided++
				if rep != nil {
					rep.Warn("%s: %s: %s has the same path after --strip-components", s.from, what, next.from)
				}
			}
			continue
		}
		out = append(out, s.m)
	}
	return out, collided
}
