package fsutil

import (
	"fmt"
	"regexp"
	"strings"
)

// Regexps are the expressions of -R and --exclude-regex (doc/design.md
// 10.11). Each one must match the whole stored path. Go's regexp is RE2: a
// match takes time linear in the path, so no expression can hang the program.
type Regexps []*Regexp

// Regexp is one expression, with its text as the user typed it, for messages.
type Regexp struct {
	Expr string
	re   *regexp.Regexp
}

// CompileRegexps compiles each expression, anchored at both ends. The s flag
// makes . match any character, a newline too, which a file name can hold.
func CompileRegexps(exprs []string) (Regexps, error) {
	out := make(Regexps, 0, len(exprs))
	for _, e := range exprs {
		// On its own first: "a)|(b" would close the wrapping group, and
		// escape the anchors, if it were only checked inside it.
		if _, err := regexp.Compile(e); err != nil {
			return nil, fmt.Errorf("regular expression %q: %w", e, err)
		}
		re, err := regexp.Compile(`(?s)^(?:` + e + `)$`)
		if err != nil {
			return nil, fmt.Errorf("regular expression %q: %w", e, err)
		}
		out = append(out, &Regexp{Expr: e, re: re})
	}
	return out, nil
}

// Match reports whether the expression matches the whole stored path.
func (r *Regexp) Match(storedPath string) bool { return r.re.MatchString(storedPath) }

// MatchAny reports whether any expression matches the path.
func (rs Regexps) MatchAny(storedPath string) bool {
	for _, r := range rs {
		if r.Match(storedPath) {
			return true
		}
	}
	return false
}

// MatchAnyOrParent reports whether any expression matches the path or a
// directory above it. It is --exclude-regex on a read: an excluded directory
// takes its contents, as the walk that made the archive did not enter it.
func (rs Regexps) MatchAnyOrParent(storedPath string) bool {
	if len(rs) == 0 {
		return false
	}
	for p := storedPath; ; {
		if rs.MatchAny(p) {
			return true
		}
		i := strings.LastIndexByte(p, '/')
		if i <= 0 {
			return false
		}
		p = p[:i]
	}
}
