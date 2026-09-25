package fsutil

import (
	"path"
	"strings"
)

// Match reports whether a stored member path matches a user-supplied pattern.
//
// A pattern matches when it equals the path, when it glob-matches it, or when
// it names a directory the path lies under. That last rule is what makes
// `eictar -xf a.eictar src` extract everything below src, which is what a user
// means by naming a directory.
func Match(pattern, memberPath string) bool {
	pattern = strings.TrimSuffix(path.Clean(pattern), "/")
	if pattern == "" || pattern == "." {
		return true
	}

	if pattern == memberPath {
		return true
	}
	if strings.HasPrefix(memberPath, pattern+"/") {
		return true
	}
	// path.Match treats / as a separator, so "*.go" does not match "a/b.go".
	// Match the full path first, then the base name, which is what shell
	// habits lead people to expect from a bare "*.go".
	if ok, err := path.Match(pattern, memberPath); err == nil && ok {
		return true
	}
	if !strings.Contains(pattern, "/") {
		if ok, err := path.Match(pattern, path.Base(memberPath)); err == nil && ok {
			return true
		}
	}
	return false
}

// MatchAny reports whether any pattern matches.
func MatchAny(patterns []string, memberPath string) bool {
	for _, p := range patterns {
		if Match(p, memberPath) {
			return true
		}
	}
	return false
}
