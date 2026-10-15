package fsutil

import (
	"strings"
	"testing"
)

// The pattern rules against a simple reference matcher (doc/testing.md 5,
// step 4). The reference follows the four rules of doc/design.md 10.11, with
// a glob of its own, and none of the code of Match.

// refGlob matches one name: * is any run of characters, and ? is one.
func refGlob(pattern, name string) bool {
	switch {
	case pattern == "":
		return name == ""
	case pattern[0] == '*':
		for i := 0; i <= len(name); i++ {
			if refGlob(pattern[1:], name[i:]) {
				return true
			}
		}
		return false
	case name == "":
		return false
	case pattern[0] == '?' || pattern[0] == name[0]:
		return refGlob(pattern[1:], name[1:])
	}
	return false
}

// refMatch is doc/design.md 10.11: the path itself, a directory that the
// path is under, a glob of the whole path in which * does not match a /,
// and, for a pattern with no /, a glob of one name at any depth.
func refMatch(pattern, member string) bool {
	if pattern == member || strings.HasPrefix(member, pattern+"/") {
		return true
	}
	pn, mn := strings.Split(pattern, "/"), strings.Split(member, "/")
	if len(pn) == len(mn) {
		all := true
		for i := range pn {
			all = all && refGlob(pn[i], mn[i])
		}
		if all {
			return true
		}
	}
	if !strings.Contains(pattern, "/") {
		for _, name := range mn {
			if refGlob(pattern, name) {
				return true
			}
		}
	}
	return false
}

// fromAlphabet makes a clean slash-separated path from b, with each byte
// one character of alphabet: no empty name, and no "/" at either end.
func fromAlphabet(b []byte, alphabet string) string {
	var s strings.Builder
	for _, c := range b {
		s.WriteByte(alphabet[int(c)%len(alphabet)])
	}
	var names []string
	for _, n := range strings.Split(s.String(), "/") {
		if n != "" {
			names = append(names, n)
		}
	}
	return strings.Join(names, "/")
}

// FuzzMatch compares Match with the reference, for patterns of a, b, *, ?
// and /, and paths of a, b and /.
func FuzzMatch(f *testing.F) {
	for _, s := range [][2]string{{"a", "a/b"}, {"*", "ab/ba"}, {"a/*", "a/b/a"}, {"?b", "b/ab"}, {"a/b", "a/b/b"}} {
		f.Add([]byte(s[0]), []byte(s[1]))
	}
	f.Fuzz(func(t *testing.T, p, m []byte) {
		if len(p) > 16 || len(m) > 32 {
			return
		}
		pattern, member := fromAlphabet(p, "ab*?/"), fromAlphabet(m, "ab/")
		if pattern == "" || member == "" {
			return
		}
		if got, want := Match(pattern, member), refMatch(pattern, member); got != want {
			t.Errorf("Match(%q, %q) = %v, the rules give %v", pattern, member, got, want)
		}
	})
}
