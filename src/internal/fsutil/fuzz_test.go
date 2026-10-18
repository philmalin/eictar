package fsutil

import (
	"strings"
	"testing"
	"time"
)

// The pattern rules against a simple reference matcher (doc/testing.md 5,
// step 4). The reference follows the four rules of doc/design.md 10.11, with
// a glob of its own, and none of the code of Match.

// refGlob matches one name: * is any run of characters, and ? is one. It
// fills a table of which start of the pattern matches which start of the
// name, so its time is len(pattern) times len(name). A glob that tries each
// place for each * takes exponential time: the gate's FuzzMatch found
// "**************?b", which took 47 seconds.
func refGlob(pattern, name string) bool {
	// ok[j]: the pattern so far matches name[:j].
	ok := make([]bool, len(name)+1)
	ok[0] = true
	for i := range len(pattern) {
		next := make([]bool, len(name)+1)
		for j := range next {
			switch {
			case pattern[i] == '*':
				next[j] = ok[j] || j > 0 && next[j-1]
			case j > 0 && (pattern[i] == '?' || pattern[i] == name[j-1]):
				next[j] = ok[j-1]
			}
		}
		ok = next
	}
	return ok[len(name)]
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

// TestRefGlob: the reference glob gives the rules, and a pattern of many *
// takes little time (FuzzMatch/b5a1eff3bd401e36 took 47 seconds).
func TestRefGlob(t *testing.T) {
	for _, tc := range []struct {
		pattern, name string
		want          bool
	}{
		{"", "", true}, {"", "a", false}, {"*", "", true}, {"*", "ab", true},
		{"?", "", false}, {"?", "a", true}, {"?", "ab", false}, {"a*b", "ab", true},
		{"a*b", "aab", true}, {"a*b", "aba", false}, {"*a*", "bab", true},
		{"*a*", "bbb", false}, {"??*", "a", false}, {"a?", "ab", true}, {"b", "a", false},
	} {
		if got := refGlob(tc.pattern, tc.name); got != tc.want {
			t.Errorf("refGlob(%q, %q) = %v, want %v", tc.pattern, tc.name, got, tc.want)
		}
	}
	done := make(chan bool, 1)
	go func() { done <- refMatch("**************?b", "abbbbbbbbbbbbbbbbbbaaba") }()
	select {
	case got := <-done:
		if got {
			t.Error(`"**************?b" matched "abbbbbbbbbbbbbbbbbbaaba"`)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("refMatch took more than 5 seconds for a pattern of 14 stars")
	}
}
