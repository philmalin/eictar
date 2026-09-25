package fsutil

import (
	"strings"
	"testing"
)

func TestRegexMatchesTheWholePath(t *testing.T) {
	rs, err := CompileRegexps([]string{`.*/dir/[a-f][0-9]+\.txt`, `a|b`})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"x/dir/a1.txt", true},
		{"x/y/dir/f42.txt", true},
		{"dir/a1.txt", false},       // .*/ needs a directory above
		{"x/dir/a1.txt.bak", false}, // the end is anchored
		{"x/olddir/a1.txt", false},  // so is the name after the slash
		{"x/dir/g1.txt", false},     // [a-f]
		{"x/dir/a1xtxt", false},     // \. is a dot, not any character
		{"a", true}, {"b", true},    // an alternation is anchored as a whole
		{"ab", false}, {"xa", false},
		{"x/dir/a1.txt\n", false}, // $ is the end of the path, not of a line
	} {
		if got := rs.MatchAny(tc.path); got != tc.want {
			t.Errorf("MatchAny(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// TestRegexDotIsAnyCharacter: . matches a newline, and a byte that is not
// UTF-8, both of which a file name can hold.
func TestRegexDotIsAnyCharacter(t *testing.T) {
	rs, err := CompileRegexps([]string{`a/.*`, `b/.`})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"a/x\ny", "b/\n", "b/\xff", "a/\xfe\xff"} {
		if !rs.MatchAny(p) {
			t.Errorf("%q did not match", p)
		}
	}
}

func TestRegexCompileErrorNamesTheExpression(t *testing.T) {
	_, err := CompileRegexps([]string{"ok", "bad[("})
	if err == nil || !strings.Contains(err.Error(), `"bad[("`) {
		t.Errorf("error = %v, want it to name the expression", err)
	}
	// Balanced only inside the wrapper, which it would break out of.
	if _, err := CompileRegexps([]string{`a)|(b`}); err == nil {
		t.Error("an unbalanced expression compiled")
	}
	// A backreference is not RE2, and would make matching slow.
	if _, err := CompileRegexps([]string{`(a)\1`}); err == nil {
		t.Error("a backreference compiled")
	}
}

func TestRegexMatchAnyOrParent(t *testing.T) {
	rs, err := CompileRegexps([]string{`.*/cache`})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"a/cache", true},
		{"a/cache/x/y", true},
		{"a/cachefile", false},
		{"cache/x", false}, // .*/ needs a directory above
		{"b/c", false},
	} {
		if got := rs.MatchAnyOrParent(tc.path); got != tc.want {
			t.Errorf("MatchAnyOrParent(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
	if (Regexps{}).MatchAnyOrParent("a") {
		t.Error("no expressions matched")
	}
}
