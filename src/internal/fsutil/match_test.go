package fsutil

import "testing"

func TestMatch(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		path    string
		want    bool
	}{
		// Exact.
		{"a.txt", "a.txt", true},
		{"dir/a.txt", "dir/a.txt", true},
		{"a.txt", "b.txt", false},

		// Naming a directory takes everything under it, which is what a user
		// means by "extract src".
		{"src", "src/main.go", true},
		{"src", "src/deep/nested/file.go", true},
		{"src", "src", true},
		{"src", "srcfile.go", false}, // prefix, but not a directory boundary
		{"src", "other/src/file.go", false},

		// Globs against the whole path.
		{"src/*.go", "src/main.go", true},
		{"src/*.go", "src/sub/main.go", false}, // * does not cross separators
		{"src/*", "src/main.go", true},

		// A pattern with no separator also matches the base name, which is
		// what shell habits lead people to expect from "*.go".
		{"*.go", "src/main.go", true},
		{"*.go", "main.go", true},
		{"*.txt", "src/main.go", false},

		// Trailing slashes and cleaning.
		{"src/", "src/main.go", true},
		{"./src", "src/main.go", true},

		// An empty or dot pattern means everything.
		{".", "anything/at/all", true},
		{"", "anything", true},

		// Malformed globs must not match everything by accident.
		{"[", "a.txt", false},
	} {
		t.Run(tc.pattern+" vs "+tc.path, func(t *testing.T) {
			if got := Match(tc.pattern, tc.path); got != tc.want {
				t.Errorf("Match(%q, %q) = %v, want %v", tc.pattern, tc.path, got, tc.want)
			}
		})
	}
}

func TestMatchAny(t *testing.T) {
	patterns := []string{"src", "*.md"}

	for _, tc := range []struct {
		path string
		want bool
	}{
		{"src/main.go", true},
		{"README.md", true},
		{"doc/design.md", true},
		{"Makefile", false},
	} {
		if got := MatchAny(patterns, tc.path); got != tc.want {
			t.Errorf("MatchAny(%v, %q) = %v, want %v", patterns, tc.path, got, tc.want)
		}
	}

	if MatchAny(nil, "anything") {
		t.Error("no patterns should match nothing, not everything")
	}
}
