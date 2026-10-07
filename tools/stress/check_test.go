//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCompareTreeHardlinks gives compareTree the trees that a fault of
// extraction makes: a link group as two files, and two groups as one file.
// Before the link groups, the model saw names, content and modes only, and
// passed both.
func TestCompareTreeHardlinks(t *testing.T) {
	// files makes a, b and c with the same content and times. linkB makes b
	// a second name of a, and linkC makes c one.
	files := func(t *testing.T, linkB, linkC bool) (string, Model) {
		root := t.TempDir()
		a := filepath.Join(root, "a")
		if err := os.WriteFile(a, []byte("content"), 0o644); err != nil {
			t.Fatal(err)
		}
		for name, link := range map[string]bool{"b": linkB, "c": linkC} {
			p := filepath.Join(root, name)
			var err error
			if link {
				err = os.Link(a, p)
			} else {
				err = os.WriteFile(p, []byte("content"), 0o644)
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		m := Model{}
		for _, name := range []string{"a", "b", "c"} {
			e, err := readEntry(filepath.Join(root, name))
			if err != nil {
				t.Fatal(err)
			}
			m[name] = e
		}
		for _, name := range []string{"a", "b", "c"} {
			if err := setTimeAbs(filepath.Join(root, name), m["a"].MTime); err != nil {
				t.Fatal(err)
			}
			e := m[name]
			e.MTime = m["a"].MTime
			m[name] = e
		}
		return root, m
	}
	// group sets the link group of each path of the model.
	group := func(m Model, links map[string]int) Model {
		for p, g := range links {
			e := m[p]
			e.Link = g
			m[p] = e
		}
		return m
	}

	tests := []struct {
		name         string
		linkB, linkC bool
		links        map[string]int
		want         string // a part of the error, or "" for none
	}{
		{"a group, linked", true, false, map[string]int{"a": 1, "b": 1, "c": 2}, ""},
		{"a group as two files", false, false, map[string]int{"a": 1, "b": 1, "c": 2}, "want a hardlink"},
		{"two groups as one file", true, true, map[string]int{"a": 1, "b": 1, "c": 2}, "want two files"},
		{"no groups, linked", false, true, map[string]int{"a": 1, "b": 2, "c": 3}, "want two files"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root, m := files(t, tt.linkB, tt.linkC)
			err := compareTree(root, group(m, tt.links))
			switch {
			case tt.want == "" && err != nil:
				t.Errorf("compareTree: %v, want no error", err)
			case tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)):
				t.Errorf("compareTree: %v, want an error with %q", err, tt.want)
			}
		})
	}
}
