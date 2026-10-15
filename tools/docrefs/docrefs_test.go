package docrefs

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestProject: each reference of the project to a section of a document
// names a section that is there.
func TestProject(t *testing.T) {
	bad, err := Check(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range bad {
		t.Error(b)
	}
}

func TestSections(t *testing.T) {
	s := Sections("# Title\n## Contents\n## 1. Scope\n### 1.1 Decisions\n## Appendix A. Why\n### A.3 The default\n#### 9.6.1 Deep\n")
	for _, want := range []string{"1", "1.1", "A.3", "9.6.1"} {
		if !s[want] {
			t.Errorf("no section %s in %v", want, s)
		}
	}
	if len(s) != 4 {
		t.Errorf("got %v, want 4 sections", s)
	}
}

func TestDocRefs(t *testing.T) {
	text := "See §9.1, §9.5 and §10.2.\n" +
		"The rule of format.md §8.3, and `doc/format.md` §7.1, §7.2.\n" +
		"The job (§15.1 of `doc/design.md`) and testing.md §5, step 2.\n"
	want := []Ref{
		{"self", "9.1", 1}, {"self", "9.5", 1}, {"self", "10.2", 1},
		{"format", "8.3", 2}, {"format", "7.1", 2}, {"format", "7.2", 2},
		{"design", "15.1", 3}, {"testing", "5", 3},
	}
	if got := DocRefs(text, "self"); !slices.Equal(got, want) {
		t.Errorf("got %v\nwant %v", got, want)
	}
}

func TestCodeRefs(t *testing.T) {
	// The paths are built, so that the check of the project does not read
	// these references as its own.
	d := "doc/"
	text := "x := 1 // see " + d + "design.md 9.1, 9.5, and more\n" +
		"// the stress tester (" + d + "testing.md\n// 4). The profiles\n" +
		"# " + d + "format.md §8.3 and " + d + "design.md\n" +
		"y := 2\n"
	want := []Ref{{"design", "9.1", 1}, {"design", "9.5", 1}, {"testing", "4", 2}, {"format", "8.3", 4}}
	if got := CodeRefs(text); !slices.Equal(got, want) {
		t.Errorf("got %v\nwant %v", got, want)
	}
}

// TestCheckFindsAMovedSection: a reference to a section that is not there
// is a fault, in a document and in code.
func TestCheckFindsAMovedSection(t *testing.T) {
	root := t.TempDir()
	write(t, root, "doc/design.md", "## 9. Changes\n### 9.1 Write\nSee §9.1 and §13.5, and testing.md §2.\n")
	write(t, root, "doc/testing.md", "## 1. Unit tests\n")
	write(t, root, "src/a.go", "// see doc/"+"design.md 9.1 and doc/"+"design.md 13.5\n// doc/"+"gone.md 1\n")
	bad, err := Check(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"doc/design.md:3: design §13.5: no such section",
		"doc/design.md:3: testing §2: no such section",
		"src/a.go:1: doc/" + "design.md 13.5: no such section",
		"src/a.go:2: doc/gone.md: no such document",
	}
	if !slices.Equal(bad, want) {
		t.Errorf("got %q\nwant %q", bad, want)
	}
}

func write(t *testing.T, root, name, text string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}
