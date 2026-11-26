package docrefs

import (
	"maps"
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
		"The job (§15.1 of `doc/design.eml`) and testing.md §5, step 2.\n"
	want := []Ref{
		{"self", "9.1", 1, ""}, {"self", "9.5", 1, ""}, {"self", "10.2", 1, ""},
		{"format", "8.3", 2, "md"}, {"format", "7.1", 2, "md"}, {"format", "7.2", 2, "md"},
		{"design", "15.1", 3, "eml"}, {"testing", "5", 3, "md"},
	}
	if got := DocRefs(text, "self"); !slices.Equal(got, want) {
		t.Errorf("got %v\nwant %v", got, want)
	}
}

func TestCodeRefs(t *testing.T) {
	// The paths are built, so that the check of the project does not read
	// these references as its own.
	d := "doc/"
	text := "x := 1 // see " + d + "design.eml 9.1, 9.5, and more\n" +
		"// the stress tester (" + d + "testing.md\n// 4). The profiles\n" +
		"# " + d + "format.md §8.3 and " + d + "design.md\n" +
		"y := 2\n"
	want := []Ref{{"design", "9.1", 1, "eml"}, {"design", "9.5", 1, "eml"}, {"testing", "4", 2, "md"}, {"format", "8.3", 4, "md"}}
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

// TestEMLSections: the numbers are the numbers that emlc gives. A section
// with nc has none from emlc, and keeps the number at the start of its
// title, if any.
func TestEMLSections(t *testing.T) {
	text := "{metadata n=sections_numbered}\n" +
		"{section 1 nc bid=contents: Contents}\n" +
		"{section 1 bid=scope: Scope}\n" +
		"{section 2 bid=decisions: Decisions}\n" +
		"{section 1 nc bid=part-ii: Part II — Behavior}\n" +
		"{section 1 bid=paths: Path handling}\n" +
		"{section 2 bid=root: Where extraction writes}\n" +
		"{section 3 bid=deep: Deep}\n" +
		"{section 2 bid=self: The archive never contains itself}\n" +
		"{section 1 nc bid=appendix-a: Appendix A. Why}\n" +
		"{section 2 nc bid=default: A.3 The default}\n" +
		"{section 2 nc bid=finding: Finding 1. A link}\n" +
		"{stable col=2 bid=table: | a | b |}\n"
	nums, bids := EMLSections(text)
	for _, want := range []string{"1", "1.1", "2", "2.1", "2.1.1", "2.2", "A", "A.3"} {
		if !nums[want] {
			t.Errorf("no section %s in %v", want, nums)
		}
	}
	if len(nums) != 8 {
		t.Errorf("got %v, want 8 sections", nums)
	}
	want := map[string]string{
		"contents": "", "scope": "1", "decisions": "1.1", "part-ii": "", "paths": "2",
		"root": "2.1", "deep": "2.1.1", "self": "2.2", "appendix-a": "A", "default": "A.3",
		"finding": "", "table": "",
	}
	if !maps.Equal(bids, want) {
		t.Errorf("got %v\nwant %v", bids, want)
	}
}

// TestCheckEML: in an EML document, a link to a block that is not there, a
// link whose number is not the number of its section, a citation of a
// document by a name that is not there, and a figure that is not there are
// faults. A link to another document is checked against its blocks.
func TestCheckEML(t *testing.T) {
	root := t.TempDir()
	write(t, root, "doc/design.eml", "{metadata n=sections_numbered}\n"+
		"{section 1 bid=scope: Scope}\n"+
		"{section 2 bid=decisions: Decisions}\n"+
		"See {ref t=#decisions:§1.1}, {ref t=#scope:1. Scope} and {ref t=#decisions:the decisions}.\n"+
		"See {ref t=#scope:§1.1} and {ref t=#gone:§2}.\n"+
		"The rule of format.md §8.3, and testing.md §2.\n"+
		"{Image s=fig/A.png w=90% center: A}\n"+
		"{Image s=fig/Gone.png w=90% center: Gone}\n")
	write(t, root, "doc/fig/A.png", "")
	write(t, root, "doc/Security_Audit.eml", "{metadata n=sections_numbered}\n"+
		"{section 1 bid=scope: Scope}\n"+
		"As in the design ({ref t=design.html#decisions:§1.1}), and {ref t=#scope:§1}.\n"+
		"Not {ref t=\"design.html#decisions\":§1}, nor {ref t=design.html#gone:§3}.\n")
	write(t, root, "doc/format.md", "## 8. Rules\n### 8.3 Codecs\n")
	write(t, root, "doc/testing.md", "## 1. Unit tests\n")
	write(t, root, "doc/history.md", "As in design.md §1.1, and design.eml §1.1.\n")
	write(t, root, "src/a.go", "// see doc/"+"design.eml 1.1 and doc/"+"design.md 1.1\n")
	bad, err := Check(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		`doc/Security_Audit.eml:4: design#decisions says 1, but its section is "1.1"`,
		"doc/Security_Audit.eml:4: design#gone: no such block",
		`doc/design.eml:5: design#scope says 1.1, but its section is "1"`,
		"doc/design.eml:5: design#gone: no such block",
		"doc/design.eml:8: fig/Gone.png: no such figure",
		"doc/design.eml:6: testing §2: no such section",
		"doc/history.md:1: design.md: no such document",
		"src/a.go:1: doc/" + "design.md: no such document",
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
