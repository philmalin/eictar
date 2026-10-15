// Package docrefs finds references to sections of the documents that name
// no section. The code and the documents refer to sections by number:
// "doc/design.md 9.6" in a comment, "§9.6" or "testing.md §5" in a
// document. A section that moves or goes leaves such references wrong, and
// no other check finds them. The test of this package runs Check on the
// project.
package docrefs

import (
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// A section number: 9, 9.6, A or A.3.
const id = `(?:[0-9]+|[A-Z])(?:\.[0-9]+)*`

var (
	// A numbered heading: "## 9. Changes and checks", "### 9.6 Concurrent writers".
	heading = regexp.MustCompile(`(?m)^#{2,4} (` + id + `)\.? `)

	// In a document: "§9.1", "§9.1, §9.5 and §10.2", with the name of a
	// document before it ("format.md §8.3", "`doc/format.md` §8.3") or after
	// it ("§15.1 of `doc/design.md`"). With no name, the document itself.
	docRef = regexp.MustCompile(`(?:(\w+)\.md` + "`?" + `\s)?(§` + id + `(?:(?:,\s+|\s+and\s+|\s+or\s+)§` + id + `)*)(?:\s+of\s+` + "`?" + `(?:doc/)?(\w+)\.md)?`)

	// In code: "doc/design.md 9.6", "doc/format.md §8.3", "doc/design.md 9.1, 9.5".
	codeRef = regexp.MustCompile(`doc/(\w+)\.md` + "`?" + ` §?(` + id + `(?:, §?` + id + `)*)\b`)

	one = regexp.MustCompile(id)

	// The line break of a comment, so that a reference can wrap.
	wrap = regexp.MustCompile(`\n[ \t]*(?://|#|\*|\\\*)?[ \t]*`)
)

// The documents whose references with no name of a document are to another
// one. The security review says "design §7.7" and "§4.3 of the design".
var bareRefs = map[string]string{"Security_Audit": "design"}

// The files with code that refers to the documents.
var codeFiles = []string{".go", ".sh", ".yml", ".tla", ".cfg", ".txt", ".1"}

// Check returns each reference under root, in the documents of root/doc and
// in README.md, and in the code, that names a section that is not there.
// The names of the files in the result have / as the separator on each
// system.
func Check(root string) ([]string, error) {
	docs := map[string]map[string]bool{}
	names, err := filepath.Glob(filepath.Join(root, "doc", "*.md"))
	if err != nil {
		return nil, err
	}
	texts := map[string]string{}
	for _, name := range names {
		b, err := os.ReadFile(name)
		if err != nil {
			return nil, err
		}
		doc := strings.TrimSuffix(filepath.Base(name), ".md")
		docs[doc] = Sections(string(b))
		texts["doc/"+filepath.Base(name)] = string(b)
	}
	if b, err := os.ReadFile(filepath.Join(root, "README.md")); err == nil {
		texts["README.md"] = string(b)
	}

	var bad []string
	for _, name := range slices.Sorted(maps.Keys(texts)) {
		self := strings.TrimSuffix(filepath.Base(name), ".md")
		if d, ok := bareRefs[self]; ok {
			self = d
		}
		for _, r := range DocRefs(texts[name], self) {
			if !docs[r.Doc][r.Section] {
				bad = append(bad, fmt.Sprintf("%s:%d: %s §%s: no such section", name, r.Line, r.Doc, r.Section))
			}
		}
	}

	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel != "." && (strings.HasPrefix(d.Name(), ".") && d.Name() != ".github" || d.Name() == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != "Makefile" && !slices.Contains(codeFiles, filepath.Ext(path)) {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, r := range CodeRefs(string(b)) {
			if _, ok := docs[r.Doc]; !ok {
				bad = append(bad, fmt.Sprintf("%s:%d: doc/%s.md: no such document", rel, r.Line, r.Doc))
			} else if !docs[r.Doc][r.Section] {
				bad = append(bad, fmt.Sprintf("%s:%d: doc/%s.md %s: no such section", rel, r.Line, r.Doc, r.Section))
			}
		}
		return nil
	})
	return bad, err
}

// Sections returns the numbers of the headings of a document.
func Sections(text string) map[string]bool {
	s := map[string]bool{}
	for _, m := range heading.FindAllStringSubmatch(text, -1) {
		s[m[1]] = true
	}
	return s
}

// A Ref is one reference to a section of a document.
type Ref struct {
	Doc     string
	Section string
	Line    int
}

// DocRefs returns the references of a document, self, to sections. A name
// before or after a list of sections names the document of each.
func DocRefs(text, self string) []Ref {
	var refs []Ref
	for _, m := range docRef.FindAllStringSubmatchIndex(text, -1) {
		doc := self
		if m[2] >= 0 {
			doc = text[m[2]:m[3]]
		} else if m[6] >= 0 {
			doc = text[m[6]:m[7]]
		}
		line := strings.Count(text[:m[0]], "\n") + 1
		for _, s := range one.FindAllString(text[m[4]:m[5]], -1) {
			refs = append(refs, Ref{doc, s, line})
		}
	}
	return refs
}

// CodeRefs returns the references of code to sections of the documents.
// A reference can wrap to the next line of a comment.
func CodeRefs(text string) []Ref {
	// The line of each byte of the joined text: a wrap joins two lines.
	var lines []int
	joined := []byte{}
	line, last := 1, 0
	for _, w := range wrap.FindAllStringIndex(text, -1) {
		for _, c := range []byte(text[last:w[0]]) {
			joined = append(joined, c)
			lines = append(lines, line)
		}
		joined = append(joined, ' ')
		lines = append(lines, line)
		line++
		last = w[1]
	}
	for _, c := range []byte(text[last:]) {
		joined = append(joined, c)
		lines = append(lines, line)
		if c == '\n' {
			line++
		}
	}

	var refs []Ref
	for _, m := range codeRef.FindAllSubmatchIndex(joined, -1) {
		doc := string(joined[m[2]:m[3]])
		for _, s := range one.FindAll(joined[m[4]:m[5]], -1) {
			refs = append(refs, Ref{doc, string(s), lines[m[0]]})
		}
	}
	return refs
}
