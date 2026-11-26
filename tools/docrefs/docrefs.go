// Package docrefs finds references to sections of the documents that name
// no section. The code and the documents refer to sections by number:
// "doc/design.eml 9.6" in a comment, "§9.6" or "testing.md §5" in a
// document. A section that moves or goes leaves such references wrong, and
// no other check finds them. The test of this package runs Check on the
// project.
//
// A document is Markdown (.md) or EML (.eml). In EML, a link to a section is
// {ref t=#bid:§9.6}, or {ref t=design.html#bid:§9.6} to another document.
// emlc numbers the sections, so the "§9.6" of a link is typed by hand: Check
// finds a link whose number is not the number of its section.
package docrefs

import (
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// A section number: 9, 9.6, A or A.3.
const id = `(?:[0-9]+|[A-Z])(?:\.[0-9]+)*`

var (
	// A numbered heading: "## 9. Changes and checks", "### 9.6 Concurrent writers".
	heading = regexp.MustCompile(`(?m)^#{2,4} (` + id + `)\.? `)

	// In a document: "§9.1", "§9.1, §9.5 and §10.2", with the name of a
	// document before it ("format.md §8.3", "`doc/format.md` §8.3") or after
	// it ("§15.1 of `doc/design.eml`"). With no name, the document itself.
	docRef = regexp.MustCompile(`(?:(\w+)\.(md|eml)` + "`?" + `\s)?(§` + id + `(?:(?:,\s+|\s+and\s+|\s+or\s+)§` + id + `)*)(?:\s+of\s+` + "`?" + `(?:doc/)?(\w+)\.(md|eml))?`)

	// In code: "doc/design.eml 9.6", "doc/format.md §8.3", "doc/design.eml 9.1, 9.5".
	codeRef = regexp.MustCompile(`doc/(\w+)\.(md|eml)` + "`?" + ` §?(` + id + `(?:, §?` + id + `)*)\b`)

	one = regexp.MustCompile(id)

	// The line break of a comment, so that a reference can wrap.
	wrap = regexp.MustCompile(`\n[ \t]*(?://|#|\*|\\\*)?[ \t]*`)

	// EML: "{section 2 nc bid=x: Title", "{ref t=#x:§9.6}", "{Image s=fig/a.png".
	emlSection = regexp.MustCompile(`(?m)^\{section ([1-6])([^:]*):[ \t]*([^\n]*)`)
	emlRef     = regexp.MustCompile(`\{ref t="?(\w*)(?:\.html)?#([\w-]+)"?:([^{}]*)\}`)
	emlImage   = regexp.MustCompile(`\{Image s="?([^\s"}:]+)`)
	blockBid   = regexp.MustCompile(`\{[A-Za-z]+ [^:{}]*\bbid=([\w-]+)`)

	// The number that an unnumbered EML section has in its title:
	// "Appendix A. Why", "A.3 The default".
	typedNumber = regexp.MustCompile(`^(?:Appendix ([A-Z])\b|([A-Z](?:\.[0-9]+)+)\s)`)

	// The number at the start of the text of a link: "§9.6", "9. Changes",
	// "Appendix A".
	linkNumber = regexp.MustCompile(`^(?:§(` + id + `)|Appendix ([A-Z])\b|([0-9]+(?:\.[0-9]+)*)\.?(?:\s|$))`)
)

// The files with code that refers to the documents.
var codeFiles = []string{".go", ".sh", ".yml", ".tla", ".cfg", ".txt", ".1"}

// Check returns each reference under root, in the documents of root/doc and
// in README.md, and in the code, that names a section that is not there.
// The names of the files in the result have / as the separator on each
// system.
func Check(root string) ([]string, error) {
	docs := map[string]map[string]bool{}   // the section numbers of each document
	bids := map[string]map[string]string{} // the number of each bid of an EML document
	files := map[string]bool{}             // "design.eml"
	texts := map[string]string{}           // "doc/design.eml": the text
	names, err := filepath.Glob(filepath.Join(root, "doc", "*.*"))
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		ext := filepath.Ext(name)
		if ext != ".md" && ext != ".eml" {
			continue
		}
		b, err := os.ReadFile(name)
		if err != nil {
			return nil, err
		}
		doc := strings.TrimSuffix(filepath.Base(name), ext)
		if ext == ".md" {
			docs[doc] = Sections(string(b))
		} else {
			docs[doc], bids[doc] = EMLSections(string(b))
		}
		files[filepath.Base(name)] = true
		texts["doc/"+filepath.Base(name)] = string(b)
	}
	if b, err := os.ReadFile(filepath.Join(root, "README.md")); err == nil {
		texts["README.md"] = string(b)
	}

	var bad []string
	for _, name := range slices.Sorted(maps.Keys(texts)) {
		text := texts[name]
		self := strings.TrimSuffix(filepath.Base(name), filepath.Ext(name))
		if filepath.Ext(name) == ".eml" {
			bad = append(bad, checkEML(root, name, self, text, bids)...)
			// The links are checked. The rest of the text is checked as
			// in Markdown.
			text = emlRef.ReplaceAllStringFunc(text, func(r string) string {
				return strings.Repeat("\n", strings.Count(r, "\n"))
			})
		}
		for _, r := range DocRefs(text, self) {
			switch {
			case r.Ext != "" && !files[r.Doc+"."+r.Ext]:
				bad = append(bad, fmt.Sprintf("%s:%d: %s.%s: no such document", name, r.Line, r.Doc, r.Ext))
			case !docs[r.Doc][r.Section]:
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
			if !files[r.Doc+"."+r.Ext] {
				bad = append(bad, fmt.Sprintf("%s:%d: doc/%s.%s: no such document", rel, r.Line, r.Doc, r.Ext))
			} else if !docs[r.Doc][r.Section] {
				bad = append(bad, fmt.Sprintf("%s:%d: doc/%s.%s %s: no such section", rel, r.Line, r.Doc, r.Ext, r.Section))
			}
		}
		return nil
	})
	return bad, err
}

// checkEML returns the links of an EML document to a section or a block that
// is not there, the links whose number is not the number of their section,
// and the figures that are not there.
func checkEML(root, name, self, text string, bids map[string]map[string]string) []string {
	var bad []string
	for _, m := range emlRef.FindAllStringSubmatchIndex(text, -1) {
		line := strings.Count(text[:m[0]], "\n") + 1
		doc, bid, body := text[m[2]:m[3]], text[m[4]:m[5]], text[m[6]:m[7]]
		if doc == "" {
			doc = self
		}
		num, ok := bids[doc][bid]
		if !ok {
			bad = append(bad, fmt.Sprintf("%s:%d: %s#%s: no such block", name, line, doc, bid))
			continue
		}
		if lm := linkNumber.FindStringSubmatch(strings.TrimSpace(body)); lm != nil {
			if says := lm[1] + lm[2] + lm[3]; says != num {
				bad = append(bad, fmt.Sprintf("%s:%d: %s#%s says %s, but its section is %q", name, line, doc, bid, says, num))
			}
		}
	}
	for _, m := range emlImage.FindAllStringSubmatchIndex(text, -1) {
		src := text[m[2]:m[3]]
		if _, err := os.Stat(filepath.Join(root, "doc", filepath.FromSlash(src))); err != nil {
			line := strings.Count(text[:m[0]], "\n") + 1
			bad = append(bad, fmt.Sprintf("%s:%d: %s: no such figure", name, line, src))
		}
	}
	return bad
}

// Sections returns the numbers of the headings of a Markdown document.
func Sections(text string) map[string]bool {
	s := map[string]bool{}
	for _, m := range heading.FindAllStringSubmatch(text, -1) {
		s[m[1]] = true
	}
	return s
}

// EMLSections returns the numbers of the sections of an EML document, as
// emlc numbers them, and the number of the section of each bid ("" for a
// section with no number). A section with nc has no number from emlc. Its
// number, if any, is at the start of its title: "Appendix A.", "A.3".
func EMLSections(text string) (map[string]bool, map[string]string) {
	nums, bids := map[string]bool{}, map[string]string{}
	var count [6]int
	for _, m := range emlSection.FindAllStringSubmatch(text, -1) {
		level, _ := strconv.Atoi(m[1])
		opts := strings.Fields(m[2])
		num := ""
		if !slices.Contains(opts, "nc") {
			count[level-1]++
			for k := level; k < len(count); k++ {
				count[k] = 0
			}
			parts := make([]string, level)
			for k := range parts {
				parts[k] = strconv.Itoa(count[k])
			}
			num = strings.Join(parts, ".")
		} else if t := typedNumber.FindStringSubmatch(m[3]); t != nil {
			num = t[1] + t[2]
		}
		if num != "" {
			nums[num] = true
		}
		for _, o := range opts {
			if bid, ok := strings.CutPrefix(o, "bid="); ok {
				bids[bid] = num
			}
		}
	}
	// Other blocks with a bid can be the target of a link too.
	for _, m := range blockBid.FindAllStringSubmatch(text, -1) {
		if _, ok := bids[m[1]]; !ok {
			bids[m[1]] = ""
		}
	}
	return nums, bids
}

// A Ref is one reference to a section of a document. Ext is the extension of
// the name of the document, "md" or "eml", or "" when the reference does
// not name it.
type Ref struct {
	Doc     string
	Section string
	Line    int
	Ext     string
}

// DocRefs returns the references of a document, self, to sections. A name
// before or after a list of sections names the document of each.
func DocRefs(text, self string) []Ref {
	var refs []Ref
	for _, m := range docRef.FindAllStringSubmatchIndex(text, -1) {
		doc, ext := self, ""
		if m[2] >= 0 {
			doc, ext = text[m[2]:m[3]], text[m[4]:m[5]]
		} else if m[8] >= 0 {
			doc, ext = text[m[8]:m[9]], text[m[10]:m[11]]
		}
		line := strings.Count(text[:m[0]], "\n") + 1
		for _, s := range one.FindAllString(text[m[6]:m[7]], -1) {
			refs = append(refs, Ref{doc, s, line, ext})
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
		doc, ext := string(joined[m[2]:m[3]]), string(joined[m[4]:m[5]])
		for _, s := range one.FindAll(joined[m[6]:m[7]], -1) {
			refs = append(refs, Ref{doc, string(s), lines[m[0]], ext})
		}
	}
	return refs
}
