package main

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// entry is one mutant of the accepted list: a change that no test can find,
// because it cannot change what the program does. Each entry gives its
// reason (doc/testing.md 5).
type entry struct {
	key    string
	reason string
	line   int  // in the list, for the report
	used   bool // a survivor or a mutant that is not covered matched it
	found  bool // the tests found the mutant: the entry is wrong
}

// readAccepted reads the accepted list. Each entry is a line that names the
// mutant, as the report prints it, and one or more indented lines that give
// the reason:
//
//	src/internal/crypt/aead.go: SealIndex: if false: err != nil → false
//		crypto/rand.Read does not return an error: it stops the program.
//
// A blank line and a line that starts with # are ignored.
func readAccepted(r io.Reader) (map[string]*entry, error) {
	list := map[string]*entry{}
	var cur *entry
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		text := strings.TrimSpace(line)
		switch {
		case text == "" || strings.HasPrefix(text, "#"):
			continue
		case line[0] == ' ' || line[0] == '\t':
			if cur == nil {
				return nil, fmt.Errorf("line %d: a reason with no mutant before it", n)
			}
			cur.reason = strings.TrimSpace(cur.reason + " " + text)
			continue
		}
		if cur != nil && cur.reason == "" {
			return nil, fmt.Errorf("line %d: %s has no reason", cur.line, cur.key)
		}
		if strings.Count(text, ": ") < 2 {
			return nil, fmt.Errorf("line %d: %q is not FILE: FUNCTION: MUTATION", n, text)
		}
		if _, dup := list[text]; dup {
			return nil, fmt.Errorf("line %d: %s is in the list two times", n, text)
		}
		cur = &entry{key: text, line: n}
		list[text] = cur
	}
	if cur != nil && cur.reason == "" {
		return nil, fmt.Errorf("line %d: %s has no reason", cur.line, cur.key)
	}
	return list, sc.Err()
}

// keys gives the name of each mutant in the accepted list: FILE: FUNCTION:
// MUTATION, and #2, #3 and more after the first of two that are the same in
// one function. ms must be in the order of the source, and files gives the
// path of each file as the list writes it.
func keys(ms []mutant, files map[string]string) []string {
	seen := map[string]int{}
	out := make([]string, len(ms))
	for i, m := range ms {
		k := files[m.file] + ": " + m.fn + ": " + m.mutation()
		seen[k]++
		if n := seen[k]; n > 1 {
			k += fmt.Sprintf(" #%d", n)
		}
		out[i] = k
	}
	return out
}
