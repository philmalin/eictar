package main

import (
	"bufio"
	"fmt"
	"io"
	"path"
	"strings"
)

// block is one block of a coverage profile that the tests ran.
type block struct {
	startLine, startCol, endLine, endCol int
}

// covered holds the blocks that ran, by the base name of their file.
type covered map[string][]block

// readProfile reads a coverage profile in the text form of go test
// -coverprofile, and keeps the blocks that ran at least once.
func readProfile(r io.Reader) (covered, error) {
	c := covered{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "mode:") || line == "" {
			continue
		}
		// name.go:12.5,14.3 2 1
		name, rest, ok := strings.Cut(line, ":")
		fields := strings.Fields(rest)
		if !ok || len(fields) != 3 {
			return nil, fmt.Errorf("coverage profile: bad line %q", line)
		}
		if fields[2] == "0" {
			continue
		}
		var b block
		if _, err := fmt.Sscanf(fields[0], "%d.%d,%d.%d", &b.startLine, &b.startCol, &b.endLine, &b.endCol); err != nil {
			return nil, fmt.Errorf("coverage profile: bad line %q: %v", line, err)
		}
		base := path.Base(name)
		c[base] = append(c[base], b)
	}
	return c, sc.Err()
}

// has reports whether the tests ran the code at line and col of the file
// with the base name base.
func (c covered) has(base string, line, col int) bool {
	for _, b := range c[base] {
		after := line > b.startLine || line == b.startLine && col >= b.startCol
		before := line < b.endLine || line == b.endLine && col < b.endCol
		if after && before {
			return true
		}
	}
	return false
}
