// Command testskips reads the output of go test -json on stdin, and prints
// each test that was skipped with the reason it gave, each test that failed
// with its output, and the totals.
//
//	go test -count=1 -json ./src/... | go run ./tools/testskips
//
// A skipped test passes quietly, and a platform avoids a test by skipping it
// (doc/design.md 15.1). CI prints this for each platform, so that a green job
// also says what it did not test, and a red one says which test failed.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

type event struct {
	Action  string
	Package string
	Test    string
	Output  string
}

func main() {
	summarize(os.Stdin, os.Stdout)
}

// summarize reads the events of go test -json from r, and writes the skipped
// tests, the failed tests and the totals to w.
func summarize(r io.Reader, w io.Writer) {
	output := map[string][]string{} // package and test, to its output lines
	var skipped, failed []string
	counts := map[string]int{}
	failedTests := map[string]int{} // package to the number of its failed tests
	var failedPackages []string

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var e event
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue // not JSON
		}
		pkg := strings.TrimPrefix(e.Package, "github.com/philmalin/eictar/")
		key := pkg + "  " + e.Test
		switch {
		case e.Action == "output":
			output[key] = append(output[key], e.Output)
		case e.Test == "":
			// A package that failed with no failed test: it did not build,
			// or it crashed or timed out outside a test.
			if e.Action == "fail" {
				failedPackages = append(failedPackages, pkg)
			}
		case e.Action == "pass" || e.Action == "fail" || e.Action == "skip":
			counts[e.Action]++
			switch e.Action {
			case "skip":
				skipped = append(skipped, key)
			case "fail":
				failed = append(failed, key)
				failedTests[pkg]++
			}
		}
	}

	sort.Strings(skipped)
	for _, key := range skipped {
		fmt.Fprintf(w, "SKIP  %s\n      %s\n", key, reason(output[key]))
	}
	sort.Strings(failed)
	for _, key := range failed {
		fmt.Fprintf(w, "FAIL  %s\n", key)
		for _, l := range said(output[key]) {
			fmt.Fprintf(w, "      %s\n", l)
		}
	}
	sort.Strings(failedPackages)
	for _, pkg := range failedPackages {
		if failedTests[pkg] > 0 {
			continue // its failed tests are above
		}
		fmt.Fprintf(w, "FAIL  %s, outside a test\n", pkg)
		for _, l := range said(output[pkg+"  "]) {
			fmt.Fprintf(w, "      %s\n", l)
		}
	}
	fmt.Fprintf(w, "%d passed, %d failed, %d skipped\n", counts["pass"], counts["fail"], counts["skip"])
}

// said is the output of a test without the lines that go test adds.
func said(lines []string) []string {
	var out []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		switch {
		case l == "", l == "PASS", l == "FAIL", strings.HasPrefix(l, "FAIL\t"), strings.HasPrefix(l, "ok "),
			strings.HasPrefix(l, "=== "), strings.HasPrefix(l, "--- "):
			continue
		}
		out = append(out, l)
	}
	return out
}

// reason is what the test said when it skipped.
func reason(lines []string) string {
	out := said(lines)
	if len(out) == 0 {
		return "(no reason given)"
	}
	return strings.Join(out, " / ")
}
