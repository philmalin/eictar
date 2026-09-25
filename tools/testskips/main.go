// Command testskips reads the output of go test -json on stdin, and prints
// each test that was skipped with the reason it gave, and the totals.
//
//	go test -count=1 -json ./src/... | go run ./tools/testskips
//
// A skipped test passes quietly, and a platform avoids a test by skipping it
// (doc/design.md 15.1). CI prints this for each platform, so that a green job
// also says what it did not test.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
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
	output := map[string][]string{} // package and test, to its output lines
	var skipped []string
	counts := map[string]int{}

	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var e event
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.Test == "" {
			continue // a package line, or not JSON (a build error)
		}
		key := strings.TrimPrefix(e.Package, "github.com/philmalin/eictar/") + "  " + e.Test
		switch e.Action {
		case "output":
			output[key] = append(output[key], e.Output)
		case "pass", "fail", "skip":
			counts[e.Action]++
			if e.Action == "skip" {
				skipped = append(skipped, key)
			}
		}
	}

	sort.Strings(skipped)
	for _, key := range skipped {
		fmt.Printf("SKIP  %s\n      %s\n", key, reason(output[key]))
	}
	fmt.Printf("%d passed, %d failed, %d skipped\n", counts["pass"], counts["fail"], counts["skip"])
}

// reason is what the test said when it skipped: its output without the
// lines that go test adds.
func reason(lines []string) string {
	var out []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "=== ") || strings.HasPrefix(l, "--- ") {
			continue
		}
		out = append(out, l)
	}
	if len(out) == 0 {
		return "(no reason given)"
	}
	return strings.Join(out, " / ")
}
