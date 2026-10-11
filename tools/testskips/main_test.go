package main

import (
	"strings"
	"testing"
)

// TestSummarize: a skipped test gives its reason, a failed test gives its
// output, and a package that failed outside a test gives the output of the
// package. The totals count the tests.
func TestSummarize(t *testing.T) {
	const pkg = `"Package":"github.com/philmalin/eictar/src/internal/archive"`
	events := strings.Join([]string{
		`{"Action":"run",` + pkg + `,"Test":"TestA"}`,
		`{"Action":"output",` + pkg + `,"Test":"TestA","Output":"=== RUN   TestA\n"}`,
		`{"Action":"pass",` + pkg + `,"Test":"TestA"}`,
		`{"Action":"output",` + pkg + `,"Test":"TestSkip","Output":"    a_test.go:9: no named pipe here\n"}`,
		`{"Action":"output",` + pkg + `,"Test":"TestSkip","Output":"--- SKIP: TestSkip (0.00s)\n"}`,
		`{"Action":"skip",` + pkg + `,"Test":"TestSkip"}`,
		`{"Action":"output",` + pkg + `,"Test":"TestBad","Output":"    a_test.go:12: Create = <nil>\n"}`,
		`{"Action":"output",` + pkg + `,"Test":"TestBad","Output":"--- FAIL: TestBad (1.36s)\n"}`,
		`{"Action":"fail",` + pkg + `,"Test":"TestBad"}`,
		`{"Action":"output",` + pkg + `,"Output":"FAIL\n"}`,
		`{"Action":"fail",` + pkg + `}`,
		`{"Action":"output","Package":"github.com/philmalin/eictar/src/internal/cli","Output":"panic: test timed out after 10m0s\n"}`,
		`{"Action":"output","Package":"github.com/philmalin/eictar/src/internal/cli","Output":"FAIL\tgithub.com/philmalin/eictar/src/internal/cli\t600.1s\n"}`,
		`{"Action":"fail","Package":"github.com/philmalin/eictar/src/internal/cli"}`,
		`not JSON`,
	}, "\n")
	var out strings.Builder
	summarize(strings.NewReader(events), &out)
	want := `SKIP  src/internal/archive  TestSkip
      a_test.go:9: no named pipe here
FAIL  src/internal/archive  TestBad
      a_test.go:12: Create = <nil>
FAIL  src/internal/cli, outside a test
      panic: test timed out after 10m0s
1 passed, 1 failed, 1 skipped
`
	if out.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", out.String(), want)
	}
}
