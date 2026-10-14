package main

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

const sample = `package p

func f(a, b int, ok bool) (int, string) {
	if a < b && !ok {
		a++
	}
	return a << 2, "x" + "y"
}
`

// TestMutants: each operator gets its changes, a string concatenation gets
// none, and each change gives the expected source.
func TestMutants(t *testing.T) {
	ms, err := mutants("p.go", []byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, m := range ms {
		got = append(got, m.kind+" "+m.orig+" → "+m.repl)
	}
	want := []string{
		"if false a < b && !ok → false",
		"operator && → ||",
		"operator < → <=",
		"operator < → >=",
		"remove ! ! → ",
		"operator ++ → --",
		"operator << → >>",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("mutants:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	for _, m := range ms {
		out := string(m.apply([]byte(sample)))
		switch m.kind + m.repl {
		case "if falsefalse":
			if !strings.Contains(out, "if false {") {
				t.Errorf("if false: %s", out)
			}
		case "remove !":
			if !strings.Contains(out, "&& ok {") {
				t.Errorf("remove !: %s", out)
			}
		case "operator--":
			if !strings.Contains(out, "a--") {
				t.Errorf("++ → --: %s", out)
			}
		}
	}
}

// TestLineOf gives the source line of a mutant without its indent.
func TestLineOf(t *testing.T) {
	src := []byte(sample)
	off := strings.Index(sample, "a++")
	if got := lineOf(src, off); got != "a++" {
		t.Errorf("lineOf = %q", got)
	}
}

// TestCovered: a block covers its start and not its end column, and a block
// that did not run covers nothing.
func TestCovered(t *testing.T) {
	prof := `mode: set
example.com/p/p.go:3.40,4.18 1 1
example.com/p/p.go:4.18,6.3 1 0
`
	c, err := readProfile(strings.NewReader(prof))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		line, col int
		want      bool
	}{
		{3, 40, true},
		{4, 5, true},
		{4, 18, false}, // the end of the first block, the start of the second
		{5, 3, false},  // a block that did not run
		{2, 1, false},
	} {
		if got := c.has("p.go", tc.line, tc.col); got != tc.want {
			t.Errorf("has(%d, %d) = %v, want %v", tc.line, tc.col, got, tc.want)
		}
	}
	if _, err := readProfile(strings.NewReader("p.go:1.1,2.2 1\n")); err == nil {
		t.Error("a line with two fields: no error")
	}
}

// TestClassify: a build failure does not count, a time-out is found, and a
// pass is a survivor.
func TestClassify(t *testing.T) {
	fail := errors.New("exit status 1")
	for _, tc := range []struct {
		err     error
		out     string
		timeout bool
		want    outcome
	}{
		{nil, "ok", false, survived},
		{fail, "--- FAIL: TestX", false, killed},
		{fail, "FAIL\texample.com/p [build failed]", false, notCompiled},
		{fail, "FAIL\texample.com/p [setup failed]", false, notCompiled},
		{fail, "panic: test timed out after 30s", false, timedOut},
		{fail, "", true, timedOut},
	} {
		if got := classify(tc.err, []byte(tc.out), tc.timeout); got != tc.want {
			t.Errorf("classify(%v, %q, %v) = %s, want %s", tc.err, tc.out, tc.timeout, outcomeNames[got], outcomeNames[tc.want])
		}
	}
}

// TestConfirmTimeouts: only the mutants that timed out run again, and their
// second outcome replaces the first. A slow run under -j that passes alone is
// a survivor, not a hang.
func TestConfirmTimeouts(t *testing.T) {
	results := []outcome{killed, timedOut, survived, timedOut, notCovered, timedOut}
	second := map[int]outcome{1: survived, 3: timedOut, 5: killed}
	var ran []int
	n := confirmTimeouts(results, func(i int) outcome {
		ran = append(ran, i)
		return second[i]
	})
	want := []outcome{killed, survived, survived, timedOut, notCovered, killed}
	if n != 3 || !slices.Equal(ran, []int{1, 3, 5}) || !slices.Equal(results, want) {
		t.Errorf("n %d, ran %v, results %v; want 3, [1 3 5], %v", n, ran, results, want)
	}
}

// TestAnchors: a case expression takes the coverage of its switch, and a
// declaration outside a function always counts as run.
func TestAnchors(t *testing.T) {
	src := `package p

const big = 1 << 20

func f(a int) int {
	switch {
	case a > 1:
		return a + 1
	}
	return a - 1
}

func g(h func(func() int) error) {
	if err := h(func() int { return 0 }); err != nil {
		return
	}
}
`
	ms, err := mutants("p.go", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, m := range ms {
		got[m.orig] = fmt.Sprintf("%d:%d always=%v", m.covLine, m.covCol, m.always)
	}
	for orig, want := range map[string]string{
		"<<": "3:15 always=true", // a constant: no block
		">":  "6:2 always=false", // the switch keyword
		"+":  "8:12 always=false",
		"-":  "10:11 always=false",
		"!=": "14:2 always=false", // after a function literal: the if statement
	} {
		if got[orig] != want {
			t.Errorf("%s: %s, want %s", orig, got[orig], want)
		}
	}
}

// TestReadAccepted: an entry is a name and an indented reason, and a name
// without a reason, a reason without a name, or a name given two times is an
// error.
func TestReadAccepted(t *testing.T) {
	list, err := readAccepted(strings.NewReader(`# comment

src/p/p.go: f: operator: + → -
	the first line
	and the second line
src/p/p.go: T.m: if false: err != nil → false #2
    a reason
`))
	if err != nil {
		t.Fatal(err)
	}
	e := list["src/p/p.go: f: operator: + → -"]
	if e == nil || e.reason != "the first line and the second line" || e.line != 3 {
		t.Errorf("entry: %+v", e)
	}
	if list["src/p/p.go: T.m: if false: err != nil → false #2"] == nil || len(list) != 2 {
		t.Errorf("list: %v", list)
	}

	for name, bad := range map[string]string{
		"no reason":         "src/p/p.go: f: operator: + → -\n",
		"no reason, middle": "src/p/p.go: f: operator: + → -\nsrc/p/p.go: g: operator: + → -\n\tr\n",
		"reason first":      "\ta reason\n",
		"two times":         "a.go: f: x\n\tr\na.go: f: x\n\tr\n",
		"not three parts":   "a.go: x\n\tr\n",
	} {
		if _, err := readAccepted(strings.NewReader(bad)); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

// TestKeys: a name holds the file, the function and the mutation, and the
// second of two same mutations in one function gets #2.
func TestKeys(t *testing.T) {
	src := `package p

type T struct{}

func (t *T) m(a, b int) bool {
	if a <
		b {
		return a < b
	}
	return false
}

var v = func() int { return 1 + 2 }()
`
	ms, err := mutants("/x/p.go", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	got := keys(ms, map[string]string{"/x/p.go": "src/p/p.go"})
	want := []string{
		"src/p/p.go: T.m: if false: a < b → false",
		"src/p/p.go: T.m: operator: < → <=",
		"src/p/p.go: T.m: operator: < → >=",
		"src/p/p.go: T.m: operator: < → <= #2",
		"src/p/p.go: T.m: operator: < → >= #2",
		"src/p/p.go: v: operator: + → -",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("keys:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// TestStaleEntries: an entry whose mutant the tests find, or that names no
// mutant of a file of the run, is stale. An entry of a file that the run
// does not change is not.
func TestStaleEntries(t *testing.T) {
	cfg := config{
		accepted: map[string]*entry{
			"a.go: f: x": {key: "a.go: f: x", used: true},
			"a.go: f: y": {key: "a.go: f: y", found: true},
			"a.go: f: z": {key: "a.go: f: z"},
			"b.go: f: z": {key: "b.go: f: z"},
		},
		mutated: map[string]bool{"a.go": true},
	}
	if n := staleEntries(cfg, "accepted.txt"); n != 2 {
		t.Errorf("%d stale entries, want 2", n)
	}
}

// TestCoveredAdd: the coverage of the binary joins that of the tests.
func TestCoveredAdd(t *testing.T) {
	tests, err := readProfile(strings.NewReader("mode: set\nexample.com/p/p.go:3.1,4.1 1 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	bin, err := readProfile(strings.NewReader("mode: set\nexample.com/p/p.go:7.1,8.1 1 1\nexample.com/p/q.go:1.1,2.1 1 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	tests.add(bin)
	if !tests.has("p.go", 3, 5) || !tests.has("p.go", 7, 5) || !tests.has("q.go", 1, 5) {
		t.Errorf("after add: %v", tests)
	}
}

// TestRunArgsAndGoflags: the tags and -run go to each go test, and the
// overlay joins the GOFLAGS of the environment, so that a go build that a
// test runs has it too.
func TestRunArgsAndGoflags(t *testing.T) {
	if got := runArgs(config{tags: "operational", run: "TestX"}); !slices.Equal(got, []string{"-tags=operational", "-run", "TestX"}) {
		t.Errorf("runArgs: %q", got)
	}
	if got := runArgs(config{}); len(got) != 0 {
		t.Errorf("runArgs with nothing: %q", got)
	}
	t.Setenv("GOFLAGS", "")
	if got := withGoflags("-overlay=o.json"); got != "GOFLAGS=-overlay=o.json" {
		t.Errorf("no GOFLAGS: %q", got)
	}
	t.Setenv("GOFLAGS", "-mod=mod")
	if got := withGoflags("-overlay=o.json"); got != "GOFLAGS=-mod=mod -overlay=o.json" {
		t.Errorf("with GOFLAGS: %q", got)
	}
}
