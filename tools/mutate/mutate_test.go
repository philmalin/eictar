package main

import (
	"errors"
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
