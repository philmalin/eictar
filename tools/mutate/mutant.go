package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
)

// mutant is one small change to one file: the bytes from start to end are
// replaced by repl.
type mutant struct {
	file       string // the absolute path of the file
	line, col  int    // where the change starts, for the report
	start, end int    // byte offsets of the replaced text
	orig, repl string
	kind       string // the operator, for the report
	fn         string // the function that holds the change, for the accepted list

	// covLine and covCol give the place whose coverage tells whether the
	// tests run the change. It is the change itself, except where the
	// coverage profile has no block (see anchors). always is true for a
	// change that is not in a function: the tests always use it.
	covLine, covCol int
	always          bool
}

func (m mutant) String() string {
	return fmt.Sprintf("%d:%d: %s: %s → %s", m.line, m.col, m.kind, m.orig, m.repl)
}

// apply returns src with the change made.
func (m mutant) apply(src []byte) []byte {
	out := make([]byte, 0, len(src)+len(m.repl))
	out = append(out, src[:m.start]...)
	out = append(out, m.repl...)
	return append(out, src[m.end:]...)
}

// swaps gives, for each binary operator, the operators that take its place:
// the boundary of a comparison, the opposite comparison, and the other
// operator of a pair. A change that does not compile, such as - on two
// strings, is found when the mutant is built, and is not counted.
var swaps = map[token.Token][]token.Token{
	token.LSS:     {token.LEQ, token.GEQ},
	token.LEQ:     {token.LSS, token.GTR},
	token.GTR:     {token.GEQ, token.LEQ},
	token.GEQ:     {token.GTR, token.LSS},
	token.EQL:     {token.NEQ},
	token.NEQ:     {token.EQL},
	token.LAND:    {token.LOR},
	token.LOR:     {token.LAND},
	token.ADD:     {token.SUB},
	token.SUB:     {token.ADD},
	token.MUL:     {token.QUO},
	token.QUO:     {token.MUL},
	token.REM:     {token.MUL},
	token.AND:     {token.OR},
	token.OR:      {token.AND},
	token.XOR:     {token.AND},
	token.SHL:     {token.SHR},
	token.SHR:     {token.SHL},
	token.AND_NOT: {token.AND},
}

// mutants parses the Go file at path and returns each change that the tool
// makes to it.
func mutants(path string, src []byte) ([]mutant, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	spans := anchors(f)
	decls := declNames(f)
	var out []mutant
	add := func(pos, end token.Pos, repl, kind string) {
		p, e := fset.Position(pos), fset.Position(end)
		c, always := p, false
		for _, s := range spans {
			if pos >= s.start && pos < s.end {
				if s.anchor == token.NoPos {
					always = true
				} else {
					c = fset.Position(s.anchor)
				}
			}
		}
		fn := "-"
		for _, d := range decls {
			if pos >= d.start && pos < d.end {
				fn = d.name
			}
		}
		out = append(out, mutant{
			file: path, line: p.Line, col: p.Column, fn: fn,
			covLine: c.Line, covCol: c.Column, always: always,
			start: p.Offset, end: e.Offset,
			orig: string(src[p.Offset:e.Offset]), repl: repl, kind: kind,
		})
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.BinaryExpr:
			if isStringLit(n.X) || isStringLit(n.Y) {
				break // a string concatenation has no other operator
			}
			for _, to := range swaps[n.Op] {
				add(n.OpPos, n.OpPos+token.Pos(len(n.Op.String())), to.String(), "operator")
			}
		case *ast.UnaryExpr:
			if n.Op == token.NOT {
				add(n.Pos(), n.X.Pos(), "", "remove !")
			}
		case *ast.IncDecStmt:
			to := token.DEC
			if n.Tok == token.DEC {
				to = token.INC
			}
			add(n.TokPos, n.TokPos+2, to.String(), "operator")
		case *ast.IfStmt:
			// The check never runs: what the tests must find when a guard
			// goes missing.
			add(n.Cond.Pos(), n.Cond.End(), "false", "if false")
		}
		return true
	})
	return out, nil
}

func isStringLit(e ast.Expr) bool {
	b, ok := e.(*ast.BasicLit)
	return ok && b.Kind == token.STRING
}

// lineOf returns the line of src that holds offset, without its indent.
func lineOf(src []byte, offset int) string {
	start := bytes.LastIndexByte(src[:offset], '\n') + 1
	end := bytes.IndexByte(src[offset:], '\n')
	if end < 0 {
		end = len(src) - offset
	}
	return string(bytes.TrimSpace(src[start : offset+end]))
}

// span is a part of a file whose coverage the profile does not give.
type span struct {
	start, end token.Pos
	anchor     token.Pos // the place to look up in its stead; NoPos: always run
}

// anchors finds the parts of a file that have no block in a coverage
// profile:
//
//   - The expressions of a case clause. A block of go test -cover starts after
//     the colon of a case, so its expressions are in no block. The switch
//     statement is in the block before it, and the tests that run the switch
//     run its case expressions too, up to the case that matches.
//   - A declaration outside a function, such as a constant. The compiler
//     uses it, so each test that builds uses it.
//   - The rest of a statement after a function literal in it, up to the
//     body of an if, a for or a switch. Its block ends where the literal
//     starts. The statement takes its place: the tests that run its start
//     run the rest.
func anchors(f *ast.File) []span {
	var out []span
	for _, d := range f.Decls {
		if g, ok := d.(*ast.GenDecl); ok {
			out = append(out, span{g.Pos(), g.End(), token.NoPos})
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		var body *ast.BlockStmt
		switch s := n.(type) {
		case *ast.SwitchStmt:
			body = s.Body
		case *ast.TypeSwitchStmt:
			body = s.Body
		default:
			return true
		}
		for _, st := range body.List {
			if cc, ok := st.(*ast.CaseClause); ok && len(cc.List) > 0 {
				out = append(out, span{cc.List[0].Pos(), cc.Colon, n.Pos()})
			}
		}
		return true
	})

	// What follows a function literal in its statement. A block of go test
	// -cover ends where a function literal starts, and no block holds the
	// rest of the statement: in `if err := f(func() {...}); err != nil {`,
	// the condition is in no block. The statement runs when its start runs.
	var stack []ast.Node
	ast.Inspect(f, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		if lit, ok := n.(*ast.FuncLit); ok {
			for i := len(stack) - 1; i >= 0; i-- {
				st, ok := stack[i].(ast.Stmt)
				if !ok {
					continue
				}
				if _, block := st.(*ast.BlockStmt); block {
					continue
				}
				if _, clause := st.(*ast.CaseClause); clause {
					break // a case expression has its own anchor
				}
				// The init statement of an if, a for or a switch is part of
				// its header: the condition after it is in no block either.
				for j := i - 1; j >= 0; j-- {
					if outer, ok := stack[j].(ast.Stmt); ok && headerEnd(outer) != outer.End() && st.End() <= headerEnd(outer) {
						st = outer
						break
					}
				}
				if end := headerEnd(st); lit.End() < end {
					out = append(out, span{lit.End(), end, st.Pos()})
				}
				break
			}
		}
		stack = append(stack, n)
		return true
	})
	return out
}

// headerEnd is where the part of st before its body ends: the brace of the
// body of an if, a for or a switch, and the end of any other statement.
func headerEnd(st ast.Stmt) token.Pos {
	switch s := st.(type) {
	case *ast.IfStmt:
		return s.Body.Lbrace
	case *ast.ForStmt:
		return s.Body.Lbrace
	case *ast.RangeStmt:
		return s.Body.Lbrace
	case *ast.SwitchStmt:
		return s.Body.Lbrace
	case *ast.TypeSwitchStmt:
		return s.Body.Lbrace
	}
	return st.End()
}

// named is a declaration outside a function and its name.
type named struct {
	start, end token.Pos
	name       string
}

// declNames gives the name of each declaration of a file: Func, or
// Type.Method for a method, and the first name of a var or const group.
func declNames(f *ast.File) []named {
	var out []named
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			name := d.Name.Name
			if d.Recv != nil && len(d.Recv.List) > 0 {
				name = recvType(d.Recv.List[0].Type) + "." + name
			}
			out = append(out, named{d.Pos(), d.End(), name})
		case *ast.GenDecl:
			for _, s := range d.Specs {
				if v, ok := s.(*ast.ValueSpec); ok && len(v.Names) > 0 {
					out = append(out, named{v.Pos(), v.End(), v.Names[0].Name})
				}
			}
		}
	}
	return out
}

// recvType gives the name of a receiver type, without * or type parameters.
func recvType(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return recvType(t.X)
	case *ast.IndexExpr:
		return recvType(t.X)
	case *ast.IndexListExpr:
		return recvType(t.X)
	case *ast.Ident:
		return t.Name
	}
	return "?"
}

// mutation gives the change as the accepted list names it, with the white
// space of a condition that spans lines made into single spaces.
func (m mutant) mutation() string {
	// A removal has an empty replacement. The name then ends at the arrow,
	// with no space, as a line of the accepted list ends.
	return strings.TrimRight(m.kind+": "+strings.Join(strings.Fields(m.orig), " ")+" → "+m.repl, " ")
}
