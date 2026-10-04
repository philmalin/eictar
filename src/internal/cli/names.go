package cli

import (
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// printable shows each character of s that a terminal can act on as an
// escape: the control characters, a byte that is not UTF-8, and the
// characters that change the direction of the text. A name on Linux can hold
// any byte but "/" and NUL, and a crafted archive can hold any name. Written
// as it is, an escape sequence in a name can recolour the terminal, move the
// cursor, or write over the lines before it, so that a listing does not show
// what the archive holds (doc/design.md 10.13, doc/Security_Audit.md finding
// 12). A backslash is shown doubled, so that each escape has one meaning.
func printable(s string) string {
	if !needsEscape(s) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\r':
			b.WriteString(`\r`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case isC1(r) || isBidi(r):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

// needsEscape reports whether printable changes s. Most names need nothing,
// and then printable makes no copy.
func needsEscape(s string) bool {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if (r == utf8.RuneError && size == 1) || r == '\\' || r < 0x20 || r == 0x7f || isC1(r) || isBidi(r) {
			return true
		}
		i += size
	}
	return false
}

// isC1 reports a control character of the C1 set, U+0080 to U+009F. Some
// terminals act on these as on the escape sequences of the C0 set.
func isC1(r rune) bool { return r >= 0x80 && r <= 0x9f }

// isBidi reports a character that changes the direction of the text after
// it. With one, a name can show its characters in another order than they
// have, and look like another name.
func isBidi(r rune) bool {
	switch {
	case r == 0x061c, r == 0x200e, r == 0x200f:
		return true
	case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
		return true
	}
	return false
}

// namesFor returns how the names of a listing are shown on w: escaped on a
// terminal, and exact otherwise, for a script that reads them. ls makes the
// same choice. --json is exact in both cases, as JSON escapes.
func namesFor(w io.Writer) func(string) string {
	if isTerminal(w) {
		return printable
	}
	return func(s string) string { return s }
}
