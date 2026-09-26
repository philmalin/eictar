package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"runtime"

	"golang.org/x/term"
)

// passphraseSource resolves where the passphrase comes from, once, at the
// point it is needed.
//
// It is deliberately not read during option parsing: a plaintext archive must
// never prompt, and a run that fails on a usage error should not have asked
// for a secret first.
type passphraseSource struct {
	file    string
	env     string
	confirm bool // creating: ask twice, since a typo is unrecoverable
	isNew   bool // the new passphrase of --change-passphrase
	stdin   *os.File
	stderr  *os.File
}

// ErrNoPassphrase means none could be obtained without a terminal.
var ErrNoPassphrase = errors.New("no passphrase available")

func (p passphraseSource) get() ([]byte, error) {
	switch {
	case p.file != "":
		return p.fromFile()
	case p.env != "":
		return p.fromEnv()
	default:
		return p.prompt()
	}
}

// fromFile reads the first line of a file, which is the usual way to script
// this without putting the secret on a command line.
func (p passphraseSource) fromFile() ([]byte, error) {
	data, err := os.ReadFile(p.file)
	if err != nil {
		return nil, fmt.Errorf("reading the passphrase file: %w", err)
	}
	// First line only, newline stripped: an editor that appended one must not
	// change the key.
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		data = data[:i]
	}
	data = bytes.TrimSuffix(data, []byte("\r"))
	if len(data) == 0 {
		return nil, fmt.Errorf("%s is empty", p.file)
	}
	return data, nil
}

func (p passphraseSource) fromEnv() ([]byte, error) {
	v, ok := os.LookupEnv(p.env)
	if !ok {
		return nil, fmt.Errorf("the environment variable %s is not set", p.env)
	}
	if v == "" {
		return nil, fmt.Errorf("the environment variable %s is empty", p.env)
	}
	return []byte(v), nil
}

// prompt reads from the terminal with echo off.
func (p passphraseSource) prompt() ([]byte, error) {
	in, errOut := p.stdin, p.stderr
	if in == nil {
		in = os.Stdin
	}
	if errOut == nil {
		errOut = os.Stderr
	}

	fd := int(in.Fd())
	if !term.IsTerminal(fd) {
		return nil, fmt.Errorf("%w: standard input is not a terminal; "+
			"use %s-file, or %s-env naming a variable", ErrNoPassphrase, p.option(), p.option())
	}

	label := "Passphrase"
	if p.isNew {
		label = "New passphrase"
	}
	// The prompt goes to stderr so that it cannot land in a redirected
	// listing or in extracted content.
	fmt.Fprint(errOut, label+": ")
	first, err := term.ReadPassword(fd)
	fmt.Fprintln(errOut)
	if err != nil {
		return nil, fmt.Errorf("reading the passphrase: %w", err)
	}
	if len(first) == 0 {
		return nil, errors.New("an empty passphrase cannot protect anything")
	}

	if p.confirm {
		fmt.Fprint(errOut, label+" (again): ")
		second, err := term.ReadPassword(fd)
		fmt.Fprintln(errOut)
		if err != nil {
			return nil, fmt.Errorf("reading the passphrase: %w", err)
		}
		// A mistyped passphrase on create is unrecoverable: nothing else in
		// the program can tell you later what you meant to type.
		if !bytes.Equal(first, second) {
			zeroBytes(first)
			zeroBytes(second)
			return nil, errors.New("the two passphrases do not match")
		}
		zeroBytes(second)
	}
	return first, nil
}

// describe says where a passphrase would come from, for error messages.
func (p passphraseSource) describe() string {
	switch {
	case p.file != "":
		return p.option() + "-file " + p.file
	case p.env != "":
		return p.option() + "-env " + p.env
	default:
		return "the terminal"
	}
}

// option is the start of the name of the options that give this passphrase.
func (p passphraseSource) option() string {
	if p.isNew {
		return "--new-passphrase"
	}
	return "--passphrase"
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// warnIfInsecureSource reports the environment-variable route, which is
// visible to anything that can read /proc, and a passphrase file that other
// users can read, as ssh does for a key (doc/Security_Audit.md, finding 8).
func (p passphraseSource) warnIfInsecureSource(warn func(string, ...any)) {
	if warn == nil {
		return
	}
	if p.env != "" {
		warn("%s-env exposes the passphrase to anything that can read this process's environment", p.option())
	}
	if p.file != "" && runtime.GOOS != "windows" {
		if fi, err := os.Stat(p.file); err == nil && fi.Mode().Perm()&0o044 != 0 {
			warn("%s can be read by other users (mode %04o); chmod 600 it", p.file, fi.Mode().Perm())
		}
	}
}
