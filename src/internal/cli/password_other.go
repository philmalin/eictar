//go:build !unix

package cli

import "golang.org/x/term"

// readPassword reads one line from the terminal fd with echo off.
func readPassword(fd int) ([]byte, error) { return term.ReadPassword(fd) }
