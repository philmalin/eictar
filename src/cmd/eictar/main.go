// Command eictar packages files into an encrypted, individually-compressed
// archive. See doc/design.md for the format and the interface.
package main

import (
	"os"

	"eictar/src/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
