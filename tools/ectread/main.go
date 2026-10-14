// ectread is a second reader of eictar archives, written from doc/format.md
// alone (doc/design.md 13.5, step 2). It lists an archive, checks it, or
// extracts it, with no code of eictar.
//
//	ectread [-p FILE] -t ARCHIVE      one JSON line for each live member
//	ectread [-p FILE] -c ARCHIVE      read and check each member
//	ectread [-p FILE] -x DIR ARCHIVE  extract into DIR, which must not exist
//
// The passphrase is the first line of FILE, as for eictar --passphrase-file.
//
// Exit status: 0 for success, 1 for a refusal of the archive (doc/format.md
// 1) or a wrong passphrase, 2 for a usage error, 3 for any other error.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/philmalin/eictar/tools/ectread/ect"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ectread", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, "Usage:\n  ectread [-p FILE] -t ARCHIVE\n  ectread [-p FILE] -c ARCHIVE\n  ectread [-p FILE] -x DIR ARCHIVE\n")
		fs.PrintDefaults()
	}
	pass := fs.String("p", "", "read the passphrase from `FILE`")
	list := fs.Bool("t", false, "list each live member as a line of JSON")
	check := fs.Bool("c", false, "read and check the content of each member")
	dest := fs.String("x", "", "extract into `DIR`, which must not exist")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	modes := 0
	for _, b := range []bool{*list, *check, *dest != ""} {
		if b {
			modes++
		}
	}
	if modes != 1 || fs.NArg() != 1 {
		fmt.Fprintln(stderr, "ectread: give one of -t, -c and -x, and one archive")
		return 2
	}
	var opt ect.Options
	if *pass != "" {
		b, err := os.ReadFile(*pass)
		if err != nil {
			fmt.Fprintln(stderr, "ectread:", err)
			return 3
		}
		b, _, _ = bytes.Cut(b, []byte("\n"))
		opt.Passphrase = bytes.TrimSuffix(b, []byte("\r"))
	}
	a, err := ect.Open(fs.Arg(0), opt)
	if err == nil {
		defer a.Close()
		switch {
		case *list:
			err = listArchive(a, stdout)
		case *check:
			err = checkArchive(a)
		default:
			err = ect.Extract(a, *dest, stderr)
		}
	}
	if err != nil {
		fmt.Fprintln(stderr, "ectread:", err)
		var refused *ect.RefusedError
		if errors.As(err, &refused) || errors.Is(err, ect.ErrWrongPassphrase) {
			return 1
		}
		return 3
	}
	return 0
}

func checkArchive(a *ect.Archive) error {
	for _, m := range a.Members {
		if (m.Type == "reg" || m.Type == "hardlink") && !m.Dead {
			if err := a.Payload(m, io.Discard); err != nil {
				return fmt.Errorf("%q: %w", m.Path, err)
			}
		}
	}
	return nil
}
