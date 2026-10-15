//go:build unix

package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/philmalin/eictar/tools/ectread/compare"
	"github.com/philmalin/eictar/tools/ectread/ect"
)

// The second reader (doc/testing.md 5, step 2) reads each state of the
// archive too. It is written from doc/format.md alone, so a rule that the
// writer breaks, or that the specification does not give, shows as a
// difference here.

// maxKDFKiB bounds the key derivation of the second reader. A damaged crypto
// header can ask for 4 GiB, and the sequences use 16 MiB at most.
const maxKDFKiB = 64 << 10

// secondReader opens archive with the second reader, with the passphrase of
// the sequence.
func (s *sequence) secondReader(archive string) (*ect.Archive, error) {
	opt := ect.Options{MaxKDFMemoryKiB: maxKDFKiB}
	if len(s.r.crypt) == 2 {
		// eictar runs in the directory of the sequence.
		pass := s.r.crypt[1]
		if !filepath.IsAbs(pass) {
			pass = filepath.Join(s.r.dir, pass)
		}
		b, err := os.ReadFile(pass)
		if err != nil {
			return nil, err
		}
		line, _, _ := bytes.Cut(b, []byte("\n"))
		opt.Passphrase = line
	}
	return ect.Open(archive, opt)
}

// readEach reads the content of each live member with the second reader.
func readEach(a *ect.Archive) error {
	for _, m := range a.Live() {
		if m.Type == "reg" || m.Type == "hardlink" {
			if err := a.Content(m, io.Discard); err != nil {
				return fmt.Errorf("%q: %w", m.Path, err)
			}
		}
	}
	return nil
}

// checkSecondReader compares the second reader with eictar on the archive:
// the listing of eictar -t --json against the index that the reader
// decodes, and the extraction of the reader against the model.
func (s *sequence) checkSecondReader() error {
	res, err := s.r.expect(true, "-tf", s.archive, "--json")
	if err != nil {
		return fmt.Errorf("list --json: %w", err)
	}
	a, err := s.secondReader(s.archive)
	if err != nil {
		return fmt.Errorf("the second reader refuses an archive that eictar reads: %w", err)
	}
	defer a.Close()
	if err := compare.Listing(a, []byte(res.stdout)); err != nil {
		return err
	}
	out := filepath.Join(s.dir, "out-second")
	if err := removeAll(out); err != nil {
		return err
	}
	if err := ect.Extract(a, out, io.Discard); err != nil {
		return fmt.Errorf("the second reader extracts: %w", err)
	}
	if err := compareTree(out, s.model); err != nil {
		return fmt.Errorf("the extraction of the second reader: %w", err)
	}
	s.stats.checks["second-reader"]++
	return nil
}

// checkSecondReaderDamaged compares the second reader with eictar on a
// damaged copy: it refuses the copy when eictar does, and reads each member
// when eictar does.
func (s *sequence) checkSecondReaderDamaged(damaged string, eictarAccepts bool) error {
	a, err := s.secondReader(damaged)
	if err == nil {
		err = readEach(a)
		a.Close()
	}
	switch {
	case eictarAccepts && err != nil:
		return fmt.Errorf("eictar accepts a damaged copy, and the second reader refuses it: %w", err)
	case !eictarAccepts && err == nil:
		return fmt.Errorf("eictar refuses a damaged copy, and the second reader accepts it")
	}
	s.stats.checks["damage-second-reader"]++
	return nil
}
