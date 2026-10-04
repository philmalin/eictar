//go:build unix

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// crashable runs a change to the archive. In the fault mode it sometimes
// then cuts the file at a random point inside the new generation, as a
// crash would leave it (doc/design.md 9.1). The archive must be refused, with
// a message that names --repair, and --repair must give back the archive of
// before the change, byte for byte.
func (s *sequence) crashable(change func() error) error {
	if !s.faults || s.rnd.IntN(5) != 0 {
		return change()
	}
	before, err := os.ReadFile(s.archive)
	if err != nil {
		return err
	}
	modelBefore := s.model.clone()
	if err := change(); err != nil {
		return err
	}
	fi, err := os.Stat(s.archive)
	if err != nil {
		return err
	}
	grown := fi.Size() - int64(len(before))
	if grown < 2 {
		return nil // nothing was written: a skip, an unchanged update, a conflict
	}
	cut := int64(len(before)) + 1 + s.rnd.Int64N(grown-1)
	s.note("crash: cut the archive at %d of %d bytes (the old generation ends at %d)", cut, fi.Size(), len(before))
	if err := os.Truncate(s.archive, cut); err != nil {
		return err
	}

	res, err := s.r.run(true, "-tf", s.archive)
	if err != nil {
		return err
	}
	if res.code != 3 || !strings.Contains(res.stderr, "--repair") {
		return fmt.Errorf("a torn archive: exit %d, want 3 and a message naming --repair:\n%s", res.code, res)
	}
	if _, err := s.r.expect(true, "--repair", "-f", s.archive); err != nil {
		return fmt.Errorf("repair: %w", err)
	}
	after, err := os.ReadFile(s.archive)
	if err != nil {
		return err
	}
	if !bytes.Equal(before, after) {
		return fmt.Errorf("repair gave %d bytes that are not the archive of before the change (%d bytes)",
			len(after), len(before))
	}
	s.model = modelBefore
	s.stats.checks["crash"]++
	return nil
}

// flipCheck damages a copy of the archive: one to four bytes, anywhere. Then
// --verify and a full extraction must both refuse it with exit 3 (exit 4 only
// for a key derivation that this machine cannot afford), or both accept it
// and give back exactly the model: a byte in dead space harms nothing. Wrong
// content with exit 0 is the failure this looks for.
func (s *sequence) flipCheck() error {
	data, err := os.ReadFile(s.archive)
	if err != nil {
		return err
	}
	var where []string
	for n := 1 + s.rnd.IntN(4); n > 0; n-- {
		off := s.rnd.IntN(len(data))
		if s.rnd.IntN(3) == 0 && len(data) > 512 {
			off = len(data) - 1 - s.rnd.IntN(512) // the index and the trailer
		}
		bit := byte(1) << s.rnd.IntN(8)
		data[off] ^= bit
		where = append(where, fmt.Sprintf("%d^%#02x", off, bit))
	}
	damaged := filepath.Join(s.dir, "damaged.ect")
	if err := os.WriteFile(damaged, data, 0o600); err != nil {
		return err
	}
	s.note("damage a copy: flip bits at %s", strings.Join(where, ", "))

	verify, err := s.r.run(true, "--verify", "-q", "-f", damaged)
	if err != nil {
		return err
	}
	out := filepath.Join(s.dir, "out-damaged")
	if err := removeAll(out); err != nil {
		return err
	}
	extract, err := s.r.run(true, "-xf", damaged, "-d", out)
	if err != nil {
		return err
	}
	for _, res := range []result{verify, extract} {
		ok := res.code == 0 || res.code == 3 ||
			(res.code == 4 && strings.Contains(res.stderr, "deriving the key needs"))
		if !ok {
			return fmt.Errorf("a damaged archive: exit %d, want 0 or 3:\n%s", res.code, res)
		}
	}
	if (verify.code == 0) != (extract.code == 0) {
		return fmt.Errorf("--verify and extraction disagree about a damaged archive:\n%s\n%s", verify, extract)
	}
	if extract.code != 0 {
		s.stats.checks["damage-refused"]++
		return nil
	}
	// Accepted: the damage must have been in dead space.
	if err := compareTree(out, s.model); err != nil {
		return fmt.Errorf("a damaged archive was accepted with wrong content: %w", err)
	}
	s.stats.checks["damage-dead"]++
	return nil
}
