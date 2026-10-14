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

// diskFaultKinds are the kinds of EICTAR_FAULT (src/internal/archive/
// faultinject.go).
var diskFaultKinds = []string{"open", "create", "write", "short", "sync", "truncate", "close", "rename", "remove", "syncdir"}

// diskFault runs a change to the archive with the binary of -tags
// faultinject, and makes one operation on the archive file fail: the Nth of
// a kind, at random (doc/design.md 13.5, step 3). The rules:
//
//   - A command that reports success leaves the new state.
//   - A command that fails leaves the old state or the new one. A change
//     made in place (append, delete) can need --repair, which must then give
//     back one of them. A change that commits with a rename (compact,
//     recompress, a change of passphrase) must never need it.
//   - No file is left beside the archive, except when the fault was the
//     removal of a temporary file.
//   - A failure is an I/O error: exit 4, never "damaged".
func (s *sequence) diskFault() error {
	before, err := os.ReadFile(s.archive)
	if err != nil {
		return err
	}
	modelBefore := s.model.clone()
	after := s.model.clone()
	oldCrypt, newCrypt := s.r.crypt, s.r.crypt
	inPlace := true
	var args []string
	var what string
	switch op := s.rnd.IntN(5); {
	case op == 0:
		paths := s.g.pickArgs()
		if len(paths) == 0 {
			return nil
		}
		spec := s.codecSpec()
		args = withPaths(append([]string{"-rf", s.archive, "-C", s.src, "--compress", spec}, s.tuning(spec)...), paths)
		s.model = after
		_, _, _, err := s.addToModel(paths, "replace", "", filter{})
		after, s.model = s.model, modelBefore.clone()
		if err != nil {
			return err
		}
		what = fmt.Sprintf("-r %q", paths)
	case op == 1:
		paths := s.model.paths()
		if len(paths) == 0 {
			return nil
		}
		p := paths[s.rnd.IntN(len(paths))]
		args = withPaths([]string{"--delete", "-f", s.archive}, []string{p})
		for q := range after.selectPaths([]string{p}) {
			delete(after, q)
		}
		what = fmt.Sprintf("--delete %q", p)
	case op == 2:
		args, inPlace, what = []string{"--compact", "-f", s.archive}, false, "--compact"
	case op == 3:
		spec := s.codecSpec()
		args = append([]string{"--compact", "-f", s.archive, "--recompress", spec}, s.tuning(spec)...)
		inPlace, what = false, "--compact --recompress "+spec
	default:
		if !s.encrypted {
			return nil
		}
		s.passphrases++
		pass := filepath.Join(s.dir, fmt.Sprintf("passphrase-%d", s.passphrases))
		if err := os.WriteFile(pass, []byte(fmt.Sprintf("stress passphrase %d\n", s.passphrases)), 0o600); err != nil {
			return err
		}
		args = []string{"--change-passphrase", "-f", s.archive, "--new-passphrase-file", pass}
		newCrypt = []string{"--passphrase-file", pass}
		inPlace, what = false, "--change-passphrase"
	}

	kind := diskFaultKinds[s.rnd.IntN(len(diskFaultKinds))]
	n := 1 + s.rnd.IntN(4)
	if kind == "write" || kind == "short" {
		n = 1 + s.rnd.IntN(40)
	}
	fault := fmt.Sprintf("%s:%d", kind, n)
	s.note("disk fault %s in %s", fault, what)
	s.stats.ops["disk fault"]++
	namesBefore, err := dirNames(s.dir)
	if err != nil {
		return err
	}
	res, err := s.r.runWith(s.r.faultBin, []string{"EICTAR_FAULT=" + fault}, true, args...)
	if err != nil {
		return err
	}
	fired := strings.Contains(res.stderr, "eictar-fault: ")
	switch {
	case res.code == 0:
		s.r.crypt = newCrypt
		s.model = after
		return s.inState("after a success", after)
	case !fired:
		return fmt.Errorf("a failure with no fault:\n%s", res)
	case res.code != 4:
		return fmt.Errorf("a disk fault: exit %d, want 4:\n%s", res.code, res)
	}
	s.stats.checks["disk-fault"]++

	// What is left beside the archive.
	namesAfter, err := dirNames(s.dir)
	if err != nil {
		return err
	}
	for name := range namesAfter {
		if namesBefore[name] {
			continue
		}
		if kind != "remove" || !strings.HasPrefix(name, "."+filepath.Base(s.archive)+".") {
			return fmt.Errorf("a disk fault left %s beside the archive:\n%s", name, res)
		}
		if err := os.Remove(filepath.Join(s.dir, name)); err != nil {
			return err
		}
	}

	list, err := s.r.run(true, "-tf", s.archive)
	if err != nil {
		return err
	}
	if list.code == 3 && inPlace && strings.Contains(list.stderr, "--repair") {
		// One fault cannot stop the rollback of a change in place, so this
		// needs two, or a crash after the fault (crash_test.go). It is an
		// outcome that the rules allow, not one that a run must reach.
		if _, err := s.r.expect(true, "--repair", "-f", s.archive); err != nil {
			return fmt.Errorf("repair after a disk fault: %w", err)
		}
	}
	// The old state, or the new one. A change that commits with a rename
	// leaves the old archive byte for byte, or the new one: a fault after
	// the rename, in the fsync of the directory, leaves the new one, and
	// the command rightly fails, as the change may not last. A compact
	// has the same model before and after, so the bytes tell them apart. A
	// change of passphrase that failed leaves the old one, or a new one
	// under the new passphrase.
	s.model = modelBefore
	if !inPlace {
		now, err := os.ReadFile(s.archive)
		if err != nil {
			return err
		}
		if bytes.Equal(now, before) {
			return s.inState("the old archive", modelBefore)
		}
	} else if err := s.inState("", modelBefore); err == nil {
		return nil
	}
	s.r.crypt, s.model = newCrypt, after
	if err := s.inState("", after); err != nil {
		s.r.crypt = oldCrypt
		return fmt.Errorf("a disk fault left neither the old state nor the new one: %w\n%s", err, res)
	}
	return nil
}

// inState checks that the archive holds m, with the checks after each step.
func (s *sequence) inState(when string, m Model) error {
	kept := s.model
	s.model = m
	err := s.checkArchive()
	s.model = kept
	if err != nil && when != "" {
		return fmt.Errorf("%s: %w", when, err)
	}
	return err
}

// dirNames is the set of names in dir.
func dirNames(dir string) (map[string]bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := map[string]bool{}
	for _, e := range entries {
		names[e.Name()] = true
	}
	return names, nil
}
