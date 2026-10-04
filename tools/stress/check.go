//go:build unix

package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// checkArchive makes the three checks of doc/design.md 13.4 after a step:
// the listing names exactly the model's paths, --verify passes, and a full
// extraction gives back the model.
func (s *sequence) checkArchive() error {
	res, err := s.r.expect(true, "-tf", s.archive)
	if err != nil {
		return fmt.Errorf("list: %w", err)
	}
	if err := sameListing(res.stdout, s.model); err != nil {
		return fmt.Errorf("list: %w\n%s", err, res)
	}
	if _, err := s.r.expect(true, "--verify", "-q", "-f", s.archive); err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	if err := s.checkExtract(s.archive, nil, s.model); err != nil {
		return err
	}
	s.stats.checks["state"]++
	return nil
}

// checkExtract extracts archive (the members matching patterns, or all) and
// compares the result with want.
func (s *sequence) checkExtract(archive string, patterns []string, want Model) error {
	return s.checkExtractArgs(archive, withPaths(nil, patterns), want)
}

// checkExtractArgs extracts archive with extra arguments (patterns, or -R)
// and compares the result with want.
func (s *sequence) checkExtractArgs(archive string, extra []string, want Model) error {
	out := filepath.Join(s.dir, "out")
	if err := removeAll(out); err != nil {
		return err
	}
	args := append([]string{"-xf", archive, "-d", out}, extra...)
	if _, err := s.r.expect(true, args...); err != nil {
		return fmt.Errorf("extract: %w", err)
	}
	if err := compareTree(out, want); err != nil {
		return fmt.Errorf("extract %v: %w", extra, err)
	}
	return nil
}

func sameListing(listing string, m Model) error {
	got := map[string]bool{}
	for _, line := range strings.Split(strings.TrimRight(listing, "\n"), "\n") {
		if line != "" {
			got[line] = true
		}
	}
	var missing, extra []string
	for p := range m {
		if !got[p] {
			missing = append(missing, p)
		}
	}
	for p := range got {
		if _, ok := m[p]; !ok {
			extra = append(extra, p)
		}
	}
	if len(missing)+len(extra) == 0 {
		return nil
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return fmt.Errorf("the listing differs from the model: missing %q, extra %q", missing, extra)
}

// compareTree compares an extracted tree with the model: every model path is
// there with its type, content, size, mode, time and link target, and
// nothing else is, apart from the parent directories that extraction makes
// for a member whose directory the archive does not hold.
func compareTree(root string, want Model) error {
	implicit := want.ancestors()
	var problems []string
	seen := map[string]bool{}

	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == root {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		seen[rel] = true
		w, ok := want[rel]
		if !ok {
			if !(d.IsDir() && implicit[rel]) {
				problems = append(problems, rel+": extracted, but not in the model")
			}
			return nil
		}
		got, err := readEntry(p)
		if err != nil {
			return err
		}
		if msg := diffEntry(w, got); msg != "" {
			problems = append(problems, rel+": "+msg)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for p := range want {
		if !seen[p] {
			problems = append(problems, p+": in the model, not extracted")
		}
	}
	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	if len(problems) > 20 {
		problems = append(problems[:20], fmt.Sprintf("and %d more", len(problems)-20))
	}
	return fmt.Errorf("the extraction differs from the model:\n  %s", strings.Join(problems, "\n  "))
}

func diffEntry(want, got Entry) string {
	if want.Kind != got.Kind {
		return fmt.Sprintf("a %v, want a %v", got.Kind, want.Kind)
	}
	switch want.Kind {
	case kFile:
		if want.Size != got.Size {
			return fmt.Sprintf("%d bytes, want %d", got.Size, want.Size)
		}
		if want.Hash != got.Hash {
			return "the content differs (the size is right)"
		}
	case kLink:
		if want.Target != got.Target {
			return fmt.Sprintf("links to %q, want %q", got.Target, want.Target)
		}
	}
	if want.Kind != kLink && want.Perm != got.Perm {
		return fmt.Sprintf("mode %v, want %v", got.Perm, want.Perm)
	}
	if want.MTime != got.MTime {
		return fmt.Sprintf("mtime %d, want %d", got.MTime, want.MTime)
	}
	return ""
}

// removeAll removes a tree whose directories may be read-only.
func removeAll(p string) error {
	filepath.WalkDir(p, func(q string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			os.Chmod(q, 0o700)
		}
		return nil
	})
	return os.RemoveAll(p)
}
