package archive

import (
	"errors"
	"fmt"
	"hash"
	"io/fs"
	"os"

	"github.com/philmalin/eictar/src/internal/format"
)

// A dry run (-n, doc/design.md 9.9) selects what its operation would work on,
// by the same code and with the same options, and reports each path. It opens
// nothing for writing: no archive is created or locked, and no file is
// extracted. It reads no file content, except to compare digests under -u
// --update-mode=digest, so a file that cannot be read fails only in the real
// run.

// Planned is one path that an operation would write, or delete.
type Planned struct {
	Path string
	// Replaces is true when the path replaces something: a live member with
	// the same path (-r, -u), or a file on disk (-x).
	Replaces bool
	// Size is the content of a regular file. It is 0 for other types, and
	// for a second name of a hardlinked file, which stores no content.
	Size uint64
}

// PlanFunc receives each path of a dry run.
type PlanFunc func(Planned)

// PlanAdd is a dry run of create, when existing is false, and of append and
// update. It walks cfg.Paths as they do, and applies --on-conflict and -u to
// the paths that the archive holds. The paths come in walk order.
func PlanAdd(cfg AppendConfig, existing bool, plan PlanFunc) (Stats, error) {
	var stats Stats
	c := &capturer{seen: map[string]bool{}, newHash: func() hash.Hash { return newDigest(nil) }}
	if existing {
		if err := cfg.checkPolicies(); err != nil {
			return stats, err
		}
		r, err := OpenWith(cfg.Archive, cfg.Open)
		if err != nil {
			return stats, err
		}
		defer r.Close()
		c.live = map[string]*format.Member{}
		c.byID = map[uint64]*format.Member{}
		all := r.AllMembers()
		for i := range all {
			m := &all[i]
			c.byID[m.ID] = m
			if !m.Dead {
				c.live[m.Path] = m
			}
		}
		c.onConflict = cfg.OnConflict
		c.updateMode = cfg.UpdateMode
		c.newHash = func() hash.Hash { return newDigest(r.keys) }
	}

	guard := newWalkGuard(cfg.CreateConfig, nil)
	// firstName holds the inodes with more than one name that the walk has
	// met: a later name stores no content (capturer.submitFile).
	firstName := map[inodeKey]bool{}
	visit := func(e entry) error {
		if guard.skip(e) {
			return nil
		}
		old, err := c.decide(e)
		if err == nil {
			err = storable(e)
		}
		if err != nil {
			return countOutcome(cfg.CreateConfig, &stats, err)
		}

		p := Planned{Path: e.Stored, Replaces: old != nil}
		if e.Kind == kindFile {
			p.Size = uint64(e.Info.Size())
			if e.Sys.OK && e.Sys.Nlink > 1 {
				key := inodeKey{e.Sys.Dev, e.Sys.Ino}
				if firstName[key] {
					p.Size = 0
				}
				firstName[key] = true
			}
		}
		stats.Members++
		stats.Bytes += p.Size
		if p.Replaces {
			stats.Replaced++
		}
		plan(p)
		return nil
	}
	return stats, walkPaths(cfg.CreateConfig, &stats, visit)
}

// PlanExtract is a dry run of extract. It selects the members as Extract
// does, and applies the overwrite policy (-k, --newer-only) to the files that
// exist under the destination. The paths come in path order.
func PlanExtract(cfg ExtractConfig, plan PlanFunc) (Stats, error) {
	var stats Stats
	r, err := OpenWith(cfg.Archive, OpenOptions{
		Passphrase: cfg.Passphrase, RequireEncryption: cfg.RequireEncryption,
	})
	if err != nil {
		return stats, err
	}
	defer r.Close()

	members, byID, collided, err := cfg.selection(r)
	if err != nil {
		return stats, err
	}
	stats.Collided = collided
	contentSize := func(m *format.Member) uint64 {
		if m.Type == format.TypeReg {
			return m.Size
		}
		return 0
	}

	// -O writes the content of the files, and nothing else.
	if cfg.ToStdout != nil {
		for i := range members {
			m := &members[i]
			content := m
			if m.Type == format.TypeHardlink {
				if content = byID[m.HardlinkTo]; content == nil {
					return stats, fmt.Errorf("%w: hardlink %q names a missing member", format.ErrCorruptIndex, m.Path)
				}
			}
			if !content.Type.HasPayload() {
				continue
			}
			stats.Members++
			stats.Bytes += content.Size
			plan(Planned{Path: m.Path, Size: content.Size})
		}
		return stats, nil
	}

	// A destination that does not exist holds no files, and a dry run does
	// not create it.
	dest := cfg.Destination
	if dest == "" {
		dest = "."
	}
	root, err := os.OpenRoot(dest)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return stats, fmt.Errorf("opening %s: %w", dest, err)
	}
	if root != nil {
		defer root.Close()
	}

	for i := range members {
		m := &members[i]
		replaces, skip, err := planMember(root, m, cfg)
		var notice *errSkipped
		switch {
		case errors.As(err, &notice):
			stats.Skipped++
			if cfg.Reporter != nil {
				cfg.Reporter.Warn("%v", notice)
			}
		case err != nil:
			stats.Failed++
			if !cfg.KeepGoing {
				return stats, err
			}
			if cfg.Reporter != nil {
				cfg.Reporter.Warn("%v", err)
			}
		case skip:
			stats.Skipped++
		default:
			stats.Members++
			stats.Bytes += contentSize(m)
			plan(Planned{Path: m.Path, Replaces: replaces, Size: contentSize(m)})
		}
	}
	return stats, nil
}

// planMember decides what extraction would do with m: write it, replacing
// what is there or not, or skip it under the overwrite policy. root is nil
// when the destination does not exist.
func planMember(root *os.Root, m *format.Member, cfg ExtractConfig) (replaces, skip bool, err error) {
	if err := checkPath(m); err != nil {
		return false, false, err
	}
	switch m.Type {
	case format.TypeCharDev, format.TypeBlockDev:
		if !cfg.Restore.Devices {
			return false, false, &errSkipped{reason: fmt.Sprintf("%s: device node skipped (use --preserve-devices, as root)", m.Path)}
		}
	case format.TypeSocket:
		return false, false, &errSkipped{reason: fmt.Sprintf("%s: socket ignored", m.Path)}
	}
	// A directory that exists is used as it is, whatever the policy.
	if root == nil || m.Type == format.TypeDir {
		return false, false, nil
	}
	skip, err = shouldSkip(root, m.Path, m.MTimeNanos, cfg.Overwrite)
	if err != nil {
		return false, false, unsafeOrRaw(root, m, err)
	}
	if skip {
		return false, true, nil
	}
	_, err = root.Lstat(m.Path)
	return err == nil, false, nil
}

// PlanDelete is a dry run of delete: it selects the live members that the
// patterns match, as DeleteMembers does. The paths come in index order.
func PlanDelete(cfg DeleteConfig, plan PlanFunc) (Stats, error) {
	var stats Stats
	if len(cfg.Patterns) == 0 && len(cfg.Regex) == 0 {
		return stats, errors.New("--delete needs at least one pattern or -R")
	}
	r, err := OpenWith(cfg.Archive, cfg.Open)
	if err != nil {
		return stats, err
	}
	defer r.Close()

	deleted, err := selectMembers(r.Members(), cfg.Patterns, cfg.Regex)
	if err != nil {
		return stats, err
	}
	for i := range deleted {
		m := &deleted[i]
		p := Planned{Path: m.Path}
		if m.Type == format.TypeReg {
			p.Size = m.Size
		}
		stats.Members++
		stats.Bytes += p.Size
		plan(p)
	}
	return stats, nil
}
