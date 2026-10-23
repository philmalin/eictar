package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/philmalin/eictar/src/internal/archive"
	"github.com/philmalin/eictar/src/internal/format"
)

// runDiff is --diff (doc/design.md 9.8): it compares the archive with the
// tree on disk, and changes nothing. --diff-extract (doc/design.md 9.10) also
// extracts each member into a scratch directory, and compares the copy with
// the disk.
func runDiff(o *Options, stdout, stderr io.Writer) error {
	extract := o.Op == OpDiffExtract
	exclude, err := gatherExcludes(o)
	if err != nil {
		return err
	}
	base, err := createBaseDir(o)
	if err != nil {
		return err
	}
	rep := &reporter{out: stdout, errOut: stderr, verbose: o.Verbose, quiet: o.Quiet}
	progress, done := withProgress(o, rep, stderr)
	res, err := archive.DiffArchive(archive.DiffConfig{
		Archive:       o.Archive,
		BaseDir:       base,
		Patterns:      o.Args,
		Exclude:       exclude,
		Regex:         o.regex,
		ExcludeRegex:  o.excludeRegex,
		Dereference:   o.Dereference,
		OneFileSystem: o.OneFileSystem,

		StripComponents: o.StripComponents,
		Metadata: archive.MetadataOptions{
			NoOwner: o.NoOwner, NoXattrs: o.NoXattrs, NoACLs: o.NoACLs,
		},
		Open:      openFor(o, rep),
		Workers:   o.Workers,
		KeepGoing: o.KeepGoing,
		Reporter:  progress,

		Extract:     extract,
		ScratchDir:  o.ScratchDir,
		MemoryLimit: int64(o.MemoryLimit),
	})
	done()
	if err != nil {
		return err
	}

	// The differences are the result of the operation, so -q does not hide
	// them, as it does not hide the damage that --verify finds.
	show := namesFor(stdout)
	for _, d := range res.Differences {
		fmt.Fprintln(stdout, differenceLine(d, show))
	}
	switch {
	case res.Damaged > 0:
		// Under --keep-going, damage found by a decode is still damage,
		// as for --verify (doc/design.md 9.10).
		return fmt.Errorf("%d members of the archive did not decode: %w", res.Damaged, format.ErrCorruptData)
	case res.Failed > 0:
		return &partialError{failed: res.Failed}
	case res.Paths > 0:
		return &differError{paths: res.Paths}
	case res.Collided > 0:
		return &collisionError{collided: res.Collided}
	}
	if !o.Quiet {
		how := "compared"
		if extract {
			how = "extracted and compared"
		}
		fmt.Fprintf(stdout, "%s: no differences, %d members %s\n", o.Archive, res.Compared, how)
	}
	return nil
}

// differenceLine renders one difference: the path, what differs, and the
// value in the archive and on disk where there is a short one. show is how a
// name is shown (namesFor). A link target is quoted, which escapes it.
func differenceLine(d archive.Difference, show func(string) string) string {
	d.Path = show(d.Path)
	if d.Kind == archive.DiffHardlink {
		d.Archive = show(d.Archive)
	}
	names := make([]string, len(d.Names))
	for i, n := range d.Names {
		names[i] = show(n)
	}
	d.Names = names
	if d.Extracted {
		return copyLine(d)
	}
	what := map[string]string{
		archive.DiffType:   "type differs",
		archive.DiffSize:   "size differs",
		archive.DiffLink:   "link target differs",
		archive.DiffDevice: "device numbers differ",
		archive.DiffMode:   "mode differs",
		archive.DiffOwner:  "owner differs",
		archive.DiffMTime:  "mtime differs",
	}
	switch d.Kind {
	case archive.DiffMissing:
		return d.Path + ": not on disk"
	case archive.DiffExtra:
		return d.Path + ": not in the archive"
	case archive.DiffContent:
		return d.Path + ": content differs"
	case archive.DiffHardlink:
		return fmt.Sprintf("%s: not a hardlink of %s", d.Path, d.Archive)
	case archive.DiffXattrs:
		return fmt.Sprintf("%s: extended attributes differ: %s", d.Path, strings.Join(d.Names, ", "))
	case archive.DiffACLs:
		return fmt.Sprintf("%s: ACLs differ: %s", d.Path, strings.Join(d.Names, ", "))
	case archive.DiffLink:
		return fmt.Sprintf("%s: %s: archive %q, disk %q", d.Path, what[d.Kind], d.Archive, d.Disk)
	}
	return fmt.Sprintf("%s: %s: archive %s, disk %s", d.Path, what[d.Kind], d.Archive, d.Disk)
}

// copyLine renders a difference between the disk and the copy that
// --diff-extract extracted, with the value of the source on disk and of the
// copy. Its path and names are already shown as differenceLine shows them.
func copyLine(d archive.Difference) string {
	what := map[string]string{
		archive.DiffSize:   "size differs",
		archive.DiffLink:   "link target differs",
		archive.DiffDevice: "device numbers differ",
		archive.DiffMode:   "mode differs",
		archive.DiffOwner:  "owner differs",
		archive.DiffMTime:  "mtime differs",
	}
	switch d.Kind {
	case archive.DiffContent:
		return fmt.Sprintf("%s: content differs after extraction, at byte %d", d.Path, d.Offset)
	case archive.DiffXattrs:
		return fmt.Sprintf("%s: extended attributes differ after extraction: %s", d.Path, strings.Join(d.Names, ", "))
	case archive.DiffACLs:
		return fmt.Sprintf("%s: ACLs differ after extraction: %s", d.Path, strings.Join(d.Names, ", "))
	case archive.DiffLink:
		return fmt.Sprintf("%s: %s after extraction: source %q, extracted %q", d.Path, what[d.Kind], d.Disk, d.Archive)
	}
	return fmt.Sprintf("%s: %s after extraction: source %s, extracted %s", d.Path, what[d.Kind], d.Disk, d.Archive)
}

// differError reports that the archive and the disk differ. As for diff(1)
// and tar -d, that is exit code 1.
type differError struct{ paths int }

func (e *differError) Error() string {
	if e.paths == 1 {
		return "1 path differs between the archive and the disk"
	}
	return fmt.Sprintf("%d paths differ between the archive and the disk", e.paths)
}
