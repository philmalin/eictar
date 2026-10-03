package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/philmalin/eictar/src/internal/archive"
)

// runDiff is --diff (doc/design.md 9.8): it compares the archive with the
// tree on disk, and changes nothing.
func runDiff(o *Options, stdout, stderr io.Writer) error {
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
		Metadata: archive.MetadataOptions{
			NoOwner: o.NoOwner, NoXattrs: o.NoXattrs, NoACLs: o.NoACLs,
		},
		Open:      openFor(o, rep),
		Workers:   o.Workers,
		KeepGoing: o.KeepGoing,
		Reporter:  progress,
	})
	done()
	if err != nil {
		return err
	}

	// The differences are the result of the operation, so -q does not hide
	// them, as it does not hide the damage that --verify finds.
	for _, d := range res.Differences {
		fmt.Fprintln(stdout, differenceLine(d))
	}
	switch {
	case res.Failed > 0:
		return &partialError{failed: res.Failed}
	case res.Paths > 0:
		return &differError{paths: res.Paths}
	}
	if !o.Quiet {
		fmt.Fprintf(stdout, "%s: no differences, %d members compared\n", o.Archive, res.Compared)
	}
	return nil
}

// differenceLine renders one difference: the path, what differs, and the
// value in the archive and on disk where there is a short one.
func differenceLine(d archive.Difference) string {
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

// differError reports that the archive and the disk differ. As for diff(1)
// and tar -d, that is exit code 1.
type differError struct{ paths int }

func (e *differError) Error() string {
	if e.paths == 1 {
		return "1 path differs between the archive and the disk"
	}
	return fmt.Sprintf("%d paths differ between the archive and the disk", e.paths)
}
