// Package fsutil holds the path rules shared by the writer and the extractor.
//
// The two are separate on purpose. StorePath decides what a path looks like
// inside an archive, and is applied when writing. SafeJoin decides where a
// member may land on extraction, and is applied when reading - including to
// archives this program did not write, which is the case that matters.
package fsutil

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// ErrUnsafePath means a member path would escape the destination directory.
var ErrUnsafePath = errors.New("unsafe member path")

// RootPath is the member path of the archived tree's own root, used when
// stripping leaves nothing behind (archiving "/" itself, say).
const RootPath = "."

// StorePath converts a filesystem path into the form stored in the index:
// slash-separated, relative, cleaned, with no leading "/" and no leading ".."
// component.
//
// The stripped result reports whether anything was removed, so the caller can
// warn once per run the way tar does ("Removing leading '/' from member
// names") rather than once per file.
//
// This follows tar, zip and pax: an archive holds a portable tree, not a set
// of filesystem locations, so /etc/passwd is stored as etc/passwd and unpacks
// under the destination rather than over the system. Unlike tar, there is no
// option to turn this off; see doc/design.md 7.
//
// On Windows, the volume name is removed too, as tar does: C:\Users\a.txt
// and \\server\share\a.txt are stored as Users/a.txt and a.txt. On other
// platforms, VolumeName is always empty.
func StorePath(p string) (stored string, stripped bool, err error) {
	if p == "" {
		return "", false, fmt.Errorf("%w: empty path", ErrUnsafePath)
	}
	if v := volumeName(p); v != "" {
		p = p[len(v):]
		stripped = true
	}

	s := path.Clean(filepath.ToSlash(p))

	// Clean has already collapsed interior ".." and repeated separators. What
	// can remain is a leading "/" or a run of leading "../".
	if strings.HasPrefix(s, "/") {
		s = strings.TrimLeft(s, "/")
		stripped = true
	}
	for s == ".." || strings.HasPrefix(s, "../") {
		s = strings.TrimPrefix(strings.TrimPrefix(s, ".."), "/")
		stripped = true
	}

	if s == "" || s == "." {
		// The path named the tree root itself: "/", "..", or ".".
		return RootPath, stripped, nil
	}
	if !IsStoredPath(s) {
		// Unreachable by construction; a belt-and-braces check, because a bug
		// here writes an archive that our own extractor must refuse.
		return "", stripped, fmt.Errorf("%w: %q normalised to %q", ErrUnsafePath, p, s)
	}
	return s, stripped, nil
}

// volumeName is filepath.VolumeName, except for a path that starts with three
// or more separators. Windows reads ///etc as the share etc, but the writer
// treats the path as /etc, as on Unix.
func volumeName(p string) string {
	if len(p) > 2 && os.IsPathSeparator(p[0]) && os.IsPathSeparator(p[1]) && os.IsPathSeparator(p[2]) {
		return ""
	}
	return filepath.VolumeName(p)
}

// IsStoredPath reports whether s is in the canonical stored form: relative,
// slash-separated, and free of "." and ".." components.
func IsStoredPath(s string) bool {
	if s == "" || strings.HasPrefix(s, "/") {
		return false
	}
	if s == RootPath {
		return true
	}
	for _, part := range strings.Split(s, "/") {
		switch part {
		case "", ".", "..":
			return false
		}
	}
	return true
}

// SafeJoin resolves a member path against a destination directory, refusing
// anything that would land outside it.
//
// It is applied to every member on extraction, including members written by
// this program: an archive is untrusted input whoever made it, and the whole
// point of the check is the archive that was crafted to escape.
//
// The check here is lexical. It stops "../etc/passwd" and "/etc/passwd"; it
// does not stop a destination path whose own components are symlinks planted
// earlier in the same extraction. That needs per-component checking as
// directories are created, which lands with extraction in M2.
func SafeJoin(dest, member string) (string, error) {
	if member == "" {
		return "", fmt.Errorf("%w: empty member path", ErrUnsafePath)
	}
	if path.IsAbs(member) || filepath.IsAbs(member) {
		return "", fmt.Errorf("%w: %q is absolute", ErrUnsafePath, member)
	}
	if !IsStoredPath(member) {
		return "", fmt.Errorf("%w: %q is not in canonical stored form", ErrUnsafePath, member)
	}
	if member == RootPath {
		return filepath.Clean(dest), nil
	}

	cleanDest := filepath.Clean(dest)
	joined := filepath.Join(cleanDest, filepath.FromSlash(member))

	// Join cleans its result, so an escape shows up as a path that is no
	// longer under the destination.
	if joined != cleanDest && !strings.HasPrefix(joined, cleanDest+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: %q escapes %q", ErrUnsafePath, member, dest)
	}
	return joined, nil
}
