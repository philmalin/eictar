package archive

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// resolveArchive gives the path of the file that -f names, with each link
// resolved. Windows has no rule as fs.protected_symlinks: mayFollowLink
// allows each link there, so neither the race of finding 15 nor the link
// inside a link target of finding 16 (doc/Security_Audit_Pass_2.eml) gives
// an attacker a path. The parts of the path as the user typed it get the
// rule all the same, as a test replaces it; then filepath.EvalSymlinks
// resolves the path, which also knows junctions and the other reparse
// points. A path that does not exist is given as it is.
func resolveArchive(path string) (string, error) {
	if err := checkLinks(path); err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(path)
	switch {
	case err == nil:
		return resolved, nil
	case errors.Is(err, fs.ErrNotExist):
		return path, nil
	}
	return "", fmt.Errorf("resolving %s: %w", path, err)
}

// checkLinks applies mayFollowLink to each part of path that is a link.
func checkLinks(path string) error {
	clean := filepath.Clean(path)
	// The walk starts at the root of the path: the volume and a separator
	// (C:\). A separator alone made \C:, which is no path, and the walk
	// stopped there.
	prefix := filepath.VolumeName(clean)
	rest := clean[len(prefix):]
	if sep := string(filepath.Separator); strings.HasPrefix(rest, sep) {
		prefix += sep
		rest = rest[len(sep):]
	}
	for _, part := range strings.Split(rest, string(filepath.Separator)) {
		prefix = filepath.Join(prefix, part)
		fi, err := os.Lstat(prefix)
		if err != nil {
			return nil // what does not exist is not a link; the caller reports it
		}
		if fi.Mode()&os.ModeSymlink != 0 && !mayFollowLink(prefix, fi) {
			return fmt.Errorf("%s: %w; the program does not follow it", prefix, ErrUnsafeLink)
		}
	}
	return nil
}
