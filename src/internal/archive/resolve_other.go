//go:build !windows

package archive

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// maxLinks is the number of symbolic links that resolveArchive follows in one
// path, as the kernel does (MAXSYMLINKS).
const maxLinks = 40

// readLink is os.Readlink. A test replaces it: a link that Lstat found and
// that cannot be read is a link that another process removed in between.
var readLink = os.Readlink

// resolveArchive gives the path of the file that -f names, with each symbolic
// link resolved. It refuses a link that the kernel would not follow for
// open(2) under fs.protected_symlinks, also a link inside the target of
// another link (doc/Security_Audit_Pass_2.eml, finding 16).
//
// The check and the resolution are one pass: each link that the pass follows
// is the link that it checked. A check first and filepath.EvalSymlinks after
// let a link that appeared between the two go through with no check, and the
// rename replaced its target (finding 15).
//
// The last name can be missing: then the result names a file that does not
// exist yet, and what does not exist is not a link. A directory of the path
// that is missing is an error, as it is for open(2).
func resolveArchive(path string) (string, error) {
	done := "" // the resolved part, which has no link in it
	if filepath.IsAbs(path) {
		done = string(filepath.Separator)
	}
	rest := splitPath(path)
	links := 0
	for len(rest) > 0 {
		name := rest[0]
		rest = rest[1:]
		// done has no link in it, so the text of ".." gives its parent, as
		// Join cleans it. Join also keeps the root: "/.." is "/".
		next := filepath.Join(done, name)
		fi, err := os.Lstat(next)
		if errors.Is(err, fs.ErrNotExist) && len(rest) == 0 {
			return next, nil
		}
		if err != nil {
			return "", fmt.Errorf("resolving %s: %w", path, err)
		}
		if fi.Mode()&fs.ModeSymlink == 0 {
			done = next
			continue
		}
		if !mayFollowLink(next, fi) {
			return "", fmt.Errorf("%s: %w; the program does not follow it", next, ErrUnsafeLink)
		}
		if links++; links > maxLinks {
			return "", fmt.Errorf("resolving %s: %w", path, syscall.ELOOP)
		}
		to, err := readLink(next)
		if err != nil {
			return "", fmt.Errorf("resolving %s: %w", path, err)
		}
		if filepath.IsAbs(to) {
			done = string(filepath.Separator)
		}
		rest = append(splitPath(to), rest...)
	}
	if done == "" {
		return ".", nil
	}
	return done, nil
}

// splitPath gives the names of path, without the empty ones and ".".
func splitPath(path string) []string {
	var names []string
	for _, name := range strings.Split(path, string(filepath.Separator)) {
		if name != "" && name != "." {
			names = append(names, name)
		}
	}
	return names
}
