package archive

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/philmalin/eictar/src/internal/meta"
)

// ErrUnsafeLink means -f names a path through a symbolic link that the
// program does not follow (doc/Security_Audit.eml, finding 4).
var ErrUnsafeLink = errors.New("a symbolic link that another user planted in a shared directory")

// ErrUnsafeTarget means that the program does not replace the file at -f:
// another user owns it in a directory that everyone can write, or the file
// changed while the program opened it (doc/Security_Audit_Pass_2.eml,
// findings 15 and 17).
var ErrUnsafeTarget = errors.New("the program does not replace this file")

// mayFollowLink is the rule of fs.protected_symlinks. A test replaces it, to
// refuse a link without a link of another user, which only root can make.
var mayFollowLink = meta.MayFollow

// effectiveUID is os.Geteuid. A test replaces it, to see a file of its own
// as the file of another user.
var effectiveUID = os.Geteuid

// targetMode is the mode that the new file of a create gets.
type targetMode struct {
	perm fs.FileMode
	// keep: the new file gets perm. limit: the new file gets the bits that
	// are both in perm and in the mode of a new file (0666 less the umask).
	// Neither: the mode of a new file.
	keep, limit bool
}

// createTarget resolves where a new archive goes, and the mode it gets. When
// a file is there, it gives that file open and locked: the guard, which
// keeps a create from a rename over a file that another run appends to.
//
// A symbolic link is followed, so that the rename replaces the file and keeps
// the link (resolveArchive). A file of the caller lends its permissions to
// the new one: replacing a 0600 archive with a 0644 one would be a silent
// change of who can read it. The file of another user does not: its mode
// only limits the mode of a new file (finding 17).
//
// The guard is the file that Lstat found at the resolved path. A link or
// another file put there between the two is refused, so the mode and the
// lock come from the file that the rename replaces.
func createTarget(path string) (string, archiveFile, targetMode, error) {
	target, err := resolveArchive(path)
	if err != nil {
		return "", nil, targetMode{}, err
	}
	before, err := os.Lstat(target)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return target, nil, targetMode{}, nil
	case err != nil:
		return "", nil, targetMode{}, fmt.Errorf("stat %s: %w", path, err)
	case !before.Mode().IsRegular():
		return "", nil, targetMode{}, fmt.Errorf("%s exists and is not a regular file", path)
	}
	pinIdentity(before) // on Windows, before the open, or the check sees the file there after it
	guard, err := fsys.OpenArchive(target, os.O_RDONLY)
	if errors.Is(err, fs.ErrNotExist) {
		return target, nil, targetMode{}, nil // removed since: the rename must not replace a new one
	}
	if err != nil {
		return "", nil, targetMode{}, fmt.Errorf("opening %s: %w", target, err)
	}
	fail := func(err error) (string, archiveFile, targetMode, error) {
		guard.Close()
		return "", nil, targetMode{}, err
	}
	opened, err := guard.Stat()
	if err != nil {
		return fail(fmt.Errorf("stat %s: %w", target, err))
	}
	if err := openedAsSeen(target, before, opened); err != nil {
		return fail(err)
	}
	mode, err := inheritedMode(target, opened)
	if err != nil {
		return fail(err)
	}
	if err := lockArchive(guard, target); err != nil {
		return fail(err)
	}
	return target, guard, mode, nil
}

// openedAsSeen checks that opened, the file that an open of path gave, is
// before, the file that Lstat found at path before the open. A link or
// another file put at path between the two is refused. On Windows, before
// must have its identity from before the open (pinIdentity): os.SameFile
// reads it from the path the first time that it needs it, and then it is
// the identity of the file that the open found.
func openedAsSeen(path string, before, opened fs.FileInfo) error {
	if before == nil || !before.Mode().IsRegular() || !os.SameFile(before, opened) {
		return fmt.Errorf("%s: %w: it changed while the program opened it", path, ErrUnsafeTarget)
	}
	return nil
}

// inheritedMode gives the mode of a new file that replaces fi, the file at
// target.
func inheritedMode(target string, fi fs.FileInfo) (targetMode, error) {
	mode := targetMode{perm: fi.Mode().Perm()}
	owner := meta.Stat(fi)
	if !owner.OK {
		mode.keep = true // the platform gives no owner (Windows)
		return mode, nil
	}
	dir := filepath.Dir(target)
	di, err := os.Stat(dir)
	if err != nil {
		return targetMode{}, fmt.Errorf("stat %s: %w", dir, err)
	}
	dirOwner := meta.Stat(di)
	switch replaceRule(owner.UID, dirOwner.UID, uint32(effectiveUID()), di.Mode(), dirOwner.OK) {
	case replaceRefuse:
		return targetMode{}, fmt.Errorf("%s: %w: another user owns it, in a directory that everyone can write",
			target, ErrUnsafeTarget)
	case replaceKeep:
		mode.keep = true
	default:
		mode.limit = true
	}
	return mode, nil
}

// The results of replaceRule.
const (
	replaceKeep   = iota // the new file gets the mode of the old one
	replaceLimit         // the mode of the old one limits the mode of a new file
	replaceRefuse        // the old file is not replaced
)

// replaceRule decides how a create treats a file that it replaces: a file of
// fileUID, in a directory of dirUID with dirMode, for the caller euid.
//
// The caller's own file gives its mode. In a sticky directory that everyone
// can write, a file that neither the caller nor the owner of the directory
// owns is refused, as the kernel refuses an open with O_CREAT of it under
// fs.protected_regular. tar gets EACCES there. Any other file of another
// user only limits the mode: a 0666 file that another user put at -f does
// not make root's archive 0666, and root's archive in the home of a user
// does not get wider than the 0600 of the old one.
func replaceRule(fileUID, dirUID, euid uint32, dirMode fs.FileMode, dirOK bool) int {
	switch {
	case fileUID == euid:
		return replaceKeep
	case dirMode&fs.ModeSticky != 0 && dirMode.Perm()&0o002 != 0 && (!dirOK || fileUID != dirUID):
		return replaceRefuse
	}
	return replaceLimit
}

// createTemp opens a new file beside target, with the mode that mode gives.
func createTemp(target string, mode targetMode) (archiveFile, os.FileInfo, string, error) {
	dir, base := filepath.Split(target)
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, nil, "", fmt.Errorf("generating a temporary name: %w", err)
	}
	tmpPath := filepath.Join(dir, fmt.Sprintf(".%s.create-%x", base, b))

	// 0666 through open(2), not os.CreateTemp's 0600, so that the umask
	// decides the mode of a new archive exactly as it would for os.Create.
	f, err := fsys.CreateNew(tmpPath, 0o666)
	if err != nil {
		return nil, nil, "", fmt.Errorf("creating %s: %w", target, err)
	}
	fail := func(err error) (archiveFile, os.FileInfo, string, error) {
		f.Close()
		fsys.Remove(tmpPath)
		return nil, nil, "", err
	}
	self, err := f.Stat()
	if err != nil {
		return fail(fmt.Errorf("stat %s: %w", target, err))
	}
	if mode.keep || mode.limit {
		perm := mode.perm
		if mode.limit {
			perm &= self.Mode().Perm()
		}
		if err := f.Chmod(perm); err != nil {
			return fail(fmt.Errorf("setting the mode of %s: %w", target, err))
		}
	}
	return f, self, tmpPath, nil
}
