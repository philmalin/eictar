package testutil

import (
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// fillSys records what Windows has of the Unix metadata. It has no owner as
// a number, no extended attributes of the user namespace, and no count of
// allocated blocks, so each file counts as dense.
func fillSys(e *Entry, _ string, fi os.FileInfo) {
	e.Blocks = (fi.Size() + 511) / 512
}

// SetLinkTimes sets a symbolic link's own times, not its target's.
func (t *Tree) SetLinkTimes(rel string, atime, mtime time.Time) *Tree {
	t.tb.Helper()
	name, err := windows.UTF16PtrFromString(t.Path(rel))
	if err != nil {
		t.tb.Fatalf("testutil: setting link times on %s: %v", rel, err)
	}
	h, err := windows.CreateFile(name, windows.FILE_WRITE_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.tb.Fatalf("testutil: setting link times on %s: %v", rel, err)
	}
	defer windows.CloseHandle(h)
	a, m := windows.NsecToFiletime(atime.UnixNano()), windows.NsecToFiletime(mtime.UnixNano())
	if err := windows.SetFileTime(h, nil, &a, &m); err != nil {
		t.tb.Fatalf("testutil: setting link times on %s: %v", rel, err)
	}
	return t
}

// Holes reports false: Sparse writes a dense file on Windows, because a file
// has holes there only after FSCTL_SET_SPARSE.
func (t *Tree) Holes(string) bool { return false }
