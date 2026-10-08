package archive

// syncDir does nothing on Windows. Windows cannot sync a directory: Sync on
// a directory that os.Open opened gives "Access is denied". NTFS records a
// rename in its journal, and writes the journal to the disk itself.
func syncDir(string) error { return nil }
