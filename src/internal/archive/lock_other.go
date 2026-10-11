//go:build (!unix && !windows) || aix

package archive

// lockFile does nothing on a platform with no flock (Plan 9, WASI, AIX).
// Two writers there are not detected; doc/design.md 9.6 says so.
func lockFile(archiveFile) error { return nil }
