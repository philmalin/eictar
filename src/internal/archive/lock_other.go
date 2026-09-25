//go:build (!unix && !windows) || aix

package archive

import "os"

// lockFile does nothing on a platform with no flock (Plan 9, WASI, AIX).
// Two writers there are not detected; doc/design.md 9.6 says so.
func lockFile(*os.File) error { return nil }
