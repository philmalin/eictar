//go:build !(linux || darwin || freebsd)

package meta

import "os"

// reportsHoles is false where DataSegments does not use SEEK_HOLE.
func reportsHoles(*os.File, int64) bool { return false }
