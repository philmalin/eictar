//go:build netbsd || openbsd

package meta

import "os"

// DataSegments reports every file as dense: the platform has no SEEK_DATA.
// The whole file is read and stored, which is correct, only larger for a
// file with holes (doc/design.md 15.1).
func DataSegments(*os.File, int64, int64) ([]Segment, bool, error) { return nil, false, nil }
