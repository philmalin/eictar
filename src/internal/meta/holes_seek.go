//go:build linux || darwin || freebsd

package meta

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// DataSegments returns the data regions of a file that has holes, or nil for
// a dense file.
//
// It uses SEEK_DATA and SEEK_HOLE. A filesystem without them reports the
// whole file as data, which comes out as dense, which is correct. The file
// offset is left at 0.
func DataSegments(f *os.File, size int64, blocks int64) ([]Segment, bool, error) {
	// The cheap test first: a file with as many blocks as bytes need has no
	// holes, and most files are like that.
	if size == 0 || blocks*512 >= size {
		return nil, false, nil
	}

	fd := int(f.Fd())
	var segs []Segment
	var total int64
	for off := int64(0); off < size; {
		data, err := unix.Seek(fd, off, unix.SEEK_DATA)
		if errors.Is(err, unix.ENXIO) {
			break // no data after off: the rest is a hole
		}
		if err != nil {
			if errors.Is(err, unix.EINVAL) || isUnsupported(err) {
				return nil, false, nil
			}
			return nil, false, fmt.Errorf("finding data: %w", err)
		}
		if data >= size {
			break
		}
		hole, err := unix.Seek(fd, data, unix.SEEK_HOLE)
		if err != nil {
			return nil, false, fmt.Errorf("finding a hole: %w", err)
		}
		if hole > size {
			hole = size
		}
		segs = append(segs, Segment{Offset: data, Length: hole - data})
		total += hole - data
		off = hole
	}
	if _, err := unix.Seek(fd, 0, 0); err != nil {
		return nil, false, fmt.Errorf("rewinding: %w", err)
	}

	if total >= size {
		return nil, false, nil
	}
	return segs, true, nil
}
