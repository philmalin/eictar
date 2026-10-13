//go:build linux || darwin || freebsd

package meta

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// fakeSeek answers SEEK_DATA and SEEK_HOLE for a file of size bytes whose
// data is in regions, which are in order. fail, when it is set, gives the
// error of a call by its whence.
type fakeSeek struct {
	regions []Segment
	size    int64
	fail    map[int]error
	calls   int
}

func (s *fakeSeek) seek(fd int, off int64, whence int) (int64, error) {
	s.calls++
	if err := s.fail[whence]; err != nil {
		return 0, err
	}
	switch whence {
	case unix.SEEK_DATA:
		for _, r := range s.regions {
			if off < r.Offset+r.Length {
				return max(off, r.Offset), nil
			}
		}
		return 0, unix.ENXIO
	case unix.SEEK_HOLE:
		for _, r := range s.regions {
			if off >= r.Offset && off < r.Offset+r.Length {
				return r.Offset + r.Length, nil
			}
		}
		return max(off, s.size), nil
	}
	return 0, nil
}

// TestDataSegmentsLogic: what DataSegments makes of the answers of the
// file system, for the shapes that a real file system gives rarely or never.
func TestDataSegmentsLogic(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "f"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	saved := seek
	t.Cleanup(func() { seek = saved })
	seg := func(off, n int64) Segment { return Segment{Offset: off, Length: n} }

	for _, tc := range []struct {
		name    string
		fs      fakeSeek
		blocks  int64
		segs    []Segment
		sparse  bool
		err     string
		noCalls bool
	}{
		{name: "empty", fs: fakeSeek{size: 0}, noCalls: true},
		{name: "all the blocks", fs: fakeSeek{size: 1024}, blocks: 2, noCalls: true},
		{name: "one byte short of the blocks", fs: fakeSeek{regions: []Segment{seg(0, 10)}, size: 1025}, blocks: 2,
			segs: []Segment{seg(0, 10)}, sparse: true},
		{name: "two regions", fs: fakeSeek{regions: []Segment{seg(0, 10), seg(500, 10)}, size: 1000},
			segs: []Segment{seg(0, 10), seg(500, 10)}, sparse: true},
		{name: "data at the end", fs: fakeSeek{regions: []Segment{seg(990, 10)}, size: 1000},
			segs: []Segment{seg(990, 10)}, sparse: true},
		{name: "a region past a hole at the end", fs: fakeSeek{regions: []Segment{seg(990, 50)}, size: 1000},
			segs: []Segment{seg(990, 10)}, sparse: true},
		{name: "data that starts at the size", fs: fakeSeek{regions: []Segment{seg(0, 10), seg(1000, 10)}, size: 1000},
			segs: []Segment{seg(0, 10)}, sparse: true},
		{name: "no data", fs: fakeSeek{size: 1000}, sparse: true},
		{name: "data in all of it", fs: fakeSeek{regions: []Segment{seg(0, 1000)}, size: 1000}},
		{name: "no SEEK_DATA", fs: fakeSeek{size: 1000, fail: map[int]error{unix.SEEK_DATA: unix.EINVAL}}},
		{name: "not supported", fs: fakeSeek{size: 1000, fail: map[int]error{unix.SEEK_DATA: unix.EOPNOTSUPP}}},
		{name: "a fault of SEEK_DATA", fs: fakeSeek{size: 1000, fail: map[int]error{unix.SEEK_DATA: unix.EIO}}, err: "finding data"},
		{name: "a fault of SEEK_HOLE", fs: fakeSeek{regions: []Segment{seg(0, 10)}, size: 1000, fail: map[int]error{unix.SEEK_HOLE: unix.EIO}}, err: "finding a hole"},
		{name: "a fault of the rewind", fs: fakeSeek{regions: []Segment{seg(0, 10)}, size: 1000, fail: map[int]error{0: unix.EIO}}, err: "rewinding"},
	} {
		fs := tc.fs
		seek = fs.seek
		segs, sparse, err := DataSegments(f, fs.size, tc.blocks)
		switch {
		case tc.err != "":
			if err == nil || !strings.Contains(err.Error(), tc.err) || !errors.Is(err, unix.EIO) {
				t.Errorf("%s: %v, want %q", tc.name, err, tc.err)
			}
		case err != nil || sparse != tc.sparse || !slices.Equal(segs, tc.segs):
			t.Errorf("%s: %v, %v, %v; want %v, %v", tc.name, segs, sparse, err, tc.segs, tc.sparse)
		}
		if tc.noCalls && fs.calls != 0 {
			t.Errorf("%s: %d calls; want none, from the count of blocks", tc.name, fs.calls)
		}
	}
}

// reportsHoles reports whether the file system gives a hole in f before
// size, by SEEK_HOLE itself.
func reportsHoles(f *os.File, size int64) bool {
	hole, err := unix.Seek(int(f.Fd()), 0, unix.SEEK_HOLE)
	unix.Seek(int(f.Fd()), 0, 0)
	return err == nil && hole < size
}
