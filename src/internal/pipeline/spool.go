package pipeline

import (
	"fmt"
	"io"
	"os"
)

// Spool accumulates one member's encoded payload until the writer is ready
// for it.
//
// It keeps the bytes in memory up to a threshold and moves to a temporary
// file past it. A member's blob must be contiguous in the archive, so the
// writer cannot start it until the whole thing exists; without the spill, one
// large member would decide the program's memory footprint.
//
// A Spool is used by one goroutine at a time: the worker that fills it, then
// the writer that drains it.
type Spool struct {
	budget    *Budget
	threshold int64
	dir       string

	buf      []byte
	file     *os.File
	reserved int64 // bytes currently held against the budget
	size     int64
}

// NewSpool returns a spool that spills into dir past threshold bytes.
func NewSpool(budget *Budget, threshold int64, dir string) *Spool {
	return &Spool{budget: budget, threshold: threshold, dir: dir}
}

// Write appends to the spool, spilling to disk if the threshold is crossed.
func (s *Spool) Write(p []byte) (int, error) {
	if s.file != nil {
		n, err := s.file.Write(p)
		s.size += int64(n)
		return n, err
	}

	// Two reasons to move to disk: this member is large enough to be worth a
	// file, or memory is tight right now. The second is what keeps a spool
	// from waiting on a budget that only it could release.
	overThreshold := int64(len(s.buf)+len(p)) > s.threshold
	if overThreshold || !s.budget.TryAcquire(int64(len(p))) {
		if err := s.spill(); err != nil {
			return 0, err
		}
		n, err := s.file.Write(p)
		s.size += int64(n)
		return n, err
	}
	s.reserved += int64(len(p))

	s.buf = append(s.buf, p...)
	s.size += int64(len(p))
	return len(p), nil
}

// spill moves what is buffered into a temporary file and hands the memory
// back to the budget.
func (s *Spool) spill() error {
	f, err := os.CreateTemp(s.dir, ".eictar-spool-*")
	if err != nil {
		return fmt.Errorf("pipeline: creating spill file: %w", err)
	}
	// Unlink now: the file stays usable through the descriptor and cannot be
	// left behind by a crash.
	if err := os.Remove(f.Name()); err != nil {
		f.Close()
		return fmt.Errorf("pipeline: unlinking spill file: %w", err)
	}

	if len(s.buf) > 0 {
		if _, err := f.Write(s.buf); err != nil {
			f.Close()
			return fmt.Errorf("pipeline: spilling: %w", err)
		}
	}

	s.file = f
	s.buf = nil
	s.budget.Release(s.reserved)
	s.reserved = 0
	return nil
}

// Spill moves the spool to disk now, if it is still in memory, and gives its
// memory back to the budget.
func (s *Spool) Spill() error {
	if s.file != nil {
		return nil
	}
	return s.spill()
}

// Size is the number of bytes spooled so far.
func (s *Spool) Size() int64 { return s.size }

// Spilled reports whether the spool moved to disk.
func (s *Spool) Spilled() bool { return s.file != nil }

// WriteTo drains the spool into w. It may be called once.
func (s *Spool) WriteTo(w io.Writer) (int64, error) {
	if s.file == nil {
		n, err := w.Write(s.buf)
		return int64(n), err
	}
	if _, err := s.file.Seek(0, io.SeekStart); err != nil {
		return 0, fmt.Errorf("pipeline: rewinding spill file: %w", err)
	}
	return io.Copy(w, s.file)
}

// Close releases the spool's memory and its spill file. It is safe to call
// more than once.
func (s *Spool) Close() error {
	s.buf = nil
	if s.reserved > 0 {
		s.budget.Release(s.reserved)
		s.reserved = 0
	}
	if s.file != nil {
		err := s.file.Close()
		s.file = nil
		return err
	}
	return nil
}
