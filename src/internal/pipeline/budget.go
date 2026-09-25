// Package pipeline holds the concurrency machinery for building an archive:
// a memory budget, spill buffers, and a worker pool that compresses chunks
// while a single goroutine owns the output file (doc/design.md 8).
package pipeline

import (
	"fmt"
	"sync"
)

// Budget is a counting semaphore over bytes.
//
// It is what stops a worker pool from reading the whole input into memory: a
// worker acquires before it allocates and releases once the bytes have been
// written out, so the total in flight is bounded however many workers there
// are and however large the inputs.
type Budget struct {
	mu    sync.Mutex
	cond  *sync.Cond
	limit int64
	used  int64
}

// NewBudget returns a budget of limit bytes. A limit of zero or less means
// unlimited, which is useful in tests and for a single-threaded run where the
// in-flight set is one chunk.
func NewBudget(limit int64) *Budget {
	b := &Budget{limit: limit}
	b.cond = sync.NewCond(&b.mu)
	return b
}

// Acquire blocks until n bytes are available, then reserves them.
//
// A request larger than the whole budget can never be satisfied by waiting, so
// it is let through immediately: the alternative is a deadlock on a chunk size
// the user chose. The budget is backpressure, not a hard ceiling.
//
// The caller must not hold a reservation while calling this. Everything that
// could block here - reading the next chunk - releases first; everything that
// holds a reservation for longer - a spool - uses TryAcquire and spills
// instead of waiting.
func (b *Budget) Acquire(n int64) {
	if b.limit <= 0 || n <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	if n > b.limit {
		b.used += n
		return
	}
	for b.used+n > b.limit {
		b.cond.Wait()
	}
	b.used += n
}

// TryAcquire reserves n bytes if they are available, and reports whether it
// did. It never blocks.
//
// This is what a spool uses: a buffer that waited for memory it alone could
// release would deadlock against itself, and the right answer under memory
// pressure is to spill to disk rather than to wait.
func (b *Budget) TryAcquire(n int64) bool {
	if b.limit <= 0 || n <= 0 {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.used+n > b.limit {
		return false
	}
	b.used += n
	return true
}

// Release returns n bytes to the budget.
func (b *Budget) Release(n int64) {
	if b.limit <= 0 || n <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	b.used -= n
	if b.used < 0 {
		// A release without a matching acquire is a bug in the caller, and a
		// silently negative budget would mask it for the rest of the run.
		panic(fmt.Sprintf("pipeline: budget released %d bytes more than acquired", -b.used))
	}
	b.cond.Broadcast()
}

// InUse reports the bytes currently reserved. It is for tests and diagnostics.
func (b *Budget) InUse() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used
}
