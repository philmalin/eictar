package pipeline

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBudgetAccounting(t *testing.T) {
	b := NewBudget(1000)

	b.Acquire(400)
	if got := b.InUse(); got != 400 {
		t.Errorf("InUse = %d, want 400", got)
	}
	b.Acquire(600)
	if got := b.InUse(); got != 1000 {
		t.Errorf("InUse = %d, want 1000", got)
	}
	b.Release(1000)
	if got := b.InUse(); got != 0 {
		t.Errorf("InUse = %d, want 0", got)
	}
}

func TestBudgetUnlimited(t *testing.T) {
	b := NewBudget(0)
	for range 100 {
		b.Acquire(1 << 30)
	}
	if got := b.InUse(); got != 0 {
		t.Errorf("an unlimited budget should track nothing, InUse = %d", got)
	}
}

// TestBudgetBlocks is the property the whole design leans on: a worker cannot
// allocate past the limit while others hold it.
func TestBudgetBlocks(t *testing.T) {
	b := NewBudget(1000)
	b.Acquire(800)

	var acquired atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		b.Acquire(500) // must wait: 800 + 500 > 1000
		acquired.Store(true)
	}()

	time.Sleep(20 * time.Millisecond)
	if acquired.Load() {
		t.Fatal("Acquire returned while the budget was full")
	}

	b.Release(800)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Acquire did not return after the budget was released")
	}
	if got := b.InUse(); got != 500 {
		t.Errorf("InUse = %d, want 500", got)
	}
}

// TestBudgetAllowsOversizedRequest: a request larger than the whole budget
// must not deadlock. A user who picks a chunk size bigger than the memory
// limit should get a slow archive, not a hung one.
func TestBudgetAllowsOversizedRequest(t *testing.T) {
	b := NewBudget(100)

	done := make(chan struct{})
	go func() {
		defer close(done)
		b.Acquire(1000)
		b.Release(1000)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("an oversized acquisition deadlocked")
	}
}

// TestBudgetOversizedDoesNotWait: a request larger than the whole budget can
// never be satisfied by waiting, so it proceeds immediately even while others
// hold bytes. Waiting would be a deadlock, not caution - the chunk reader is
// often the only thing that will release what it is waiting for.
func TestBudgetOversizedDoesNotWait(t *testing.T) {
	b := NewBudget(100)
	b.Acquire(50)

	done := make(chan struct{})
	go func() {
		defer close(done)
		b.Acquire(1000)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("an oversized acquisition waited on bytes it could not have been given")
	}
	if got := b.InUse(); got != 1050 {
		t.Errorf("InUse = %d, want 1050 (both reservations counted)", got)
	}
}

// TestBudgetTryAcquire is what a spool uses: it must never block, because the
// bytes it waits for may be its own.
func TestBudgetTryAcquire(t *testing.T) {
	b := NewBudget(1000)

	if !b.TryAcquire(600) {
		t.Fatal("TryAcquire refused a request that fits")
	}
	if b.TryAcquire(600) {
		t.Error("TryAcquire granted a request past the limit")
	}
	if !b.TryAcquire(400) {
		t.Error("TryAcquire refused a request that exactly fills the budget")
	}
	if got := b.InUse(); got != 1000 {
		t.Errorf("InUse = %d, want 1000", got)
	}

	b.Release(1000)
	if !b.TryAcquire(1) {
		t.Error("TryAcquire refused after everything was released")
	}
}

func TestBudgetTryAcquireUnlimited(t *testing.T) {
	b := NewBudget(0)
	if !b.TryAcquire(1 << 40) {
		t.Error("an unlimited budget refused a reservation")
	}
}

func TestBudgetConcurrentUse(t *testing.T) {
	const (
		limit   = 1 << 16
		workers = 16
		each    = 200
	)
	b := NewBudget(limit)

	var peak atomic.Int64
	var mu sync.Mutex
	var wg sync.WaitGroup

	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range each {
				const n = limit / 8
				b.Acquire(n)

				mu.Lock()
				if u := b.InUse(); u > peak.Load() {
					peak.Store(u)
				}
				mu.Unlock()

				b.Release(n)
			}
		}()
	}
	wg.Wait()

	if got := b.InUse(); got != 0 {
		t.Errorf("budget leaked: InUse = %d, want 0", got)
	}
	if p := peak.Load(); p > limit {
		t.Errorf("peak use %d exceeded the limit %d", p, limit)
	}
}

func TestBudgetOverRelease(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("releasing more than was acquired should panic, not silently skew the budget")
		}
	}()
	b := NewBudget(100)
	b.Acquire(10)
	b.Release(20)
}
