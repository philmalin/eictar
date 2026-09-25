package pipeline

import (
	"bytes"
	"math/rand"
	"testing"
)

func TestSpoolStaysInMemoryUnderThreshold(t *testing.T) {
	b := NewBudget(1 << 20)
	s := NewSpool(b, 1024, t.TempDir())
	defer s.Close()

	payload := bytes.Repeat([]byte("x"), 500)
	if _, err := s.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if s.Spilled() {
		t.Error("spooled below the threshold but still spilled to disk")
	}
	if s.Size() != 500 {
		t.Errorf("Size = %d, want 500", s.Size())
	}
	if b.InUse() != 500 {
		t.Errorf("budget in use = %d, want 500", b.InUse())
	}

	var got bytes.Buffer
	n, err := s.WriteTo(&got)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != 500 || !bytes.Equal(got.Bytes(), payload) {
		t.Errorf("drained %d bytes, content match = %v", n, bytes.Equal(got.Bytes(), payload))
	}
}

// TestSpoolSpillsAndReleasesBudget is the point of the spill: one large
// member must not decide the program's memory footprint.
func TestSpoolSpillsAndReleasesBudget(t *testing.T) {
	b := NewBudget(1 << 20)
	s := NewSpool(b, 1024, t.TempDir())
	defer s.Close()

	rnd := rand.New(rand.NewSource(3))
	want := make([]byte, 10_000)
	rnd.Read(want)

	// Write in pieces, crossing the threshold part way through.
	for off := 0; off < len(want); off += 300 {
		end := min(off+300, len(want))
		if _, err := s.Write(want[off:end]); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}

	if !s.Spilled() {
		t.Fatal("writing past the threshold did not spill")
	}
	if got := b.InUse(); got != 0 {
		t.Errorf("budget still holds %d bytes after spilling; the memory was handed to a file", got)
	}
	if s.Size() != int64(len(want)) {
		t.Errorf("Size = %d, want %d", s.Size(), len(want))
	}

	var got bytes.Buffer
	if _, err := s.WriteTo(&got); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Error("spilled content did not survive the round trip")
	}
}

func TestSpoolCloseReleasesBudget(t *testing.T) {
	b := NewBudget(1 << 20)
	s := NewSpool(b, 1<<20, t.TempDir())

	if _, err := s.Write(bytes.Repeat([]byte("y"), 4096)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if b.InUse() == 0 {
		t.Fatal("writing reserved nothing")
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := b.InUse(); got != 0 {
		t.Errorf("Close left %d bytes reserved", got)
	}
	// Close is idempotent: the emitter closes it, and a failure path may too.
	if err := s.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestSpoolEmpty(t *testing.T) {
	b := NewBudget(1 << 20)
	s := NewSpool(b, 1024, t.TempDir())
	defer s.Close()

	var got bytes.Buffer
	n, err := s.WriteTo(&got)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != 0 || got.Len() != 0 {
		t.Errorf("an empty spool drained %d bytes", n)
	}
}

// TestSpoolLargeSingleWrite covers a write that crosses the threshold on its
// own, which is the common case for an incompressible chunk.
func TestSpoolLargeSingleWrite(t *testing.T) {
	b := NewBudget(1 << 20)
	s := NewSpool(b, 100, t.TempDir())
	defer s.Close()

	want := bytes.Repeat([]byte("z"), 5000)
	if _, err := s.Write(want); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !s.Spilled() {
		t.Error("a write past the threshold did not spill")
	}

	var got bytes.Buffer
	if _, err := s.WriteTo(&got); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Error("content did not survive")
	}
}
