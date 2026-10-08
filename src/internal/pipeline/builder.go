package pipeline

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/philmalin/eictar/src/internal/codec"
	"github.com/philmalin/eictar/src/internal/crypt"
	"github.com/philmalin/eictar/src/internal/format"
)

// Config describes one archive-building run.
type Config struct {
	Workers        int     // compressors; 1 means everything on one goroutine
	ChunkSize      int     // plaintext bytes per chunk
	Budget         *Budget // bytes that may be in flight
	SpillThreshold int64   // a member's payload moves to disk past this
	SpillDir       string  // where spill files go; "" means the system default
	Encoder        codec.Encoder
	Stored         bool // true when the codec is "none", so nothing is compressed

	// NewSealer builds the sealer for one member, or is nil for a plaintext
	// archive. Each member gets its own, because each has its own key.
	NewSealer func(m *format.Member) (*crypt.MemberSealer, error)

	// Emit is called once per completed member, from a single goroutine, in
	// completion order. It owns assigning the member's offset in the archive.
	// Payload is nil for members with no content.
	Emit func(m *format.Member, payload io.WriterTo) error
}

// Builder runs the walker's members through the worker pool and into Emit.
//
// The shape is the one in doc/design.md 8: a scheduler reads members in order
// on one goroutine, chunks fan out to the pool, and completed members arrive
// at a single emitting goroutine. Because member order in the archive carries
// no meaning, that goroutine takes whatever finishes first and never waits on
// a particular member.
type Builder struct {
	cfg Config

	chunks  chan chunkJob
	done    chan *memberBuild
	workers sync.WaitGroup
	emitter sync.WaitGroup

	mu      sync.Mutex
	err     error
	stopped bool
	stop    chan struct{}

	// scratch is the read buffer of AddFile, kept from one file to the next.
	// AddFile runs on one goroutine at a time, the walker's.
	scratch []byte
}

// chunkJob is one chunk of one member, waiting to be compressed.
type chunkJob struct {
	member *memberBuild
	index  int
	final  bool
	plain  []byte
	// budget held for plain, released once the compressed chunk has been
	// handed to the spool. Holding it that long is what bounds the pending
	// set: a chunk cannot be read until an earlier one has landed.
	held int64
}

// memberBuild is a member being assembled.
type memberBuild struct {
	m      format.Member
	spool  *Spool
	sealer *crypt.MemberSealer
	// chunks is the number of chunks the reader submitted, known only once
	// reading finishes. The last chunk's seal is bound to being last, so the
	// count has to be settled before any chunk can be sealed as final.
	chunks int

	mu      sync.Mutex
	next    int            // the chunk index the spool expects
	pending map[int][]byte // compressed chunks that arrived early
	lengths []uint32
	left    int // chunks not yet appended
	failed  error
}

// New returns a Builder. Start must be called before adding members.
func New(cfg Config) *Builder {
	if cfg.Workers < 1 {
		cfg.Workers = 1
	}
	if cfg.Budget == nil {
		cfg.Budget = NewBudget(0)
	}
	cfg.Budget.atLeast(2 * int64(cfg.ChunkSize))
	return &Builder{
		cfg: cfg,
		// One slot per worker keeps the queue short: the budget, not the
		// channel, is what limits work in flight.
		chunks: make(chan chunkJob, cfg.Workers),
		done:   make(chan *memberBuild, cfg.Workers),
		stop:   make(chan struct{}),
	}
}

// Start launches the workers and the emitting goroutine.
func (b *Builder) Start() {
	for range b.cfg.Workers {
		b.workers.Add(1)
		go b.worker()
	}
	b.emitter.Add(1)
	go b.emit()
}

func (b *Builder) worker() {
	defer b.workers.Done()
	for job := range b.chunks {
		out, err := b.encode(job.plain)
		if err == nil && job.member.sealer != nil {
			// Sealing happens after compression: ciphertext does not
			// compress (doc/design.md 6.3). final is known because the
			// reader settles the chunk count before releasing its claim.
			out, err = job.member.sealer.Seal(nil, out, uint64(job.index), job.final)
		}

		// Release before settling. settle appends to a spool, which may need
		// memory of its own, and holding one reservation while asking for
		// another is how a worker pool deadlocks.
		b.cfg.Budget.Release(job.held)

		if err != nil {
			job.member.fail(fmt.Errorf("encoding %q: %w", job.member.m.Path, err))
			job.member.settle(job.index, nil, b.done)
			continue
		}
		job.member.settle(job.index, out, b.done)
	}
}

// encode compresses one chunk, falling back to the plaintext when compression
// would grow it (doc/design.md 4.1).
//
// The plaintext is returned as it is, not copied: AddFile reads each chunk
// into a buffer of its own, and nothing writes to that buffer once the chunk
// is submitted. Sealing writes to a new slice, and the spool copies.
func (b *Builder) encode(plain []byte) ([]byte, error) {
	if b.cfg.Stored {
		return plain, nil
	}
	out, err := b.cfg.Encoder.Encode(nil, plain)
	if err != nil {
		return nil, err
	}
	if len(out) >= len(plain) {
		return plain, nil
	}
	return out, nil
}

// emit drains completed members on one goroutine.
func (b *Builder) emit() {
	defer b.emitter.Done()
	for mb := range b.done {
		// A directory or a symbolic link has no spool at all: it exists only
		// in the index. No other goroutine touches this member once it has
		// been handed over, so the fields are read without the lock.
		var payload io.WriterTo
		if mb.spool != nil {
			mb.m.Chunks = mb.lengths
			mb.m.Length = uint64(mb.spool.Size())
			payload = mb.spool
		}

		if err := mb.failed; err != nil {
			b.setErr(err)
			mb.close()
			continue
		}
		if err := b.cfg.Emit(&mb.m, payload); err != nil {
			b.setErr(err)
		}
		mb.close()
	}
}

// AddMeta records a member with no content: a directory or a symbolic link.
// It goes straight to the emitter, skipping the pool entirely.
func (b *Builder) AddMeta(m format.Member) error {
	if err := b.Err(); err != nil {
		return err
	}
	mb := &memberBuild{m: m}
	b.done <- mb
	return nil
}

// AddFile chunks r and submits the chunks to the pool.
//
// Reading happens here, on the caller's goroutine, so the input is read
// sequentially however many workers are compressing it. Calls must not
// overlap: they share one read buffer.
func (b *Builder) AddFile(m format.Member, r io.Reader, digest io.Writer) error {
	if err := b.Err(); err != nil {
		return err
	}

	mb := &memberBuild{
		m:       m,
		spool:   NewSpool(b.cfg.Budget, b.cfg.SpillThreshold, b.cfg.SpillDir),
		pending: map[int][]byte{},
		// The reader holds one claim of its own until it has submitted every
		// chunk. Without it, a pool that finishes the chunks submitted so far
		// would see the count reach zero and emit a member that is still
		// being read.
		left: 1,
	}
	mb.m.ChunkSize = uint32(b.cfg.ChunkSize)

	if b.cfg.NewSealer != nil {
		sealer, err := b.cfg.NewSealer(&mb.m)
		if err != nil {
			mb.close()
			return err
		}
		mb.sealer = sealer
	}

	submit := func(index int, plain []byte, final bool) error {
		mb.mu.Lock()
		mb.left++
		mb.mu.Unlock()

		select {
		case b.chunks <- chunkJob{
			member: mb, index: index, final: final,
			plain: plain, held: int64(b.cfg.ChunkSize),
		}:
			return nil
		case <-b.stop:
			// The run is failing. This member will never be emitted, so
			// nothing downstream will close its spool: do it here, or the
			// spill file's descriptor is held until the process exits.
			b.cfg.Budget.Release(int64(b.cfg.ChunkSize))
			mb.close()
			return b.Err()
		}
	}

	// One chunk is always held back, because a chunk cannot be sealed until
	// it is known whether another follows: the last chunk's seal is bound to
	// being last, which is what makes truncation detectable (doc/design.md
	// 6.3).
	var (
		held      []byte
		heldIndex int
		index     int
		read      uint64 // payload bytes read: for a sparse file, the data only
	)

	for {
		// The budget is taken before the read and held until the encoded
		// chunk has landed, so an unread chunk cannot start until an earlier
		// one has finished.
		if err := b.acquireFor(mb); err != nil {
			// The spool could not move to disk, so its budget is not free,
			// and a wait for budget would never end. Abandon the member, as
			// a read failure does.
			if held != nil {
				b.cfg.Budget.Release(int64(b.cfg.ChunkSize))
			}
			mb.close()
			return err
		}

		if b.scratch == nil {
			b.scratch = make([]byte, b.cfg.ChunkSize)
		}
		n, err := io.ReadFull(r, b.scratch)
		var buf []byte
		if n == len(b.scratch) {
			// A full chunk takes the buffer itself: the chunk goes to a worker
			// as it is, and encode relies on nobody writing to it again. The
			// next read gets a new buffer.
			buf, b.scratch = b.scratch, nil
		} else if n > 0 {
			// A short chunk - the end of a file, or the whole of a small one -
			// is copied out at its own size. A new chunk-sized buffer for each
			// small file cost more to clear than the file cost to compress:
			// 2000 files of 8 KiB cleared 8 GB of memory.
			buf = append([]byte(nil), b.scratch[:n]...)
		}
		if n > 0 {
			if digest != nil {
				digest.Write(buf[:n])
			}
			read += uint64(n)

			if held != nil {
				if serr := submit(heldIndex, held, false); serr != nil {
					b.cfg.Budget.Release(int64(b.cfg.ChunkSize))
					return serr
				}
			}
			held, heldIndex = buf[:n], index
			index++
		} else {
			b.cfg.Budget.Release(int64(b.cfg.ChunkSize))
		}

		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
			// A read failure abandons the member, so its spool has to be
			// released on the way out.
			if held != nil {
				b.cfg.Budget.Release(int64(b.cfg.ChunkSize))
			}
			mb.fail(err)
			mb.close()
			return err
		}
	}

	mb.chunks = index

	// A dense member's size is what was read. A sparse member's size is its
	// logical length, set by the caller with the data map, and the bytes
	// read must be exactly the map's total: anything else means the file
	// changed while it was being read, and the map no longer describes it.
	if len(mb.m.Sparse) == 0 {
		mb.m.Size = read
	} else if want := mb.m.PayloadSize(); read != want {
		if held != nil {
			b.cfg.Budget.Release(int64(b.cfg.ChunkSize))
		}
		mb.close()
		return fmt.Errorf("the file changed while it was read: %d bytes of data, expected %d", read, want)
	}

	if held == nil {
		// An empty file: no chunks, no chunk size, straight to the emitter.
		mb.m.ChunkSize = 0
		mb.spool.Close()
		mb.spool = nil
		mb.m.Digest = sum(digest)
		b.done <- mb
		return nil
	}

	if err := submit(heldIndex, held, true); err != nil {
		return err
	}

	// The digest covers the whole plaintext and reading is done here, on this
	// goroutine, so it is complete before the reader drops its claim.
	mb.m.Digest = sum(digest)
	mb.release(b.done)
	return nil
}

// acquireFor takes the budget for the next chunk of mb.
//
// It must not wait for budget that only mb itself can give back. The chunks
// of mb that the workers have finished are in its spool, in memory, and they
// hold budget until the member is complete; the member cannot be complete
// until this reader goes on. When the budget is full of them, the reader and
// the spool wait for each other for ever. That happened: 2 workers and 512-byte
// chunks hung a create, and with the defaults a file of 24 to 32 MiB on a
// two-CPU machine could do the same.
//
// So when the budget is not free at once, mb's spool moves to disk first.
// Everything else that holds budget - chunks in the workers, finished
// members on their way to the emitter - is released without this reader,
// so the wait that follows ends.
//
// If the spill fails, the spool keeps its budget, and the wait could never
// end. acquireFor then returns the error and takes no budget.
func (b *Builder) acquireFor(mb *memberBuild) error {
	n := int64(b.cfg.ChunkSize)
	if b.cfg.Budget.TryAcquire(n) {
		return nil
	}
	if err := mb.spill(); err != nil {
		return err
	}
	b.cfg.Budget.Acquire(n)
	return nil
}

// sum returns the digest accumulated so far, or nil if there was no hasher.
func sum(digest io.Writer) []byte {
	if h, ok := digest.(interface{ Sum(b []byte) []byte }); ok {
		return h.Sum(nil)
	}
	return nil
}

// release drops the reader's claim, emitting the member if the pool has
// already finished every chunk.
func (mb *memberBuild) release(done chan<- *memberBuild) {
	mb.mu.Lock()
	mb.left--
	complete := mb.left == 0 && len(mb.pending) == 0
	mb.mu.Unlock()

	if complete {
		done <- mb
	}
}

// settle files a compressed chunk in order, and hands the member to done once
// the last one has landed.
func (mb *memberBuild) settle(index int, data []byte, done chan<- *memberBuild) {
	mb.mu.Lock()

	// A member whose reader gave up has no spool: close set it to nil while
	// this chunk was in a worker. The member is never emitted, because the
	// reader never drops its claim, so the chunk is dropped here.
	if data != nil && mb.spool != nil {
		mb.pending[index] = data
		for {
			next, ok := mb.pending[mb.next]
			if !ok {
				break
			}
			delete(mb.pending, mb.next)

			if _, err := mb.spool.Write(next); err != nil && mb.failed == nil {
				mb.failed = err
			}
			mb.lengths = append(mb.lengths, uint32(len(next)))
			mb.next++
		}
	}

	mb.left--
	complete := mb.left == 0 && len(mb.pending) == 0
	mb.mu.Unlock()

	if complete {
		done <- mb
	}
}

// close releases the member's spool. It is safe to call more than once, and
// on a member that never had one.
func (mb *memberBuild) close() {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	if mb.spool != nil {
		mb.spool.Close()
		mb.spool = nil
	}
}

// spill moves the member's spool to disk, giving its memory back to the
// budget. A failure fails the member, as a failed spool write does, and is
// returned.
func (mb *memberBuild) spill() error {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	if mb.spool == nil {
		return nil
	}
	err := mb.spool.Spill()
	if err != nil && mb.failed == nil {
		mb.failed = err
	}
	return err
}

func (mb *memberBuild) fail(err error) {
	mb.mu.Lock()
	if mb.failed == nil {
		mb.failed = err
	}
	mb.mu.Unlock()
}

// Finish closes the pool, waits for every member to be emitted, and reports
// the first error seen anywhere in the run.
func (b *Builder) Finish() error {
	close(b.chunks)
	b.workers.Wait()
	close(b.done)
	b.emitter.Wait()
	return b.Err()
}

// Err reports the first error recorded by any goroutine.
func (b *Builder) Err() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.err
}

func (b *Builder) setErr(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err == nil {
		b.err = err
		if !b.stopped {
			b.stopped = true
			close(b.stop)
		}
	}
}
