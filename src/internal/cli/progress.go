package cli

import (
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/term"

	"eictar/src/internal/archive"
	"eictar/src/internal/format"
)

// isTerminal reports whether w is a terminal. It is a variable so that tests
// can draw the meter into a buffer.
var isTerminal = func(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// meterInterval is how often the meter redraws.
const meterInterval = 200 * time.Millisecond

// meter is --progress: one status line on stderr, redrawn in place. It wraps
// the reporter, so that a -v line or a warning clears the status line first
// and the two never run into each other (doc/design.md 10.4).
type meter struct {
	inner *reporter
	out   io.Writer
	now   func() time.Time

	done, total, files atomic.Int64

	// The meter shows nothing until the operation reports its first byte or
	// its total. Before that it may be asking for a passphrase on the same
	// terminal, and a redraw would write over the prompt. The clock starts
	// then too, so that the time spent typing does not lower the rate.
	started atomic.Bool
	start   atomic.Int64 // UnixNano

	mu    sync.Mutex // guards the terminal line
	shown int        // width of the line on screen, to clear it
	stop  chan struct{}
	wg    sync.WaitGroup
}

// withProgress returns the reporter the operation should use: a meter when
// --progress was asked for and stderr is a terminal, the plain reporter
// otherwise. The returned function stops the meter and clears its line.
func withProgress(o *Options, rep *reporter, stderr io.Writer) (archive.Reporter, func()) {
	if !o.Progress || o.Quiet || !isTerminal(stderr) {
		return rep, func() {}
	}
	m := &meter{inner: rep, out: stderr, now: time.Now, stop: make(chan struct{})}
	m.wg.Add(1)
	go m.run()
	return m, m.finish
}

func (m *meter) run() {
	defer m.wg.Done()
	t := time.NewTicker(meterInterval)
	defer t.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-t.C:
			m.mu.Lock()
			m.draw()
			m.mu.Unlock()
		}
	}
}

func (m *meter) finish() {
	close(m.stop)
	m.wg.Wait()
	m.mu.Lock()
	m.clear()
	m.mu.Unlock()
}

func (m *meter) Total(n int64)   { m.begin(); m.total.Store(n) }
func (m *meter) Advance(n int64) { m.begin(); m.done.Add(n) }

func (m *meter) begin() {
	if !m.started.Load() {
		m.start.CompareAndSwap(0, m.now().UnixNano())
		m.started.Store(true)
	}
}

func (m *meter) Member(mem *format.Member) {
	m.files.Add(1)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clear()
	m.inner.Member(mem)
	m.draw()
}

func (m *meter) Warn(f string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clear()
	m.inner.Warn(f, args...)
	m.draw()
}

// clear removes the status line. The caller holds mu.
func (m *meter) clear() {
	if m.shown > 0 {
		fmt.Fprintf(m.out, "\r%*s\r", m.shown, "")
		m.shown = 0
	}
}

// draw writes the status line. The caller holds mu.
func (m *meter) draw() {
	if !m.started.Load() {
		return
	}
	elapsed := m.now().Sub(time.Unix(0, m.start.Load()))
	line := meterLine(m.done.Load(), m.total.Load(), m.files.Load(), elapsed)
	pad := max(0, m.shown-len(line))
	fmt.Fprintf(m.out, "\r%s%*s", line, pad, "")
	m.shown = len(line)
}

// meterLine renders the status: with a total, the percentage and the time
// left; without one, the count of members. Both give the rate.
//
//	1.2 GiB / 3.4 GiB  35%  120 MiB/s  0:18 left
//	1.2 GiB  1234 members  120 MiB/s
func meterLine(done, total, files int64, elapsed time.Duration) string {
	rate := int64(0)
	if secs := elapsed.Seconds(); secs > 0 {
		rate = int64(float64(done) / secs)
	}
	if total > 0 {
		pct := min(100, 100*done/total)
		left := "-:--"
		if rate > 0 && done <= total {
			left = clock(time.Duration(float64(total-done) / float64(rate) * float64(time.Second)))
		}
		return fmt.Sprintf("%s / %s  %d%%  %s/s  %s left", humanBytes(done), humanBytes(total), pct, humanBytes(rate), left)
	}
	return fmt.Sprintf("%s  %s  %s/s", humanBytes(done), plural(int(files), "member"), humanBytes(rate))
}

// humanBytes renders a byte count with a binary unit, as --chunk-size takes.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	v, i := float64(n), 0
	for v >= unit && i < 5 {
		v /= unit
		i++
	}
	return fmt.Sprintf("%.1f %ciB", v, "KMGTPE"[i-1])
}

// clock renders a duration as h:mm:ss, or m:ss under an hour.
func clock(d time.Duration) string {
	s := int64(d.Round(time.Second).Seconds())
	if s >= 3600 {
		return fmt.Sprintf("%d:%02d:%02d", s/3600, s/60%60, s%60)
	}
	return fmt.Sprintf("%d:%02d", s/60, s%60)
}
