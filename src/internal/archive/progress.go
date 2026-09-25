package archive

import (
	"io"

	"eictar/src/internal/format"
)

// Progress is an optional part of a Reporter, for a progress meter
// (--progress). A Reporter that also implements it receives byte counts.
type Progress interface {
	// Total announces how many bytes the operation will process, when that
	// is known before it starts: extraction, verification and compaction
	// know it from the index. A create walks as it goes, and never calls it.
	Total(bytes int64)
	// Advance adds bytes processed. Extraction calls it from several
	// goroutines at once.
	Advance(bytes int64)
}

// progressOf returns the Reporter's Progress, or nil.
func progressOf(r Reporter) Progress {
	p, _ := r.(Progress)
	return p
}

// countReader counts what is read through r, when there is a meter.
func countReader(r io.Reader, p Progress) io.Reader {
	if p == nil {
		return r
	}
	return &counting{r: r, p: p}
}

// countWriter counts what is written through w, when there is a meter.
func countWriter(w io.Writer, p Progress) io.Writer {
	if p == nil {
		return w
	}
	return &counting{w: w, p: p}
}

type counting struct {
	r io.Reader
	w io.Writer
	p Progress
}

func (c *counting) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	c.p.Advance(int64(n))
	return n, err
}

func (c *counting) Write(b []byte) (int, error) {
	n, err := c.w.Write(b)
	c.p.Advance(int64(n))
	return n, err
}

// payloadTotal is the content that decoding the members will produce.
func payloadTotal(members []format.Member) int64 {
	var n int64
	for i := range members {
		if members[i].Type.HasPayload() {
			n += int64(members[i].PayloadSize())
		}
	}
	return n
}
