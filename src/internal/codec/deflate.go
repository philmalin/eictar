package codec

import (
	"bytes"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/klauspost/compress/flate"
	"github.com/klauspost/compress/gzip"
)

func init() {
	Register(deflateFactory{name: "flate"})
	Register(deflateFactory{name: "gzip", framed: true})
}

// Levels as on the gzip command line.
const deflateLevelMin, deflateLevelMax, deflateLevelDefault = 1, 9, 6

// deflateFactory is DEFLATE, raw (flate) or in a gzip member (gzip). The gzip
// form adds an 18-byte header and trailer with a CRC-32 to each chunk. The
// BLAKE3 digest already covers the content, so the CRC adds nothing here;
// gzip exists because it is the name people know, and -z asks for it.
type deflateFactory struct {
	name   string
	framed bool
}

func (f deflateFactory) Name() string { return f.name }

func (f deflateFactory) Describe() Spec {
	desc := "DEFLATE with no framing: portable, moderate ratio"
	if f.framed {
		desc = "DEFLATE in a gzip member for each chunk (-z)"
	}
	return Spec{
		Name:        f.name,
		Description: desc,
		Params: []ParamSpec{{
			Name:        "level",
			Description: "compression level, as on the gzip command line",
			Default:     fmt.Sprint(deflateLevelDefault),
			Min:         deflateLevelMin, Max: deflateLevelMax,
		}},
	}
}

func (f deflateFactory) NewEncoder(p Params, _ int) (Encoder, error) {
	if err := checkParams(p, f.Describe()); err != nil {
		return nil, err
	}
	level, err := intParam(p, "level", deflateLevelDefault, deflateLevelMin, deflateLevelMax)
	if err != nil {
		return nil, err
	}
	e := &deflateEncoder{framed: f.framed, level: level}
	// A writer holds several hundred KiB of state. Each Encode takes one from
	// the pool and resets it, so that concurrent callers do not share one and
	// a busy pool does not allocate one per chunk.
	e.pool.New = func() any {
		if f.framed {
			w, _ := gzip.NewWriterLevel(io.Discard, level)
			return w
		}
		w, _ := flate.NewWriter(io.Discard, level)
		return w
	}
	return e, nil
}

type deflateEncoder struct {
	framed bool
	level  int
	pool   sync.Pool
}

type resetWriter interface {
	io.WriteCloser
	Reset(io.Writer)
}

// Encode is safe for concurrent use: each call has its own writer.
func (e *deflateEncoder) Encode(dst, src []byte) ([]byte, error) {
	w := e.pool.Get().(resetWriter)
	defer e.pool.Put(w)

	buf := bytes.NewBuffer(dst)
	w.Reset(buf)
	if gw, ok := w.(*gzip.Writer); ok {
		// Reset clears the header, and the library writes a zero time as a
		// negative Unix time cut to 32 bits. MTIME 0 is RFC 1952's "no time".
		gw.ModTime = time.Unix(0, 0)
	}
	if _, err := w.Write(src); err != nil {
		return nil, fmt.Errorf("deflate: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("deflate: %w", err)
	}
	return buf.Bytes(), nil
}

func (e *deflateEncoder) Resolved() map[string]any { return map[string]any{"level": e.level} }
func (e *deflateEncoder) Close() error             { return nil }

func (f deflateFactory) NewDecoder(maxPlain int) (Decoder, error) {
	return &deflateDecoder{name: f.name, framed: f.framed, maxPlain: maxPlain}, nil
}

type deflateDecoder struct {
	name     string
	framed   bool
	maxPlain int
}

func (d *deflateDecoder) Decode(dst, src []byte, plainSize int) ([]byte, error) {
	var r io.Reader
	if d.framed {
		// One gzip member per chunk: a second member would be data the index
		// does not account for.
		zr, err := gzip.NewReader(bytes.NewReader(src))
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		zr.Multistream(false)
		defer zr.Close()
		r = zr
	} else {
		fr := flate.NewReader(bytes.NewReader(src))
		defer fr.Close()
		r = fr
	}
	return decodeStream(d.name, r, dst, plainSize, d.maxPlain)
}

func (d *deflateDecoder) Close() error { return nil }

// encodeMemory is what one Encode call holds: a pooled compressor of about
// 1 MB, and the output.
func (deflateFactory) encodeMemory(_ Params, maxChunk int) (int64, error) {
	return int64(maxChunk) + 2<<20, nil
}
