package codec

import (
	"bytes"
	"fmt"

	"github.com/ulikunitz/xz/lzma"
)

func init() { Register(xzFactory{}) }

const xzPresetMin, xzPresetMax, xzPresetDefault = 0, 9, 6

// xzPresetDict is the dictionary size of each preset, as on the xz command
// line. It is capped at the chunk size when a chunk is encoded, because a
// larger dictionary holds nothing more.
//
// Every preset uses the hash-chain match finder. xz uses a binary tree from
// preset 4, but the binary tree of this library takes quadratic time on
// repetitive input: 128 KiB of one repeated byte takes ten seconds, and one
// 4 MiB chunk of zeroes would take hours. A file of zeroes is common, and a
// codec that hangs on it cannot be offered.
var xzPresetDict = [...]int{
	256 << 10, 1 << 20, 2 << 20, 4 << 20, 4 << 20,
	8 << 20, 8 << 20, 16 << 20, 32 << 20, 64 << 20,
}

// xzFactory is LZMA2, the algorithm of xz, stored as a raw LZMA2 stream
// without the .xz container (doc/format.md).
//
// The container is left out for safety, not for size. Its block header
// declares the dictionary size, and a reader that honours it can be made to
// allocate 4 GiB by a crafted chunk. A raw stream has no such field: the
// reader chooses the dictionary, and a chunk's own size is always enough,
// because chunks are independent and no match reaches back beyond one. The
// container's CRC-64 would only repeat what the BLAKE3 digest checks.
type xzFactory struct{}

func (xzFactory) Name() string { return "xz" }

func (xzFactory) Describe() Spec {
	return Spec{
		Name:        "xz",
		Description: "LZMA2, as in xz (-J): high ratio, slow; stored without the .xz container",
		Params: []ParamSpec{{
			Name:        "preset",
			Description: "compression preset, as on the xz command line",
			Default:     fmt.Sprint(xzPresetDefault),
			Min:         xzPresetMin, Max: xzPresetMax,
		}},
	}
}

func (f xzFactory) NewEncoder(p Params, _ int) (Encoder, error) {
	if err := checkParams(p, f.Describe()); err != nil {
		return nil, err
	}
	preset, err := intParam(p, "preset", xzPresetDefault, xzPresetMin, xzPresetMax)
	if err != nil {
		return nil, err
	}
	cfg := lzma.Writer2Config{DictCap: xzPresetDict[preset], Matcher: lzma.HashTable4}
	if err := cfg.Verify(); err != nil {
		return nil, fmt.Errorf("xz: %w", err)
	}
	return &xzEncoder{preset: preset, cfg: cfg}, nil
}

type xzEncoder struct {
	preset int
	cfg    lzma.Writer2Config
}

// Encode is safe for concurrent use: each call makes its own writer. The
// library has no way to reset one, and a chunk costs far more to compress
// than a writer does to make.
func (e *xzEncoder) Encode(dst, src []byte) ([]byte, error) {
	// A dictionary larger than the chunk holds nothing more, and the writer
	// allocates all of it at once.
	cfg := e.cfg
	cfg.DictCap = max(lzma.MinDictCap, min(cfg.DictCap, len(src)))

	buf := bytes.NewBuffer(dst)
	w, err := cfg.NewWriter2(buf)
	if err != nil {
		return nil, fmt.Errorf("xz: %w", err)
	}
	if _, err := w.Write(src); err != nil {
		return nil, fmt.Errorf("xz: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("xz: %w", err)
	}
	return buf.Bytes(), nil
}

func (e *xzEncoder) Resolved() map[string]any { return map[string]any{"preset": e.preset} }
func (e *xzEncoder) Close() error             { return nil }

func (xzFactory) NewDecoder(maxPlain int) (Decoder, error) {
	return &xzDecoder{maxPlain: maxPlain}, nil
}

type xzDecoder struct{ maxPlain int }

func (d *xzDecoder) Decode(dst, src []byte, plainSize int) ([]byte, error) {
	// The dictionary is the chunk's size, never a number from the stream.
	cfg := lzma.Reader2Config{DictCap: max(lzma.MinDictCap, plainSize)}
	r, err := cfg.NewReader2(bytes.NewReader(src))
	if err != nil {
		return nil, fmt.Errorf("xz: %w", err)
	}
	return decodeStream("xz", r, dst, plainSize, d.maxPlain)
}

func (d *xzDecoder) Close() error { return nil }

// encodeMemory is what one Encode call holds, from measurements: about 7
// times its dictionary, which is the chunk at most (doc/design.md 8.2). At
// 4 MiB chunks, it is 30 MB.
func (xzFactory) encodeMemory(p Params, maxChunk int) (int64, error) {
	preset, err := intParam(p, "preset", xzPresetDefault, xzPresetMin, xzPresetMax)
	if err != nil {
		return 0, err
	}
	dict := xzPresetDict[preset]
	if maxChunk > 0 {
		dict = max(lzma.MinDictCap, min(dict, maxChunk))
	}
	return 7*int64(dict) + 2<<20, nil
}
