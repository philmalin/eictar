package codec

import (
	"fmt"

	"github.com/klauspost/compress/zstd"
)

func init() { Register(zstdFactory{}) }

// zstd parameter ranges. The level range matches the zstd command line so a
// number a user already knows means the same thing here.
const (
	zstdLevelMin, zstdLevelMax, zstdLevelDefault = 1, 22, 3
	zstdLongMin, zstdLongMax                     = 10, 30
)

type zstdFactory struct{}

func (zstdFactory) Name() string { return "zstd" }

func (zstdFactory) Describe() Spec {
	return Spec{
		Name:        "zstd",
		Description: "Zstandard: the default, good ratio at high speed",
		Params: []ParamSpec{
			{
				Name:        "level",
				Description: "compression level, as on the zstd command line",
				Default:     fmt.Sprint(zstdLevelDefault),
				Min:         zstdLevelMin, Max: zstdLevelMax,
			},
			{
				Name:        "long",
				Description: "window log: the window is 2^long bytes, improving ratio on large files",
				Default:     "off",
				Min:         zstdLongMin, Max: zstdLongMax,
			},
		},
	}
}

func (f zstdFactory) NewEncoder(p Params, concurrency int) (Encoder, error) {
	spec := f.Describe()
	if err := checkParams(p, spec); err != nil {
		return nil, err
	}

	level, err := intParam(p, "level", zstdLevelDefault, zstdLevelMin, zstdLevelMax)
	if err != nil {
		return nil, err
	}
	long, err := intParam(p, "long", 0, zstdLongMin, zstdLongMax)
	if err != nil {
		return nil, err
	}

	opts := []zstd.EOption{
		zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(level)),
		// This is not a request for codec-internal threads. The library keeps
		// a pool of encoder states sized by this number and EncodeAll takes
		// one per call, so a shared encoder built with 1 serialises every
		// caller: the worker pool runs, and only one worker compresses at a
		// time. It must match the number of goroutines that will share it
		// (doc/design.md 8.2).
		zstd.WithEncoderConcurrency(concurrency),
	}
	resolved := map[string]any{"level": level}
	if _, ok := p["long"]; ok {
		opts = append(opts, zstd.WithWindowSize(1<<long))
		resolved["long"] = long
	}

	enc, err := zstd.NewWriter(nil, opts...)
	if err != nil {
		return nil, fmt.Errorf("zstd encoder: %w", err)
	}
	return &zstdEncoder{enc: enc, resolved: resolved}, nil
}

func (zstdFactory) NewDecoder(maxPlain int) (Decoder, error) {
	// The bound goes into the decoder itself: a frame that would exceed it is
	// refused while decoding, not after the memory has been handed over.
	// The library requires at least a window's worth.
	maxMem := max(uint64(maxPlain), 1<<20)

	dec, err := zstd.NewReader(nil,
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderMaxMemory(maxMem))
	if err != nil {
		return nil, fmt.Errorf("zstd decoder: %w", err)
	}
	return &zstdDecoder{dec: dec, maxPlain: maxPlain}, nil
}

type zstdEncoder struct {
	enc      *zstd.Encoder
	resolved map[string]any
}

// Encode is safe for concurrent use: EncodeAll is stateless across calls.
func (z *zstdEncoder) Encode(dst, src []byte) ([]byte, error) {
	return z.enc.EncodeAll(src, dst), nil
}

func (z *zstdEncoder) Resolved() map[string]any { return z.resolved }
func (z *zstdEncoder) Close() error             { return z.enc.Close() }

type zstdDecoder struct {
	dec      *zstd.Decoder
	maxPlain int
}

func (z *zstdDecoder) Decode(dst, src []byte, plainSize int) ([]byte, error) {
	if plainSize > z.maxPlain {
		return nil, fmt.Errorf("zstd: chunk claims %d bytes, more than the %d permitted",
			plainSize, z.maxPlain)
	}

	// Size the destination to what the index promises, so the common case
	// does not reallocate.
	start := len(dst)
	if cap(dst)-start < plainSize {
		grown := make([]byte, start, start+plainSize)
		copy(grown, dst)
		dst = grown
	}

	out, err := z.dec.DecodeAll(src, dst[:start])
	if err != nil {
		return nil, fmt.Errorf("zstd: %w", err)
	}
	if got := len(out) - start; got != plainSize {
		return nil, fmt.Errorf("zstd: chunk decoded to %d bytes, index says %d", got, plainSize)
	}
	return out, nil
}

func (z *zstdDecoder) Close() error {
	z.dec.Close()
	return nil
}
