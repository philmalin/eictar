package codec

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/klauspost/compress/dict"
	"github.com/klauspost/compress/zstd"
)

func init() { Register(zstdFactory{}) }

// zstd parameter ranges. The level range matches the zstd command line so a
// number a user already knows means the same thing here.
//
// The library has four speeds, not 22 levels: 1-2 is its fastest, 3-5 its
// default, 6-9 better, and 10-22 best (EncoderLevelFromZstd). Thus 12 and 19
// give the same archive. The default is 12, the best speed: about 5% smaller
// than 3 on source code, and about 3.4 times slower to create, with the same
// extraction speed (doc/design.md 10.2). 12 rather than 19, so that it stays
// a sensible level if the library gains finer ones.
const (
	zstdLevelMin, zstdLevelMax, zstdLevelDefault = 1, 22, 12
	zstdLongMin, zstdLongMax                     = 10, 30
	// zstdLongBare is the window of zstd --long given alone.
	zstdLongBare = 27

	// Dictionary sizes (doc/design.md 4.2). The default is the one of the
	// zstd trainer.
	zstdTrainMin, zstdTrainMax, zstdTrainBare = 4 << 10, 1 << 20, 112 << 10
	// zstdDictMagic starts every dictionary in the zstd format, and the
	// dictionary id follows it.
	zstdDictMagic = 0xEC30A437
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
				Description: "window log: the window is 2^long bytes, improving ratio on large files; a window larger than the chunk has no effect",
				Default:     Off,
				Min:         zstdLongMin, Max: zstdLongMax,
				Bare: fmt.Sprint(zstdLongBare),
			},
			{
				Name:        "train",
				Description: "train a dictionary of this many bytes from the files first, and store it in the archive: many small, similar files compress better",
				Default:     Off,
				Min:         zstdTrainMin, Max: zstdTrainMax,
				Bare: fmt.Sprint(zstdTrainBare),
			},
		},
	}
}

func (f zstdFactory) NewEncoder(p Params, concurrency int) (Encoder, error) {
	return f.newEncoderWith(p, EncoderOptions{Concurrency: concurrency})
}

// newEncoderWith builds the encoder, with a dictionary when o.Dict is not nil.
// The train key is checked here but does not change the encoder: the writer
// trains the dictionary and hands it in (doc/design.md 4.2).
func (f zstdFactory) newEncoderWith(p Params, o EncoderOptions) (Encoder, error) {
	concurrency, dictionary := o.Concurrency, o.Dict
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
	if _, err := f.trainSize(p); err != nil {
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
	window := 0 // the library's own, for the level
	if _, ok := p["long"]; ok {
		window = 1 << long
		resolved["long"] = long
	}
	// No match reaches back past the start of its chunk (doc/design.md 4),
	// so a window larger than the chunk holds nothing, but the library
	// allocates it: 300 MB for each state at long=27. A window of the chunk,
	// rounded up to a power of 2, gives the same result.
	if w := zstdWindow(window, level, o.MaxChunk); w != window || window != 0 {
		opts = append(opts, zstd.WithWindowSize(w))
	}
	if dictionary != nil {
		opts = append(opts, zstd.WithEncoderDict(dictionary))
	}

	enc, err := zstd.NewWriter(nil, opts...)
	if err != nil {
		return nil, fmt.Errorf("zstd encoder: %w", err)
	}
	return &zstdEncoder{enc: enc, resolved: resolved}, nil
}

func (f zstdFactory) NewDecoder(maxPlain int) (Decoder, error) {
	return f.newDictDecoder(maxPlain, nil)
}

// newDictDecoder builds the decoder, with a dictionary when dict is not nil.
// A frame names the id of its dictionary, and the decoder refuses a frame
// that names another, so a wrong dictionary is damage, not wrong output.
func (zstdFactory) newDictDecoder(maxPlain int, dictionary []byte) (Decoder, error) {
	// The bound goes into the decoder itself: a frame that would exceed it is
	// refused while decoding, not after the memory has been handed over.
	// The library requires at least a window's worth.
	maxMem := max(uint64(maxPlain), 1<<20)

	opts := []zstd.DOption{
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderMaxMemory(maxMem),
	}
	if dictionary != nil {
		opts = append(opts, zstd.WithDecoderDicts(dictionary))
	}
	dec, err := zstd.NewReader(nil, opts...)
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

// zstdWindow is the window that the encoder uses: the one asked for (0: the
// library's for the level), but no larger than a chunk needs. The library
// takes a power of 2 from 1 KiB to 512 MiB.
func zstdWindow(window, level, maxChunk int) int {
	if window == 0 {
		window = zstdLevelWindow(level)
	}
	if maxChunk > 0 {
		need := 1 << 10
		for need < maxChunk && need < 1<<29 {
			need <<= 1
		}
		window = min(window, need)
	}
	return window
}

// zstdLevelWindow is the library's window for each of its speeds.
func zstdLevelWindow(level int) int {
	if zstd.EncoderLevelFromZstd(level) == zstd.SpeedBestCompression {
		return 8 << 20
	}
	return 4 << 20
}

// encodeMemory is what one encoder state holds, from measurements: a base for
// each speed of the library, and two buffers of the window (doc/design.md
// 8.2). At level 12 with 4 MiB chunks, it is 44 MB.
func (zstdFactory) encodeMemory(p Params, maxChunk int) (int64, error) {
	level, err := intParam(p, "level", zstdLevelDefault, zstdLevelMin, zstdLevelMax)
	if err != nil {
		return 0, err
	}
	long, err := intParam(p, "long", 0, zstdLongMin, zstdLongMax)
	if err != nil {
		return 0, err
	}
	window := 0
	if _, ok := p["long"]; ok {
		window = 1 << long
	}
	base := map[zstd.EncoderLevel]int64{
		zstd.SpeedFastest:           1 << 20,
		zstd.SpeedDefault:           2 << 20,
		zstd.SpeedBetterCompression: 5 << 20,
		zstd.SpeedBestCompression:   36 << 20,
	}[zstd.EncoderLevelFromZstd(level)]
	return base + 2*int64(zstdWindow(window, level, maxChunk)), nil
}

// window is the long window that p asks for, or 0 when p does not set long.
func (zstdFactory) window(p Params) (int, string, error) {
	if _, ok := p["long"]; !ok {
		return 0, "", nil
	}
	long, err := intParam(p, "long", 0, zstdLongMin, zstdLongMax)
	if err != nil {
		return 0, "", err
	}
	return 1 << long, "window", nil
}

// trainSize reads the train key: 0 when it is absent.
func (zstdFactory) trainSize(p Params) (int, error) {
	raw, ok := p["train"]
	if !ok {
		return 0, nil
	}
	n, err := parseSize(raw)
	if err != nil {
		return 0, fmt.Errorf("parameter train: %w", err)
	}
	if n < zstdTrainMin || n > zstdTrainMax {
		return 0, fmt.Errorf("parameter train: %d bytes is out of range %d..%d", n, zstdTrainMin, zstdTrainMax)
	}
	return n, nil
}

// train makes a dictionary in the zstd format, of at most size bytes in all.
// The trainer of klauspost/compress/dict is experimental, and it can fail,
// or panic, on small or uniform input; either way the result is "no
// dictionary".
//
// The trainer's size is that of the dictionary's content. The header and the
// entropy tables come on top, about 100 bytes, so a dictionary asked for at
// the 1 MiB limit came out above it. When the result is too large, the
// trainer runs again with the content smaller by the excess.
func (f zstdFactory) train(p Params, samples [][]byte, size int, id uint32) ([]byte, error) {
	level, err := intParam(p, "level", zstdLevelDefault, zstdLevelMin, zstdLevelMax)
	if err != nil {
		return nil, err
	}
	content := size
	for range 4 {
		out, err := f.trainOnce(samples, content, id, level)
		if err != nil {
			return nil, err
		}
		if len(out) <= size {
			return out, nil
		}
		content -= len(out) - size + 64
		if content < zstdTrainMin/2 {
			break
		}
	}
	return nil, fmt.Errorf("the dictionary trainer could not keep the dictionary within %d bytes", size)
}

func (zstdFactory) trainOnce(samples [][]byte, content int, id uint32, level int) (out []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, fmt.Errorf("the dictionary trainer failed: %v", r)
		}
	}()
	out, err = dict.BuildZstdDict(samples, dict.Options{
		MaxDictSize: content,
		HashBytes:   6,
		ZstdDictID:  id,
		ZstdLevel:   zstd.EncoderLevelFromZstd(level),
	})
	if err != nil {
		return nil, fmt.Errorf("the dictionary trainer failed: %w", err)
	}
	if got, err := (zstdFactory{}).dictID(out); err != nil || got != id {
		return nil, fmt.Errorf("the dictionary trainer made a dictionary with id %d, want %d (%v)", got, id, err)
	}
	return out, nil
}

// dictID reads the id of a dictionary in the zstd format: the magic, then
// the id, both little-endian (RFC 8878, section 5).
func (zstdFactory) dictID(d []byte) (uint32, error) {
	if len(d) < 8 || binary.LittleEndian.Uint32(d) != zstdDictMagic {
		return 0, fmt.Errorf("zstd: not a dictionary in the zstd format")
	}
	return binary.LittleEndian.Uint32(d[4:]), nil
}

// parseSize reads a byte count with an optional unit: 65536, 64K, 64KiB, 1M.
// The units are powers of 1024, as on the rest of the command line.
func parseSize(s string) (int, error) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0, fmt.Errorf("%q is not a size", s)
	}
	n, err := strconv.Atoi(s[:i])
	if err != nil || n > 1<<40 {
		// The bound keeps a shift below from wrapping into the range.
		return 0, fmt.Errorf("%q is not a size", s)
	}
	switch strings.ToLower(s[i:]) {
	case "", "b":
	case "k", "kb", "kib":
		n <<= 10
	case "m", "mb", "mib":
		n <<= 20
	default:
		return 0, fmt.Errorf("%q has an unknown unit", s)
	}
	return n, nil
}
