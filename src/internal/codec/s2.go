package codec

import (
	"fmt"

	"github.com/klauspost/compress/s2"
)

func init() { Register(s2Factory{}) }

var s2Modes = []string{"fast", "better", "best"}

// s2Factory is S2, a faster successor to Snappy. It uses the block format:
// one block for each chunk, with the decoded length at its start.
type s2Factory struct{}

func (s2Factory) Name() string { return "s2" }

func (s2Factory) Describe() Spec {
	return Spec{
		Name:        "s2",
		Description: "S2 (Snappy family): very fast, lower ratio",
		Params: []ParamSpec{{
			Name:        "mode",
			Description: "speed against ratio",
			Default:     "better",
			Choices:     s2Modes,
		}},
	}
}

func (f s2Factory) NewEncoder(p Params, _ int) (Encoder, error) {
	if err := checkParams(p, f.Describe()); err != nil {
		return nil, err
	}
	mode := p["mode"]
	if mode == "" {
		mode = "better"
	}
	var encode func(dst, src []byte) []byte
	switch mode {
	case "fast":
		encode = s2.Encode
	case "better":
		encode = s2.EncodeBetter
	case "best":
		encode = s2.EncodeBest
	default:
		return nil, fmt.Errorf("parameter mode: %q is not one of %v", mode, s2Modes)
	}
	return &s2Encoder{mode: mode, encode: encode}, nil
}

type s2Encoder struct {
	mode   string
	encode func(dst, src []byte) []byte
}

// Encode is safe for concurrent use: the block functions keep no state.
func (e *s2Encoder) Encode(dst, src []byte) ([]byte, error) {
	// The block functions write from the start of dst, so the output goes
	// after what dst already holds.
	start := len(dst)
	need := s2.MaxEncodedLen(len(src))
	if need < 0 {
		return nil, fmt.Errorf("s2: a %d-byte chunk is too large", len(src))
	}
	if cap(dst)-start < need {
		grown := make([]byte, start, start+need)
		copy(grown, dst)
		dst = grown
	}
	out := e.encode(dst[start:start+need], src)
	return dst[:start+len(out)], nil
}

func (e *s2Encoder) Resolved() map[string]any { return map[string]any{"mode": e.mode} }
func (e *s2Encoder) Close() error             { return nil }

func (s2Factory) NewDecoder(maxPlain int) (Decoder, error) {
	return &s2Decoder{maxPlain: maxPlain}, nil
}

type s2Decoder struct{ maxPlain int }

func (d *s2Decoder) Decode(dst, src []byte, plainSize int) ([]byte, error) {
	if plainSize > d.maxPlain {
		return nil, fmt.Errorf("s2: chunk claims %d bytes, more than the %d permitted", plainSize, d.maxPlain)
	}
	// The block states its decoded length first. It is checked against the
	// index before anything is allocated.
	n, err := s2.DecodedLen(src)
	if err != nil {
		return nil, fmt.Errorf("s2: %w", err)
	}
	if n != plainSize {
		return nil, fmt.Errorf("s2: chunk decodes to %d bytes, index says %d", n, plainSize)
	}
	start := len(dst)
	if cap(dst)-start < plainSize {
		grown := make([]byte, start, start+plainSize)
		copy(grown, dst)
		dst = grown
	}
	out, err := s2.Decode(dst[start:start+plainSize], src)
	if err != nil {
		return nil, fmt.Errorf("s2: %w", err)
	}
	if len(out) != plainSize {
		return nil, fmt.Errorf("s2: chunk decoded to %d bytes, index says %d", len(out), plainSize)
	}
	return dst[:start+plainSize], nil
}

func (d *s2Decoder) Close() error { return nil }

// encodeMemory is what one Encode call holds, from measurements: two
// buffers of the chunk. At 4 MiB chunks, it is 9 MB.
func (s2Factory) encodeMemory(_ Params, maxChunk int) (int64, error) {
	return 2*int64(max(maxChunk, 1<<20)) + 1<<20, nil
}
