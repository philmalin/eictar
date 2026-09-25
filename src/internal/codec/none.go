package codec

import "fmt"

func init() { Register(noneFactory{}) }

// noneFactory stores content unchanged. It is not a degenerate case to be
// tolerated but a first-class choice: already-compressed data, and anything
// where extraction speed matters more than size, belongs here.
type noneFactory struct{}

func (noneFactory) Name() string { return "none" }

func (noneFactory) Describe() Spec {
	return Spec{
		Name:        "none",
		Description: "store content unchanged",
	}
}

func (f noneFactory) NewEncoder(p Params, concurrency int) (Encoder, error) {
	if err := checkParams(p, f.Describe()); err != nil {
		return nil, err
	}
	return noneCodec{}, nil
}

func (noneFactory) NewDecoder(maxPlain int) (Decoder, error) { return noneCodec{maxPlain}, nil }

type noneCodec struct{ maxPlain int }

func (noneCodec) Encode(dst, src []byte) ([]byte, error) { return append(dst, src...), nil }

func (c noneCodec) Decode(dst, src []byte, plainSize int) ([]byte, error) {
	if c.maxPlain > 0 && plainSize > c.maxPlain {
		return nil, fmt.Errorf("chunk claims %d bytes, more than the %d permitted", plainSize, c.maxPlain)
	}
	if len(src) != plainSize {
		return nil, fmt.Errorf("stored chunk is %d bytes, index says %d", len(src), plainSize)
	}
	return append(dst, src...), nil
}

func (noneCodec) Resolved() map[string]any { return nil }
func (noneCodec) Close() error             { return nil }
