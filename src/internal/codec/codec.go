// Package codec holds the compression algorithms and the registry that names
// them.
//
// A codec compresses one chunk at a time: chunks are independent so that a
// large member can be compressed and decompressed in parallel, and so that a
// single chunk can be fetched without touching the rest (doc/design.md 4).
// Encoders therefore never hold cross-chunk state.
package codec

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ErrUnknownCodec means the archive, or the user, named a codec this build
// does not have.
var ErrUnknownCodec = errors.New("unknown codec")

// Params are the raw k=v settings from a --compress spec.
type Params map[string]string

// Encoder compresses one chunk at a time.
type Encoder interface {
	// Encode appends the compressed form of src to dst and returns dst. It
	// must be safe for concurrent use: the worker pool shares one encoder
	// across chunks (M3).
	Encode(dst, src []byte) ([]byte, error)
	// Resolved returns the parameters actually in effect, for the index
	// catalog and for --list. Values are numbers or strings, so that a
	// generic CBOR dump of an index stays readable.
	Resolved() map[string]any
	Close() error
}

// Decoder decompresses one chunk at a time.
//
// Decoding takes the expected plaintext size, which the index knows for every
// chunk. Without it a crafted chunk is a decompression bomb; with it, the
// decoder refuses anything that does not decode to the size claimed.
type Decoder interface {
	Decode(dst, src []byte, plainSize int) ([]byte, error)
	Close() error
}

// Factory builds encoders and decoders for one algorithm.
type Factory interface {
	Name() string
	Describe() Spec
	// NewEncoder builds an encoder that will be shared by concurrency
	// goroutines. The count is not a request for codec-internal threads: it
	// sizes whatever per-caller state the library keeps, which is what lets
	// concurrent Encode calls actually run at once rather than queue.
	NewEncoder(p Params, concurrency int) (Encoder, error)
	// NewDecoder takes no compression parameters: decoding is determined by
	// the compressed stream itself, so an archive stays readable even if the
	// parameters recorded in the index mean nothing to a later build.
	//
	// maxPlain is the largest plaintext a single chunk may decode to, which
	// the index knows. It bounds the decoder before it allocates, rather than
	// leaving a crafted chunk to be caught after the memory is already gone.
	NewDecoder(maxPlain int) (Decoder, error)
}

// Spec documents a codec for --list-codecs.
type Spec struct {
	Name        string
	Description string
	Params      []ParamSpec
}

// ParamSpec documents one tunable.
type ParamSpec struct {
	Name        string
	Description string
	Default     string
	Min, Max    int // for integer parameters; both zero when not applicable
	Choices     []string
}

var registry = map[string]Factory{}

// Register adds a factory. It is called from package init functions, so
// adding a codec touches one file.
func Register(f Factory) {
	if _, dup := registry[f.Name()]; dup {
		panic("codec: registered twice: " + f.Name())
	}
	registry[f.Name()] = f
}

// Names returns the registered codec names, sorted.
func Names() []string {
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Lookup returns the factory for name.
func Lookup(name string) (Factory, error) {
	f, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("%w %q (known: %s)", ErrUnknownCodec, name, strings.Join(Names(), ", "))
	}
	return f, nil
}

// NewEncoder builds an encoder for name with params, to be shared by
// concurrency goroutines.
func NewEncoder(name string, p Params, concurrency int) (Encoder, error) {
	f, err := Lookup(name)
	if err != nil {
		return nil, err
	}
	if concurrency < 1 {
		concurrency = 1
	}
	return f.NewEncoder(p, concurrency)
}

// NewDecoder builds a decoder for name, bounded to maxPlain bytes per chunk.
func NewDecoder(name string, maxPlain int) (Decoder, error) {
	f, err := Lookup(name)
	if err != nil {
		return nil, err
	}
	if maxPlain <= 0 {
		return nil, fmt.Errorf("codec %s: chunk bound must be positive, got %d", name, maxPlain)
	}
	return f.NewDecoder(maxPlain)
}

// Describe returns every codec's documentation, sorted by name.
func Describe() []Spec {
	out := make([]Spec, 0, len(registry))
	for _, n := range Names() {
		out = append(out, registry[n].Describe())
	}
	return out
}

// intParam reads an integer parameter, applying the default when absent and
// enforcing the range. An out-of-range value is an error rather than a clamp:
// a user who asks for level 30 should be told it does not exist, not handed
// level 22 and a different archive than they expected.
func intParam(p Params, name string, def, lo, hi int) (int, error) {
	raw, ok := p[name]
	if !ok || raw == "" {
		return def, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("parameter %s: %q is not a number", name, raw)
	}
	if v < lo || v > hi {
		return 0, fmt.Errorf("parameter %s: %d is out of range %d..%d", name, v, lo, hi)
	}
	return v, nil
}

// checkParams rejects parameters the codec does not have, so a typo such as
// "levle=19" is reported rather than ignored.
func checkParams(p Params, spec Spec) error {
	known := make(map[string]bool, len(spec.Params))
	for _, ps := range spec.Params {
		known[ps.Name] = true
	}
	unknown := make([]string, 0, len(p))
	for k := range p {
		if !known[k] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	sort.Strings(unknown)

	valid := make([]string, 0, len(spec.Params))
	for _, ps := range spec.Params {
		valid = append(valid, ps.Name)
	}
	if len(valid) == 0 {
		return fmt.Errorf("codec %s takes no parameters, got %s", spec.Name, strings.Join(unknown, ", "))
	}
	return fmt.Errorf("codec %s has no parameter %s (known: %s)",
		spec.Name, strings.Join(unknown, ", "), strings.Join(valid, ", "))
}
