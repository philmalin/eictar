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

// Params are the raw k=v settings from a --compress spec. A key given alone
// has the value "on", and "off" turns a key off (doc/design.md 10.2).
type Params map[string]string

// On and Off are the values of a key given alone, and of a key turned off.
const (
	On  = "on"
	Off = "off"
)

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
	// Bare is what the key means when it is given alone, or "on": long is
	// 27, as with zstd --long. Empty means the key needs a value.
	Bare string
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
	return NewEncoderWithDict(name, p, concurrency, nil)
}

// NewEncoderWithDict is NewEncoder with a dictionary (doc/design.md 4.2).
// A nil dictionary means none. Only a codec that has dictionaries takes one.
func NewEncoderWithDict(name string, p Params, concurrency int, dict []byte) (Encoder, error) {
	f, err := Lookup(name)
	if err != nil {
		return nil, err
	}
	if p, err = normalize(p, f.Describe()); err != nil {
		return nil, err
	}
	if concurrency < 1 {
		concurrency = 1
	}
	if dict == nil {
		return f.NewEncoder(p, concurrency)
	}
	df, ok := f.(dictFactory)
	if !ok {
		return nil, fmt.Errorf("codec %s has no dictionaries", name)
	}
	return df.newDictEncoder(p, concurrency, dict)
}

// dictFactory is a codec with dictionaries. Only zstd has them.
type dictFactory interface {
	newDictEncoder(p Params, concurrency int, dict []byte) (Encoder, error)
	newDictDecoder(maxPlain int, dict []byte) (Decoder, error)
	// trainSize is the dictionary size that p asks for, or 0.
	trainSize(p Params) (int, error)
	train(p Params, samples [][]byte, size int, id uint32) ([]byte, error)
	dictID(dict []byte) (uint32, error)
}

// TrainSize returns the size of the dictionary that the parameters ask for,
// or 0 when they ask for none.
func TrainSize(name string, p Params) (int, error) {
	f, err := Lookup(name)
	if err != nil {
		return 0, err
	}
	if p, err = normalize(p, f.Describe()); err != nil {
		return 0, err
	}
	df, ok := f.(dictFactory)
	if !ok {
		return 0, nil
	}
	return df.trainSize(p)
}

// TrainDict makes a dictionary of size bytes from samples, with the given id.
// It fails when the samples are too few or too alike to make one.
func TrainDict(name string, p Params, samples [][]byte, size int, id uint32) ([]byte, error) {
	f, err := Lookup(name)
	if err != nil {
		return nil, err
	}
	if p, err = normalize(p, f.Describe()); err != nil {
		return nil, err
	}
	df, ok := f.(dictFactory)
	if !ok {
		return nil, fmt.Errorf("codec %s has no dictionaries", name)
	}
	return df.train(p, samples, size, id)
}

// DictID reads the id that a dictionary of the codec carries.
func DictID(name string, dict []byte) (uint32, error) {
	f, err := Lookup(name)
	if err != nil {
		return 0, err
	}
	df, ok := f.(dictFactory)
	if !ok {
		return 0, fmt.Errorf("codec %s has no dictionaries", name)
	}
	return df.dictID(dict)
}

// normalize turns "on" into the key's bare value, and removes a key that is
// "off", so that each codec sees plain values. It returns a copy.
func normalize(p Params, spec Spec) (Params, error) {
	if len(p) == 0 {
		return p, nil
	}
	byName := make(map[string]ParamSpec, len(spec.Params))
	for _, ps := range spec.Params {
		byName[ps.Name] = ps
	}
	out := make(Params, len(p))
	for k, v := range p {
		ps, known := byName[k]
		switch {
		case !known:
			out[k] = v // checkParams reports it
		case v == On:
			if ps.Bare == "" {
				return nil, fmt.Errorf("parameter %s needs a value", k)
			}
			out[k] = ps.Bare
		case v == Off:
			if ps.Default != Off {
				return nil, fmt.Errorf("parameter %s cannot be off", k)
			}
		case v == "":
			return nil, fmt.Errorf("parameter %s has an empty value", k)
		default:
			out[k] = v
		}
	}
	return out, nil
}

// NewDecoder builds a decoder for name, bounded to maxPlain bytes per chunk.
func NewDecoder(name string, maxPlain int) (Decoder, error) {
	return NewDecoderWithDict(name, maxPlain, nil)
}

// NewDecoderWithDict is NewDecoder for chunks made with a dictionary. A nil
// dictionary means none.
func NewDecoderWithDict(name string, maxPlain int, dict []byte) (Decoder, error) {
	f, err := Lookup(name)
	if err != nil {
		return nil, err
	}
	if maxPlain <= 0 {
		return nil, fmt.Errorf("codec %s: chunk bound must be positive, got %d", name, maxPlain)
	}
	if dict == nil {
		return f.NewDecoder(maxPlain)
	}
	df, ok := f.(dictFactory)
	if !ok {
		return nil, fmt.Errorf("codec %s has no dictionaries", name)
	}
	return df.newDictDecoder(maxPlain, dict)
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
