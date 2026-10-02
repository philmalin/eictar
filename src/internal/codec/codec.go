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
//
// A Decoder keeps no state from one Decode to the next. The reader uses one
// for every chunk of a member, and then for the next member with the same
// codec, chunk size and dictionary. It is not safe for concurrent use.
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
	return NewEncoderWith(name, p, EncoderOptions{Concurrency: concurrency})
}

// EncoderOptions are what an encoder needs beyond its parameters.
type EncoderOptions struct {
	// Concurrency is how many Encode calls may run at once. The encoder
	// keeps a state for each, and a caller over the number waits. The
	// writer bounds it by memory (doc/design.md 8.2).
	Concurrency int
	// Dict is a dictionary (doc/design.md 4.2), or nil. Only a codec that
	// has dictionaries takes one.
	Dict []byte
	// MaxChunk is the largest input of one Encode call, or 0 when it is not
	// known. zstd needs no window larger than a chunk, and a smaller window
	// saves memory with no change in the result.
	MaxChunk int
}

// NewEncoderWith builds an encoder with options.
func NewEncoderWith(name string, p Params, o EncoderOptions) (Encoder, error) {
	f, err := Lookup(name)
	if err != nil {
		return nil, err
	}
	if p, err = normalize(p, f.Describe()); err != nil {
		return nil, err
	}
	o.Concurrency = max(1, o.Concurrency)
	var enc Encoder
	switch of, ok := f.(optionsFactory); {
	case ok:
		enc, err = of.newEncoderWith(p, o)
	case o.Dict != nil:
		return nil, fmt.Errorf("codec %s has no dictionaries", name)
	default:
		enc, err = f.NewEncoder(p, o.Concurrency)
	}
	if err != nil {
		return nil, err
	}
	return &limited{Encoder: enc, slots: make(chan struct{}, o.Concurrency)}, nil
}

// limited lets at most cap(slots) Encode calls run at once. zstd limits
// itself with its pool of states; the other codecs allocate for each call,
// and this bounds what they hold at one time (doc/design.md 8.2).
type limited struct {
	Encoder
	slots chan struct{}
}

func (l *limited) Encode(dst, src []byte) ([]byte, error) {
	l.slots <- struct{}{}
	defer func() { <-l.slots }()
	return l.Encoder.Encode(dst, src)
}

// windowFactory is a codec with a parameter that sets how much history a
// match can reach back to: the window of zstd, the dictionary of xz.
type windowFactory interface {
	// window returns that history, in bytes, and what the codec calls it,
	// when p sets the parameter; 0 when p does not.
	window(p Params) (int, string, error)
}

// WindowBeyondChunk reports the history that the parameters p of the codec
// name ask for, when it is larger than chunkSize: a zstd long window, or the
// dictionary of an xz preset. The chunks are independent, so no match reaches
// back past the start of its chunk, and the history beyond a chunk has no
// effect (doc/design.md 10.2). It returns 0 when p asks for no more than a
// chunk, or does not set the parameter: a codec's default is not the user's
// choice. what is "window" or "dictionary".
func WindowBeyondChunk(name string, p Params, chunkSize int) (size int, what string, err error) {
	f, err := Lookup(name)
	if err != nil {
		return 0, "", err
	}
	wf, ok := f.(windowFactory)
	if !ok {
		return 0, "", nil
	}
	if p, err = normalize(p, f.Describe()); err != nil {
		return 0, "", err
	}
	size, what, err = wf.window(p)
	if err != nil || size <= chunkSize {
		return 0, "", err
	}
	return size, what, nil
}

// optionsFactory is a codec that uses EncoderOptions beyond Concurrency: a
// dictionary, or the chunk size. Only zstd is one.
type optionsFactory interface {
	newEncoderWith(p Params, o EncoderOptions) (Encoder, error)
}

// memoryFactory is a codec that knows the memory of one Encode call in
// progress: its state and its buffers.
type memoryFactory interface {
	encodeMemory(p Params, maxChunk int) (int64, error)
}

// EncodeMemory estimates the bytes that one Encode call in progress holds,
// for chunks of at most maxChunk bytes. The writer divides its memory by it
// to bound the calls that run at once (doc/design.md 8.2). The estimates
// come from measurements, and they are rounded up.
func EncodeMemory(name string, p Params, maxChunk int) (int64, error) {
	f, err := Lookup(name)
	if err != nil {
		return 0, err
	}
	if p, err = normalize(p, f.Describe()); err != nil {
		return 0, err
	}
	if mf, ok := f.(memoryFactory); ok {
		return mf.encodeMemory(p, maxChunk)
	}
	// An input and an output buffer, and a little state.
	return 2*int64(maxChunk) + 1<<20, nil
}

// dictFactory is a codec with dictionaries. Only zstd has them.
type dictFactory interface {
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
