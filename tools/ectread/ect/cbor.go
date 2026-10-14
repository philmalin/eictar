package ect

import (
	"encoding/binary"
	"fmt"
	"math"
)

// A CBOR decoder for the subset of RFC 8949 that doc/format.md 8.1 allows:
// definite lengths, no tags, and no duplicate keys. It shares no code with
// the decoder of eictar.

// text is a CBOR text string. A path is not always UTF-8, so it holds bytes.
type text string

// cmap is a CBOR map, with its keys in the order of the encoding.
type cmap struct {
	keys []any
	vals []any
}

// get returns the value of the text key name.
func (m *cmap) get(name string) (any, bool) {
	for i, k := range m.keys {
		if t, ok := k.(text); ok && string(t) == name {
			return m.vals[i], true
		}
	}
	return nil, false
}

// simple is a CBOR simple value other than false and true (null, undefined
// and the unassigned ones).
type simple uint8

const maxDepth = 64

type decoder struct {
	b     []byte
	pos   int
	depth int
}

// decodeCBOR decodes exactly one item from b.
func decodeCBOR(b []byte) (any, error) {
	d := &decoder{b: b}
	v, err := d.item()
	if err != nil {
		return nil, err
	}
	if d.pos != len(b) {
		return nil, refusef("CBOR: %d bytes after the item", len(b)-d.pos)
	}
	return v, nil
}

func (d *decoder) byte() (byte, error) {
	if d.pos >= len(d.b) {
		return 0, refusef("CBOR: the data ends early")
	}
	c := d.b[d.pos]
	d.pos++
	return c, nil
}

// argument reads the argument of an initial byte whose low five bits are ai.
func (d *decoder) argument(ai byte) (uint64, error) {
	var n int
	switch {
	case ai < 24:
		return uint64(ai), nil
	case ai == 24:
		n = 1
	case ai == 25:
		n = 2
	case ai == 26:
		n = 4
	case ai == 27:
		n = 8
	case ai == 31:
		return 0, refusef("CBOR: an indefinite length")
	default:
		return 0, refusef("CBOR: a reserved additional information %d", ai)
	}
	if len(d.b)-d.pos < n {
		return 0, refusef("CBOR: the data ends early")
	}
	var v uint64
	for _, c := range d.b[d.pos : d.pos+n] {
		v = v<<8 | uint64(c)
	}
	d.pos += n
	return v, nil
}

// length checks that a count of n items of at least one byte each can fit in
// what is left.
func (d *decoder) length(n uint64) (int, error) {
	if n > uint64(len(d.b)-d.pos) {
		return 0, refusef("CBOR: a length of %d with %d bytes left", n, len(d.b)-d.pos)
	}
	return int(n), nil
}

func (d *decoder) item() (any, error) {
	c, err := d.byte()
	if err != nil {
		return nil, err
	}
	major, ai := c>>5, c&31
	if major == 7 {
		return d.simpleOrFloat(ai)
	}
	arg, err := d.argument(ai)
	if err != nil {
		return nil, err
	}
	switch major {
	case 0:
		return arg, nil
	case 1:
		if arg > math.MaxInt64 {
			return nil, refusef("CBOR: a negative integer below the range of int64")
		}
		return -1 - int64(arg), nil
	case 2, 3:
		n, err := d.length(arg)
		if err != nil {
			return nil, err
		}
		s := d.b[d.pos : d.pos+n]
		d.pos += n
		if major == 3 {
			return text(s), nil
		}
		return append([]byte(nil), s...), nil
	case 4:
		n, err := d.length(arg)
		if err != nil {
			return nil, err
		}
		if err := d.enter(); err != nil {
			return nil, err
		}
		a := make([]any, n)
		for i := range a {
			if a[i], err = d.item(); err != nil {
				return nil, err
			}
		}
		d.depth--
		return a, nil
	case 5:
		n, err := d.length(arg)
		if err != nil {
			return nil, err
		}
		if err := d.enter(); err != nil {
			return nil, err
		}
		m := &cmap{keys: make([]any, n), vals: make([]any, n)}
		seen := make(map[string]bool, n)
		for i := 0; i < n; i++ {
			if m.keys[i], err = d.item(); err != nil {
				return nil, err
			}
			id, err := keyIdentity(m.keys[i])
			if err != nil {
				return nil, err
			}
			if seen[id] {
				return nil, refusef("CBOR: a duplicate key %q", id[2:])
			}
			seen[id] = true
			if m.vals[i], err = d.item(); err != nil {
				return nil, err
			}
		}
		d.depth--
		return m, nil
	}
	return nil, refusef("CBOR: a tag")
}

func (d *decoder) enter() error {
	d.depth++
	if d.depth > maxDepth {
		return refusef("CBOR: nested more than %d levels", maxDepth)
	}
	return nil
}

func (d *decoder) simpleOrFloat(ai byte) (any, error) {
	switch {
	case ai == 20:
		return false, nil
	case ai == 21:
		return true, nil
	case ai < 24:
		return simple(ai), nil
	case ai == 24:
		v, err := d.argument(24)
		if err != nil {
			return nil, err
		}
		if v < 32 {
			return nil, refusef("CBOR: a simple value %d in two bytes", v)
		}
		return simple(v), nil
	case ai == 25, ai == 26, ai == 27:
		v, err := d.argument(ai)
		if err != nil {
			return nil, err
		}
		switch ai {
		case 25:
			return halfToFloat(uint16(v)), nil
		case 26:
			return float64(math.Float32frombits(uint32(v))), nil
		}
		return math.Float64frombits(v), nil
	case ai == 31:
		return nil, refusef("CBOR: a break outside an indefinite length")
	}
	return nil, refusef("CBOR: a reserved simple value %d", ai)
}

func halfToFloat(h uint16) float64 {
	exp, frac := int(h>>10)&31, float64(h&1023)
	var v float64
	switch exp {
	case 0:
		v = math.Ldexp(frac, -24)
	case 31:
		if frac == 0 {
			v = math.Inf(1)
		} else {
			v = math.NaN()
		}
	default:
		v = math.Ldexp(frac+1024, exp-25)
	}
	if h&0x8000 != 0 {
		v = -v
	}
	return v
}

// keyIdentity gives a map key a string that is equal for equal keys.
func keyIdentity(k any) (string, error) {
	switch k := k.(type) {
	case text:
		return "t:" + string(k), nil
	case []byte:
		return "b:" + string(k), nil
	case uint64:
		return "u:" + fmt.Sprint(k), nil
	case int64:
		return "n:" + fmt.Sprint(k), nil
	case bool:
		return "s:" + fmt.Sprint(k), nil
	case simple:
		return "s:" + fmt.Sprint(uint8(k)), nil
	case float64:
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], math.Float64bits(k))
		return "f:" + string(b[:]), nil
	}
	return "", refusef("CBOR: a map key of type %T", k)
}
