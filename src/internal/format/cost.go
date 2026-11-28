package format

import (
	"encoding/binary"
	"fmt"
	"reflect"
	"strings"
)

// The bound on the memory of a decoded index (doc/Security_Audit_Pass_2.eml,
// finding 19).
//
// The bound on the bytes of the index (indexLimit) does not bound the Go
// memory that those bytes decode into. An empty CBOR map is one byte, and as
// a member it becomes a Member of 320 bytes: a plain archive of 2,895 bytes
// held 4 million of them, and a listing used 1.6 GB before Validate refused
// the index. A real index decodes to at most about 5 times its bytes, for
// members with short paths and no content, and to about 6.5 times for a
// member with many empty extended attributes. So an index may decode to
// MaxIndexMemoryRatio times its bytes, or to MinIndexMemory, whichever is
// more. decodedCost gives the memory before the decode.
const (
	MaxIndexMemoryRatio = 8
	MinIndexMemory      = 1 << 20
)

// mapEntryCost is the memory of one entry of a Go map, apart from the key and
// the value: the control byte and the space that the load factor of 7/8
// leaves free, rounded up.
const mapEntryCost = 8

// decodedCost gives the Go memory that the decoder allocates when it decodes
// b into a value of type t: the elements of each slice and map, each string,
// and the value of each pointer and interface. It reads the CBOR with the
// layout of t, field by field, as the decoder does. A key that t does not
// have is skipped, as the decoder skips it, with no cost. A value of the
// wrong type costs nothing: the decoder refuses it before it allocates.
//
// The walk is as strict as the decoder: a truncated item, a tag, a length
// that is not definite or a reserved head is an error. An interface takes
// only an integer or a text string: the codec parameters are the only
// interfaces of the index, and every writer of eictar makes them so. A
// nested array or map there was the bomb of finding 19.
func decodedCost(b []byte, t reflect.Type) (uint64, error) {
	w := &costWalker{b: b, fields: map[reflect.Type]map[string]reflect.Type{}}
	if err := w.value(t); err != nil {
		return 0, err
	}
	return w.cost + uint64(t.Size()), nil
}

type costWalker struct {
	b      []byte
	off    int
	cost   uint64
	fields map[reflect.Type]map[string]reflect.Type
}

func (w *costWalker) fail(what string) error {
	return fmt.Errorf("format: %w: at byte %d: %s", ErrCorruptIndex, w.off, what)
}

// CBOR major types.
const (
	majorUint   = 0
	majorNegInt = 1
	majorBytes  = 2
	majorText   = 3
	majorArray  = 4
	majorMap    = 5
	majorTag    = 6
	majorSimple = 7
)

// head reads the head of the next item: its major type and its argument.
// For a string, the argument is its length, and head checks that the bytes
// are there. For an array or a map, head checks that the bytes can hold that
// many items, at least one byte each.
func (w *costWalker) head() (byte, uint64, error) {
	if w.off >= len(w.b) {
		return 0, 0, w.fail("the item is cut off")
	}
	ib := w.b[w.off]
	w.off++
	major, info := ib>>5, ib&0x1f
	var arg uint64
	switch {
	case info < 24:
		arg = uint64(info)
	case info <= 27:
		n := 1 << (info - 24)
		if len(w.b)-w.off < n {
			return 0, 0, w.fail("the head is cut off")
		}
		var buf [8]byte
		copy(buf[8-n:], w.b[w.off:w.off+n])
		arg = binary.BigEndian.Uint64(buf[:])
		w.off += n
	case info == 31:
		return 0, 0, w.fail("a length that is not definite")
	default:
		return 0, 0, w.fail("a reserved head")
	}
	left := uint64(len(w.b) - w.off)
	switch major {
	case majorTag:
		return 0, 0, w.fail("a tag")
	case majorBytes, majorText:
		if arg > left {
			return 0, 0, w.fail("the string is cut off")
		}
		w.off += int(arg)
	case majorArray:
		if arg > left {
			return 0, 0, w.fail("the array is cut off")
		}
	case majorMap:
		if arg > left/2 {
			return 0, 0, w.fail("the map is cut off")
		}
	}
	return major, arg, nil
}

// skip passes the rest of an item whose head is read, with no cost. It
// counts the items still to read, so that a deep item needs no recursion.
func (w *costWalker) skip(major byte, arg uint64) error {
	pending := uint64(0)
	for {
		switch major {
		case majorArray:
			pending += arg
		case majorMap:
			pending += 2 * arg
		}
		if pending == 0 {
			return nil
		}
		pending--
		var err error
		if major, arg, err = w.head(); err != nil {
			return err
		}
	}
}

// value reads the next item as a value of type t, and adds what the decoder
// allocates for it. What t holds in its own memory, its parent counts.
func (w *costWalker) value(t reflect.Type) error {
	if t.Kind() == reflect.Pointer {
		// null and undefined leave the pointer nil.
		if w.off < len(w.b) && (w.b[w.off] == 0xf6 || w.b[w.off] == 0xf7) {
			w.off++
			return nil
		}
		w.cost += uint64(t.Elem().Size())
		return w.value(t.Elem())
	}
	major, arg, err := w.head()
	if err != nil {
		return err
	}
	switch t.Kind() {
	case reflect.String:
		if major == majorBytes || major == majorText {
			w.cost += arg
		}
		return nil
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 && (major == majorBytes || major == majorText) {
			w.cost += arg
			return nil
		}
		if major != majorArray {
			return w.skip(major, arg)
		}
		w.cost += arg * uint64(t.Elem().Size())
		for range arg {
			if err := w.value(t.Elem()); err != nil {
				return err
			}
		}
		return nil
	case reflect.Map:
		if major != majorMap {
			return w.skip(major, arg)
		}
		w.cost += arg * (uint64(t.Key().Size()) + uint64(t.Elem().Size()) + mapEntryCost)
		for range arg {
			if err := w.value(t.Key()); err != nil {
				return err
			}
			if err := w.value(t.Elem()); err != nil {
				return err
			}
		}
		return nil
	case reflect.Struct:
		if major != majorMap {
			return w.skip(major, arg)
		}
		fields := w.fieldsOf(t)
		for range arg {
			kmajor, karg, err := w.head()
			if err != nil {
				return err
			}
			var ft reflect.Type
			if kmajor == majorText || kmajor == majorBytes {
				ft = fields[string(w.b[w.off-int(karg):w.off])]
			} else if err := w.skip(kmajor, karg); err != nil {
				return err
			}
			if ft == nil {
				vmajor, varg, err := w.head()
				if err != nil {
					return err
				}
				if err := w.skip(vmajor, varg); err != nil {
					return err
				}
				continue
			}
			if err := w.value(ft); err != nil {
				return err
			}
		}
		return nil
	case reflect.Interface:
		switch major {
		case majorUint, majorNegInt:
			w.cost += 8
		case majorText:
			w.cost += 16 + arg
		default:
			return w.fail("a codec parameter that is not an integer or a text string")
		}
		return nil
	}
	return w.skip(major, arg)
}

// fieldsOf gives the fields of t by their CBOR key, as the decoder matches
// them: the name in the cbor tag, or the name of the field.
func (w *costWalker) fieldsOf(t reflect.Type) map[string]reflect.Type {
	if f, ok := w.fields[t]; ok {
		return f
	}
	f := map[string]reflect.Type{}
	for i := range t.NumField() {
		sf := t.Field(i)
		if !sf.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(sf.Tag.Get("cbor"), ",")
		switch name {
		case "-":
			continue
		case "":
			name = sf.Name
		}
		f[name] = sf.Type
	}
	w.fields[t] = f
	return f
}
