package format

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// cborHead is the head of a CBOR item of major type major, with argument n.
func cborHead(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n <= 0xff:
		return []byte{major<<5 | 24, byte(n)}
	case n <= 0xffff:
		return []byte{major<<5 | 25, byte(n >> 8), byte(n)}
	default:
		return []byte{major<<5 | 26, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
}

func cborText(s string) []byte { return append(cborHead(majorText, uint64(len(s))), s...) }

// emptyMembers is an index of n members that are each an empty map: one
// byte each, and 320 bytes of Go memory each.
func emptyMembers(n int) []byte {
	b := cborHead(majorMap, 3)
	b = append(b, cborText("v")...)
	b = append(b, 1)
	b = append(b, cborText("gen")...)
	b = append(b, 1)
	b = append(b, cborText("members")...)
	b = append(b, cborHead(majorArray, uint64(n))...)
	return append(b, bytes.Repeat([]byte{0xa0}, n)...)
}

// allocated gives the bytes that f allocates.
func allocated(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// TestIndexOfEmptyMembersIsRefusedBeforeTheDecode: the attack of finding
// 19 (doc/Security_Audit_Pass_2.eml). An index of empty maps as members
// decoded to 320 bytes of memory for each byte, and Validate refused it only
// after the decode: a plain archive of 2,895 bytes made a listing use
// 1.6 GB. Now the index is refused before the decode, and the refusal
// allocates almost nothing.
func TestIndexOfEmptyMembersIsRefusedBeforeTheDecode(t *testing.T) {
	const n = 1 << 18
	raw := emptyMembers(n)
	var err error
	used := allocated(func() { _, err = DecodeIndex(raw, 0, nil) })
	if !errors.Is(err, ErrIndexTooLarge) {
		t.Errorf("DecodeIndex = %v, want %v", err, ErrIndexTooLarge)
	}
	if used > uint64(len(raw)) {
		t.Errorf("the refusal allocated %d bytes, for an index of %d bytes", used, len(raw))
	}
}

// TestIndexWithNestedCodecParametersIsRefused: the first attack of finding
// 19. Arrays of empty maps in a codec parameter decoded to about 67 bytes
// of memory for each byte: a plain archive of 7 KB made a listing use
// 4.2 GB. A codec parameter is now an integer or a text string, and the walk
// refuses any other value before the decode.
func TestIndexWithNestedCodecParametersIsRefused(t *testing.T) {
	ix := sampleIndex()
	maps := make([]any, 1000)
	for i := range maps {
		maps[i] = map[string]any{}
	}
	ix.Codecs[1].Params = map[string]any{"preset": uint64(6), "x": []any{maps}}
	raw, err := encMode.Marshal(ix)
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecodeIndex(raw, 0, nil)
	// The walk refuses it, before the decode: its error gives the byte.
	if !errors.Is(err, ErrCorruptIndex) || !strings.Contains(err.Error(), "at byte") ||
		!strings.Contains(err.Error(), "not an integer or a text string") {
		t.Errorf("DecodeIndex = %v, want a refusal of the parameter by the walk", err)
	}
}

// realIndex is an index of n members of one kind, as the writer makes them.
func realIndex(kind string, n int) *Index {
	ix := &Index{Version: IndexVersion, Generation: 1,
		Codecs: []CodecSpec{{Name: "zstd", Params: map[string]any{"level": uint64(3)}}}}
	for i := range n {
		m := Member{ID: uint64(i + 1), Generation: 1, Path: fmt.Sprintf("d%d", i), Type: TypeReg,
			Mode: 0o644, MTimeNanos: 1700000000000000000 + int64(i), Codec: NoCodec}
		if kind != "dir" {
			m.Digest = make([]byte, DigestSize) // of the empty content
		}
		switch kind {
		case "dir":
			m.Type, m.Mode = TypeDir, 0o755
		case "file":
			m.Size = 1000
			m.UID, m.GID = OwnerID(1000), OwnerID(1000)
			m.Uname, m.Gname = "user", "user"
			m.Codec, m.ChunkSize = 0, 1<<20
			m.Offset, m.Length = 64+uint64(i)*1000, 1000
			m.Chunks = []uint32{1000}
		case "xattrs":
			m.Xattrs = map[string][]byte{}
			for j := range 64 {
				m.Xattrs[fmt.Sprintf("user.%d", j)] = nil
			}
		case "dead":
			m.Dead = true
		}
		ix.Members = append(ix.Members, m)
	}
	return ix
}

// TestRealIndexesDecode: the indexes that the writer makes decode to less
// than MaxIndexMemoryRatio times their bytes, also the ones with the most
// memory for each byte: members with short paths and no content, and members
// with many empty extended attributes. The estimate is near what the decoder
// allocates.
func TestRealIndexesDecode(t *testing.T) {
	for _, kind := range []string{"dir", "empty", "file", "xattrs", "dead"} {
		ix := realIndex(kind, 20000)
		raw, err := encMode.Marshal(ix)
		if err != nil {
			t.Fatal(err)
		}
		cost, err := decodedCost(raw, reflect.TypeFor[Index]())
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		ratio := float64(cost) / float64(len(raw))
		if ratio >= MaxIndexMemoryRatio*0.9 {
			t.Errorf("%s: %.1f times the bytes, too near the limit of %d", kind, ratio, MaxIndexMemoryRatio)
		}
		var got *Index
		used := allocated(func() { got, err = DecodeIndex(raw, 0, nil) })
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if !reflect.DeepEqual(got.Members[1], ix.Members[1]) {
			t.Errorf("%s: member 2 is %+v, want %+v", kind, got.Members[1], ix.Members[1])
		}
		// The decoder allocates more than the estimate (the maps grow in
		// steps, and Validate has its own maps), but not much more.
		if used > 4*cost || used < cost/2 {
			t.Errorf("%s: the estimate is %d bytes, and the decode allocated %d", kind, cost, used)
		}
		t.Logf("%s: %d bytes, estimate %d (%.1f times), allocated %d", kind, len(raw), cost, ratio, used)
	}
}

// TestDecodedCost: the walk adds the memory of each slice, map, string,
// pointer and interface, skips what the type does not have, and is as strict
// as the decoder.
func TestDecodedCost(t *testing.T) {
	type inner struct {
		A uint64 `cbor:"a"`
	}
	type outer struct {
		S   string            `cbor:"s"`
		B   []byte            `cbor:"b"`
		L   []inner           `cbor:"l"`
		M   map[string][]byte `cbor:"m"`
		P   *inner            `cbor:"p"`
		Any any               `cbor:"any"`
		N   uint32            // no tag: the key is the name
		X   int               `cbor:"-"`
		low string
	}
	ty := reflect.TypeFor[outer]()
	size := uint64(ty.Size())
	isize := uint64(reflect.TypeFor[inner]().Size())
	entry := uint64(16+24) + mapEntryCost

	m := func(pairs int, parts ...[]byte) []byte {
		return cat(append([][]byte{cborHead(majorMap, uint64(pairs))}, parts...)...)
	}
	for _, c := range []struct {
		name string
		in   []byte
		want uint64
	}{
		{"empty", m(0), 0},
		{"text", m(1, cborText("s"), cborText("abc")), 3},
		{"bytes as a string", m(1, cborText("s"), cborHead(majorBytes, 2), []byte("ab")), 2},
		{"bytes", m(1, cborText("b"), cborHead(majorBytes, 300), make([]byte, 300)), 300},
		{"text as bytes", m(1, cborText("b"), cborText("xyz")), 3},
		{"array of structs", m(1, cborText("l"), cborHead(majorArray, 3), m(0), m(1, cborText("a"), []byte{5}), m(0)), 3 * isize},
		{"map", m(1, cborText("m"), m(2, cborText("k1"), cborHead(majorBytes, 1), []byte{1}, cborText("k"), []byte{0xf6})), 2*entry + 2 + 1 + 1},
		{"pointer", m(1, cborText("p"), m(1, cborText("a"), []byte{1})), isize},
		{"null pointer", m(1, cborText("p"), []byte{0xf6}), 0},
		{"null pointer, then a field", m(2, cborText("p"), []byte{0xf6}, cborText("s"), cborText("abc")), 3},
		{"an unknown map, then a field", m(2, cborText("later"), m(2, cborText("k"), cborText("v"), cborText("k2"), cborText("v2")), cborText("s"), cborText("abc")), 3},
		{"undefined pointer", m(1, cborText("p"), []byte{0xf7}), 0},
		{"interface integer", m(1, cborText("any"), cborHead(majorUint, 1000)), 8},
		{"interface negative integer", m(1, cborText("any"), []byte{0x20}), 8},
		{"interface text", m(1, cborText("any"), cborText("on")), 18},
		{"field by its name", m(1, cborText("N"), []byte{7}), 0},
		{"byte-string key", m(1, cborHead(majorBytes, 1), []byte("s"), cborText("abcd")), 4},
		{"unknown key, deep value", m(1, cborText("later"), cborHead(majorArray, 1), cborHead(majorArray, 1), m(1, cborText("k"), cborText("long text"))), 0},
		{"integer key", m(1, []byte{1}, cborText("abc")), 0},
		{"array key", m(1, cborHead(majorArray, 1), []byte{1}, cborText("abc")), 0},
		{"a key of a skipped field", m(1, cborText("X"), cborText("abc")), 0},
		{"a key of an unexported field", m(1, cborText("low"), cborText("abc")), 0},
		{"wrong type: map for a slice", m(1, cborText("l"), m(1, cborText("a"), cborText("abc"))), 0},
		{"wrong type: array for a map", m(1, cborText("m"), cborHead(majorArray, 1), cborText("abc")), 0},
		{"wrong type: array for a struct", m(1, cborText("p"), cborHead(majorArray, 2), []byte{1, 2}), isize},
		{"wrong type: integer for a string", m(1, cborText("s"), cborHead(majorUint, 70000)), 0},
		{"an array as bytes", m(1, cborText("b"), cborHead(majorArray, 1), []byte{1}), 1},
		{"float", m(1, cborText("N"), []byte{0xfb, 0, 0, 0, 0, 0, 0, 0, 0}), 0},
		{"simple value", m(1, cborText("N"), []byte{0xf8, 0x20}), 0},
		{"wrong type at the top", cborHead(majorArray, 0), 0},
	} {
		got, err := decodedCost(c.in, ty)
		if err != nil || got != c.want+size {
			t.Errorf("%s: %d, %v; want %d", c.name, got, err, c.want+size)
		}
	}

	for _, c := range []struct {
		name string
		in   []byte
		want string
	}{
		{"nothing", nil, "cut off"},
		{"a head cut off", []byte{0xa1, 0x61, 's', 0x79, 0}, "head is cut off"},
		{"a string cut off", m(1, cborText("s"), cborHead(majorText, 5), []byte("ab")), "string is cut off"},
		{"an array cut off", m(1, cborText("l"), cborHead(majorArray, 5), m(0)), "array is cut off"},
		{"a map cut off", m(3, cborText("s")), "map is cut off"},
		{"an item cut off", m(1, cborText("s")), "item is cut off"},
		{"a tag", m(1, cborText("s"), []byte{0xc0}, cborText("x")), "a tag"},
		{"a length not definite", m(1, cborText("s"), []byte{0x7f, 0xff}), "not definite"},
		{"a reserved head", m(1, cborText("s"), []byte{0x1c}), "reserved"},
		{"a tag in a skipped value", m(1, cborText("later"), cborHead(majorArray, 1), []byte{0xc0, 1}), "a tag"},
		{"a tag as a key", m(1, []byte{0xc0, 1}, []byte{1}), "a tag"},
		{"a bad value of an unknown key", m(1, cborText("later"), []byte{0x1c}), "reserved"},
		{"a bad key of a map", m(1, cborText("m"), m(1, []byte{0x1c}, []byte{1})), "reserved"},
		{"a bad value of a map", m(1, cborText("m"), m(1, cborText("k"), []byte{0x1c})), "reserved"},
		{"a bad element", m(1, cborText("l"), cborHead(majorArray, 1), []byte{0x1c}), "reserved"},
		{"a bad pointer", m(1, cborText("p"), []byte{0x1c}), "reserved"},
		{"a pointer cut off", m(1, cborText("p")), "item is cut off"},
		{"a bad array as a key", m(1, cborHead(majorArray, 1), []byte{0x1c}, []byte{1}), "reserved"},
		{"an array as a parameter", m(1, cborText("any"), cborHead(majorArray, 0)), "not an integer"},
		{"a map as a parameter", m(1, cborText("any"), m(0)), "not an integer"},
		{"bytes as a parameter", m(1, cborText("any"), cborHead(majorBytes, 0)), "not an integer"},
		{"null as a parameter", m(1, cborText("any"), []byte{0xf6}), "not an integer"},
	} {
		_, err := decodedCost(c.in, ty)
		if !errors.Is(err, ErrCorruptIndex) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error with %q", c.name, err, c.want)
		}
	}
}

// TestIndexMemoryLimit: an index may decode to MaxIndexMemoryRatio times
// its bytes, and a small one to MinIndexMemory.
func TestIndexMemoryLimit(t *testing.T) {
	member := uint64(reflect.TypeFor[Member]().Size())
	// The most empty members that MinIndexMemory allows, and one more.
	small := int((MinIndexMemory - uint64(reflect.TypeFor[Index]().Size())) / member)
	for _, c := range []struct {
		n       int
		tooMany bool
	}{{small, false}, {small + 1, true}} {
		_, err := DecodeIndex(emptyMembers(c.n), 0, nil)
		if c.tooMany != errors.Is(err, ErrIndexTooLarge) {
			t.Errorf("%d empty members: %v", c.n, err)
		}
	}
}

// TestValidateCodecs: the catalog has at most MaxCodecs entries, an entry
// at most MaxCodecParams parameters, and a parameter is an integer or a text
// string.
func TestValidateCodecs(t *testing.T) {
	ix := sampleIndex()
	ix.Codecs[1].Params = map[string]any{"a": 1, "b": int64(-1), "c": uint64(2), "d": "on"}
	if err := ix.Validate(); err != nil {
		t.Errorf("integers and text: %v", err)
	}
	for _, v := range []any{1.5, true, nil, []byte("x"), []any{}, map[any]any{}} {
		ix.Codecs[1].Params = map[string]any{"x": v}
		if err := ix.Validate(); !errors.Is(err, ErrCorruptIndex) {
			t.Errorf("a parameter of type %T: %v", v, err)
		}
	}

	ix.Codecs[1].Params = map[string]any{}
	for i := range MaxCodecParams {
		ix.Codecs[1].Params[fmt.Sprint(i)] = 1
	}
	if err := ix.Validate(); err != nil {
		t.Errorf("%d parameters: %v", MaxCodecParams, err)
	}
	ix.Codecs[1].Params["one more"] = 1
	if err := ix.Validate(); !errors.Is(err, ErrCorruptIndex) {
		t.Errorf("%d parameters: %v", MaxCodecParams+1, err)
	}

	ix = sampleIndex()
	for len(ix.Codecs) < MaxCodecs {
		ix.Codecs = append(ix.Codecs, CodecSpec{Name: "xz"})
	}
	if err := ix.Validate(); err != nil {
		t.Errorf("%d codecs: %v", MaxCodecs, err)
	}
	ix.Codecs = append(ix.Codecs, CodecSpec{Name: "xz"})
	if err := ix.Validate(); !errors.Is(err, ErrIndexTooLarge) {
		t.Errorf("%d codecs: %v", MaxCodecs+1, err)
	}
}

// TestIndexMemoryLimitIsInclusive: an index that needs exactly the limit
// decodes, and one byte more is refused.
func TestIndexMemoryLimitIsInclusive(t *testing.T) {
	member := uint64(reflect.TypeFor[Member]().Size())
	room := MinIndexMemory - uint64(reflect.TypeFor[Index]().Size())
	n, path := int(room/member), int(room%member)
	for _, extra := range []int{0, 1} {
		raw := emptyMembers(n)
		// The first member gets a path, which costs its length.
		first := bytes.IndexByte(raw, 0xa0)
		withPath := cat(cborHead(majorMap, 1), cborText("path"), cborText(strings.Repeat("p", path+extra)))
		raw = cat(raw[:first], withPath, raw[first+1:])
		if cost, err := decodedCost(raw, reflect.TypeFor[Index]()); err != nil || cost != MinIndexMemory+uint64(extra) {
			t.Fatalf("the cost is %d, %v; want %d", cost, err, MinIndexMemory+extra)
		}
		_, err := DecodeIndex(raw, 0, nil)
		if tooLarge := errors.Is(err, ErrIndexTooLarge); tooLarge != (extra == 1) {
			t.Errorf("%d bytes over the limit: %v", extra, err)
		}
	}
}

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
