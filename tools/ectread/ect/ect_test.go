package ect

import (
	"bytes"
	"encoding/binary"
	"errors"
	"go/parser"
	"go/token"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"lukechampine.com/blake3"
)

const goldenDir = "../../../src/internal/archive/testdata/golden"

// TestNoCodeOfEictar checks that the reader and its command import no
// package of eictar: the reader is written from doc/format.md alone.
func TestNoCodeOfEictar(t *testing.T) {
	for _, dir := range []string{".", ".."} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		if len(files) == 0 {
			t.Fatalf("no Go file in %s", dir)
		}
		for _, f := range files {
			ast, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range ast.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				if strings.HasPrefix(p, "github.com/philmalin/eictar/") && p != "github.com/philmalin/eictar/tools/ectread/ect" {
					t.Errorf("%s imports %s", f, p)
				}
			}
		}
	}
}

func TestCBOR(t *testing.T) {
	deep := strings.Repeat("81", maxDepth+1) + "00"
	for _, tc := range []struct {
		hex, refusal string
	}{
		{"a2616100616201", ""},
		{"a2616100616101", "duplicate key"},
		{"9f00ff", "indefinite"},
		{"5f4100ff", "indefinite"},
		{"c000", "a tag"},
		{"0000", "after the item"},
		{"5bffffffffffffffff", "length"},
		{"3bffffffffffffffff", "int64"},
		{"1c", "reserved"},
		{"f818", "two bytes"},
		{"ff", "break"},
		{"a1810000", "map key"},
		{"1a0000", "ends early"},
		{deep, "nested"},
		{strings.Repeat("81", maxDepth) + "00", ""},
		{"f4f5f6f7f93c00fa3f800000fb3ff0000000000000", "after the item"},
	} {
		b := mustHex(t, tc.hex)
		_, err := decodeCBOR(b)
		if tc.refusal == "" {
			if err != nil {
				t.Errorf("%s: %v", tc.hex, err)
			}
			continue
		}
		var r *RefusedError
		if !errors.As(err, &r) || !strings.Contains(err.Error(), tc.refusal) {
			t.Errorf("%s: %v, want a refusal with %q", tc.hex, err, tc.refusal)
		}
	}
	v, err := decodeCBOR(mustHex(t, "85f4f5f93e00fa3f800000fb4000000000000000"))
	if err != nil {
		t.Fatal(err)
	}
	want := []any{false, true, 1.5, 1.0, 2.0}
	for i, w := range want {
		if v.([]any)[i] != w {
			t.Errorf("item %d: %v, want %v", i, v.([]any)[i], w)
		}
	}
	for h, w := range map[uint16]float64{0x0001: 5.960464477539063e-08, 0x7bff: 65504, 0xc000: -2} {
		if got := halfToFloat(h); got != w {
			t.Errorf("half %#x: %v, want %v", h, got, w)
		}
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b := make([]byte, len(s)/2)
	for i := range b {
		v, err := strconv.ParseUint(s[2*i:2*i+2], 16, 8)
		if err != nil {
			t.Fatal(err)
		}
		b[i] = byte(v)
	}
	return b
}

func TestGoldens(t *testing.T) {
	for _, g := range []struct {
		name    string
		pass    []byte
		members int
	}{
		{"plain.ect", nil, 8}, {"encrypted.ect", []byte("golden"), 8},
		{"dict.ect", []byte("golden"), 61}, {"shared.ect", nil, 3},
	} {
		a, err := Open(filepath.Join(goldenDir, g.name), Options{Passphrase: g.pass})
		if err != nil {
			t.Fatalf("%s: %v", g.name, err)
		}
		if n := len(a.Live()); n != g.members {
			t.Errorf("%s: %d live members, want %d", g.name, n, g.members)
		}
		for _, m := range a.Live() {
			if m.Type == "reg" || m.Type == "hardlink" {
				if err := a.Content(m, io.Discard); err != nil {
					t.Errorf("%s: %s: %v", g.name, m.Path, err)
				}
			}
		}
		a.Close()
	}
}

func TestPassphrase(t *testing.T) {
	enc := filepath.Join(goldenDir, "encrypted.ect")
	if _, err := Open(enc, Options{}); !errors.Is(err, ErrNeedPassphrase) {
		t.Errorf("no passphrase: %v", err)
	}
	if _, err := Open(enc, Options{Passphrase: []byte("Golden")}); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("a wrong passphrase: %v", err)
	}
	if _, err := Open(enc, Options{Passphrase: []byte("golden"), MaxKDFMemoryKiB: 8}); !isRefusal(err, "more than the limit") {
		t.Errorf("a limit on the memory: %v", err)
	}
	if _, err := Open(filepath.Join(goldenDir, "plain.ect"), Options{Passphrase: []byte("golden")}); !isRefusal(err, "not encrypted") {
		t.Errorf("a plain archive, and an encrypted one expected: %v", err)
	}
}

func isRefusal(err error, reason string) bool {
	var r *RefusedError
	return errors.As(err, &r) && strings.Contains(r.Reason, reason)
}

func readGolden(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(goldenDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func openBytes(b []byte, opt Options) (*Archive, error) {
	return read(bytes.NewReader(b), int64(len(b)), opt)
}

func fixCRC(b []byte, n int) {
	binary.LittleEndian.PutUint32(b[n:], crc32.Checksum(b[:n], castagnoli))
}

// TestHeaderAndTrailer changes the fixed parts of the plain golden archive.
func TestHeaderAndTrailer(t *testing.T) {
	golden := readGolden(t, "plain.ect")
	end := len(golden) - trailerSize
	for _, tc := range []struct {
		name    string
		change  func(b []byte)
		refusal string
	}{
		{"magic", func(b []byte) { b[0] = 'X' }, "magic"},
		{"header CRC", func(b []byte) { b[30]++ }, "CRC of the file header"},
		{"major", func(b []byte) { b[8] = 2; fixCRC(b, 60) }, "format_major"},
		{"a newer minor", func(b []byte) { b[10] = 7; fixCRC(b, 60) }, "version of the trailer"},
		{"header flag", func(b []byte) { b[13] = 1; fixCRC(b, 60) }, "header_flags"},
		{"header reserved", func(b []byte) { b[50] = 1; fixCRC(b, 60) }, "reserved byte of the file header"},
		{"crypto length", func(b []byte) { b[40] = 4; fixCRC(b, 60) }, "crypto header of 4"},
		{"trailer magic", func(b []byte) { b[end] = 'X' }, "does not end with a trailer"},
		{"trailer CRC", func(b []byte) { b[end+20]++ }, "CRC of the trailer"},
		{"trailer flag", func(b []byte) { b[end+13] = 1; fixCRC(b[end:], 92) }, "trailer_flags"},
		{"sealed in plain", func(b []byte) { b[end+12] |= 1; fixCRC(b[end:], 92) }, "sealed index in a plain"},
		{"trailer reserved", func(b []byte) { b[end+90] = 1; fixCRC(b[end:], 92) }, "reserved byte of the trailer"},
		{"index digest", func(b []byte) { b[end+60]++; fixCRC(b[end:], 92) }, "digest of the index"},
		{"index before body", func(b []byte) { binary.LittleEndian.PutUint64(b[end+24:], 10); fixCRC(b[end:], 92) }, "not between"},
		{"index into trailer", func(b []byte) { binary.LittleEndian.PutUint64(b[end+32:], 1<<40); fixCRC(b[end:], 92) }, "not between"},
		{"short", func(b []byte) {}, "fewer than"},
	} {
		b := bytes.Clone(golden)
		tc.change(b)
		if tc.name == "short" {
			b = b[:100]
		}
		if _, err := openBytes(b, Options{}); !isRefusal(err, tc.refusal) {
			t.Errorf("%s: %v, want a refusal with %q", tc.name, err, tc.refusal)
		}
	}
	// A newer minor in both places is accepted.
	b := bytes.Clone(golden)
	b[10] = 7
	b[end+10] = 7
	fixCRC(b, 60)
	fixCRC(b[end:], 92)
	if _, err := openBytes(b, Options{}); err != nil {
		t.Errorf("a newer format_minor: %v", err)
	}
}

// encode is a CBOR encoder for the tests: it writes the values that
// decodeCBOR gives back.
func encode(v any) []byte {
	head := func(major byte, n uint64) []byte {
		switch {
		case n < 24:
			return []byte{major<<5 | byte(n)}
		case n < 1<<8:
			return []byte{major<<5 | 24, byte(n)}
		case n < 1<<16:
			return binary.BigEndian.AppendUint16([]byte{major<<5 | 25}, uint16(n))
		case n < 1<<32:
			return binary.BigEndian.AppendUint32([]byte{major<<5 | 26}, uint32(n))
		}
		return binary.BigEndian.AppendUint64([]byte{major<<5 | 27}, n)
	}
	switch v := v.(type) {
	case uint64:
		return head(0, v)
	case int64:
		if v >= 0 {
			return head(0, uint64(v))
		}
		return head(1, uint64(-1-v))
	case []byte:
		return append(head(2, uint64(len(v))), v...)
	case text:
		return append(head(3, uint64(len(v))), v...)
	case []any:
		out := head(4, uint64(len(v)))
		for _, x := range v {
			out = append(out, encode(x)...)
		}
		return out
	case *cmap:
		out := head(5, uint64(len(v.keys)))
		for i := range v.keys {
			out = append(append(out, encode(v.keys[i])...), encode(v.vals[i])...)
		}
		return out
	case bool:
		if v {
			return []byte{0xf5}
		}
		return []byte{0xf4}
	case simple:
		return []byte{0xe0 | byte(v)}
	}
	panic("encode: a type that the tests do not use")
}

func (m *cmap) set(key string, v any) {
	for i, k := range m.keys {
		if k == text(key) {
			m.vals[i] = v
			return
		}
	}
	m.keys = append(m.keys, text(key))
	m.vals = append(m.vals, v)
}

func (m *cmap) del(key string) {
	for i, k := range m.keys {
		if k == text(key) {
			m.keys = append(m.keys[:i:i], m.keys[i+1:]...)
			m.vals = append(m.vals[:i:i], m.vals[i+1:]...)
			return
		}
	}
}

// goldenIndex decodes the index of the plain golden archive.
func goldenIndex(t *testing.T, b []byte) *cmap {
	t.Helper()
	tr := b[len(b)-trailerSize:]
	off, n := binary.LittleEndian.Uint64(tr[24:]), binary.LittleEndian.Uint64(tr[32:])
	dec, err := zstd.NewReader(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Close()
	plain, err := dec.DecodeAll(b[off:off+n], nil)
	if err != nil {
		t.Fatal(err)
	}
	v, err := decodeCBOR(plain)
	if err != nil {
		t.Fatal(err)
	}
	return v.(*cmap)
}

// withIndex writes idx in the place of the index of the plain golden
// archive b, with a trailer that is correct for it: its length, its digest,
// its live members (live, when it is not -1) and its CRC.
func withIndex(t *testing.T, b []byte, idx *cmap, live int) []byte {
	t.Helper()
	enc, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	z := enc.EncodeAll(encode(idx), nil)
	enc.Close()
	tr := bytes.Clone(b[len(b)-trailerSize:])
	off := binary.LittleEndian.Uint64(tr[24:])
	binary.LittleEndian.PutUint64(tr[32:], uint64(len(z)))
	if live >= 0 {
		binary.LittleEndian.PutUint64(tr[48:], uint64(live))
	}
	h := blake3.New(32, nil)
	h.Write(b[24:40])
	h.Write(tr[16:24])
	h.Write(z)
	copy(tr[56:88], h.Sum(nil))
	fixCRC(tr, 92)
	return append(append(bytes.Clone(b[:off]), z...), tr...)
}

func memberOf(idx *cmap, id uint64) *cmap {
	ms, _ := idx.get("members")
	for _, m := range ms.([]any) {
		if v, _ := m.(*cmap).get("id"); v == id {
			return m.(*cmap)
		}
	}
	panic("no member " + strconv.FormatUint(id, 10))
}

func addMember(idx *cmap, m *cmap) {
	ms, _ := idx.get("members")
	idx.set("members", append(ms.([]any), m))
}

// TestIndexChecks breaks each rule of doc/format.md 8.4 in the index of the
// plain golden archive, and the reader must refuse it. The members of that
// index: 1 the directory g, 2 and 3 tombstones, 4 the file g/hard.txt (two
// chunks of zstd, stored), 5 a hardlink to 4, 6 a symbolic link, 7 a
// directory, 8 a file of four chunks, and 9 and 10 files with no codec.
func TestIndexChecks(t *testing.T) {
	golden := readGolden(t, "plain.ect")
	for _, tc := range []struct {
		name    string
		change  func(idx *cmap)
		live    int // the live members to write in the trailer, or -1
		refusal string
	}{
		{"no change", func(idx *cmap) {}, -1, ""},
		{"a key that is not known", func(idx *cmap) { memberOf(idx, 4).set("zz", text("x")); idx.set("later", uint64(1)) }, -1, ""},
		{"index version", func(idx *cmap) { idx.set("v", uint64(2)) }, -1, "index version 2"},
		{"generation", func(idx *cmap) { idx.set("gen", uint64(2)) }, -1, "generation 2"},
		{"no members", func(idx *cmap) { idx.del("members") }, -1, "has no members"},
		{"members null", func(idx *cmap) { idx.set("members", simple(22)) }, 0, ""},
		{"members false", func(idx *cmap) { idx.set("members", false) }, 0, "not an array"},
		{"two ids", func(idx *cmap) { memberOf(idx, 5).set("id", uint64(4)) }, -1, "two members have id 4"},
		{"id 0", func(idx *cmap) { memberOf(idx, 5).set("id", uint64(0)) }, -1, "id 0"},
		{"type", func(idx *cmap) { memberOf(idx, 7).set("type", text("door")) }, -1, "not known"},
		{"mode", func(idx *cmap) { memberOf(idx, 7).set("mode", uint64(0o10000)) }, -1, "more than 07777"},
		{"uid alone", func(idx *cmap) { memberOf(idx, 7).set("uid", uint64(1)) }, -1, "not both"},
		{"mtime", func(idx *cmap) { memberOf(idx, 7).del("mtime") }, -1, "has no mtime"},
		{"mtime type", func(idx *cmap) { memberOf(idx, 7).set("mtime", text("now")) }, -1, "not an integer"},
		{"size of a directory", func(idx *cmap) { memberOf(idx, 7).set("size", uint64(1)) }, -1, "a dir with size"},
		{"no link", func(idx *cmap) { memberOf(idx, 6).del("link") }, -1, "link on a symlink"},
		{"link on a file", func(idx *cmap) { memberOf(idx, 9).set("link", text("x")) }, -1, "link on a reg"},
		{"hardlink to a directory", func(idx *cmap) { memberOf(idx, 5).set("hardlink", uint64(7)) }, -1, "not a reg member"},
		{"hardlink to nothing", func(idx *cmap) { memberOf(idx, 5).set("hardlink", uint64(99)) }, -1, "not a reg member"},
		{"rdev on a file", func(idx *cmap) { memberOf(idx, 9).set("rdev", []any{uint64(1), uint64(3)}) }, -1, "rdev on a reg"},
		{"device without rdev", func(idx *cmap) { memberOf(idx, 7).set("type", text("chardev")) }, -1, "rdev on a chardev"},
		{"rdev of 3", func(idx *cmap) {
			memberOf(idx, 7).set("type", text("chardev"))
			memberOf(idx, 7).set("rdev", []any{uint64(1), uint64(3), uint64(0)})
		}, -1, "rdev has 3"},
		{"xattr name", func(idx *cmap) { memberOf(idx, 7).set("xattrs", &cmap{keys: []any{text("")}, vals: []any{[]byte{}}}) }, -1, "outside the limits"},
		{"xattr value", func(idx *cmap) {
			memberOf(idx, 7).set("xattrs", &cmap{keys: []any{text("user.x")}, vals: []any{make([]byte, maxXValue+1)}})
		}, -1, "outside the limits"},
		{"digest", func(idx *cmap) { memberOf(idx, 9).set("digest", make([]byte, 31)) }, -1, "31 bytes"},
		{"no digest", func(idx *cmap) { memberOf(idx, 9).del("digest") }, -1, "has no digest"},
		{"codec", func(idx *cmap) { memberOf(idx, 9).set("codec", int64(1)) }, -1, "not a catalog position"},
		{"codec -2", func(idx *cmap) { memberOf(idx, 9).set("codec", int64(-2)) }, -1, "not a catalog position"},
		{"dead false", func(idx *cmap) { memberOf(idx, 9).set("dead", false) }, -1, "dead is not true"},
		{"live count", func(idx *cmap) { memberOf(idx, 9).set("dead", true) }, -1, "live members"},
		{"chunks total", func(idx *cmap) { memberOf(idx, 9).set("chunks", []any{uint64(16), uint64(5)}) }, -1, "chunks total"},
		{"too few chunks", func(idx *cmap) { memberOf(idx, 9).set("chunk", uint64(8)) }, -1, "does not need 2 chunks"},
		{"too many chunks", func(idx *cmap) { memberOf(idx, 9).set("chunk", uint64(22)) }, -1, "does not need 2 chunks"},
		{"chunk 0", func(idx *cmap) { memberOf(idx, 9).set("chunk", uint64(0)) }, -1, "chunk 0"},
		{"no chunk", func(idx *cmap) { memberOf(idx, 9).del("chunk") }, -1, "has no chunk"},
		{"chunk alone", func(idx *cmap) { memberOf(idx, 9).del("chunks") }, -1, "chunk with no chunks"},
		{"empty chunks", func(idx *cmap) { memberOf(idx, 9).set("chunks", []any{}) }, -1, "chunks is empty"},
		{"chunks on a directory", func(idx *cmap) { memberOf(idx, 7).set("chunks", []any{uint64(1)}) }, -1, "chunks on a member"},
		{"no chunks for content", func(idx *cmap) {
			memberOf(idx, 9).del("chunks")
			memberOf(idx, 9).del("chunk")
			memberOf(idx, 9).del("len")
		}, -1, "does not need 0 chunks"},
		{"len with no chunks", func(idx *cmap) { memberOf(idx, 7).set("len", uint64(3)) }, -1, "len 3 with no chunks"},
		{"blob before the body", func(idx *cmap) { memberOf(idx, 9).set("off", uint64(60)) }, -1, "not inside the body"},
		{"blob over the index", func(idx *cmap) { memberOf(idx, 9).set("off", uint64(len(golden))) }, -1, "not inside the body"},
		{"sparse empty segment", func(idx *cmap) {
			memberOf(idx, 9).set("sparse", []any{&cmap{keys: []any{text("off"), text("len")}, vals: []any{uint64(0), uint64(0)}}})
		}, -1, "is empty"},
		{"sparse overlap", func(idx *cmap) {
			memberOf(idx, 9).set("sparse", []any{
				&cmap{keys: []any{text("off"), text("len")}, vals: []any{uint64(0), uint64(10)}},
				&cmap{keys: []any{text("off"), text("len")}, vals: []any{uint64(5), uint64(12)}},
			})
		}, -1, "overlaps"},
		{"sparse past the size", func(idx *cmap) {
			memberOf(idx, 9).set("sparse", []any{&cmap{keys: []any{text("off"), text("len")}, vals: []any{uint64(10), uint64(22)}}})
		}, -1, "ends after the size"},
		{"sparse on a directory", func(idx *cmap) { memberOf(idx, 7).set("sparse", []any{}) }, -1, "sparse on a dir"},
		{"enc on a directory", func(idx *cmap) {
			memberOf(idx, 7).set("enc", &cmap{keys: []any{text("salt")}, vals: []any{make([]byte, 16)}})
		}, -1, "enc on a member"},
		{"enc salt", func(idx *cmap) {
			memberOf(idx, 9).set("enc", &cmap{keys: []any{text("salt")}, vals: []any{make([]byte, 15)}})
		}, -1, "15 bytes"},
		{"data to a directory", func(idx *cmap) { addMember(idx, shared(11, 7, 22, nil)) }, 9, "not a reg member with a blob"},
		{"data to a reference", func(idx *cmap) {
			addMember(idx, shared(11, 9, 22, memberDigest(idx, 9)))
			addMember(idx, shared(12, 11, 22, memberDigest(idx, 9)))
		}, 10, "not a reg member with a blob"},
		{"data of another size", func(idx *cmap) { addMember(idx, shared(11, 9, 21, memberDigest(idx, 9))) }, 9, "another size"},
		{"data of another digest", func(idx *cmap) { addMember(idx, shared(11, 9, 22, make([]byte, 32))) }, 9, "another size"},
		{"data with a codec", func(idx *cmap) {
			m := shared(11, 9, 22, memberDigest(idx, 9))
			m.set("codec", int64(0))
			addMember(idx, m)
		}, 9, "codec 0 on a member with data"},
		{"data with off", func(idx *cmap) {
			m := shared(11, 9, 22, memberDigest(idx, 9))
			m.set("off", uint64(792))
			addMember(idx, m)
		}, 9, "off or len on a member with data"},
		{"data", func(idx *cmap) { addMember(idx, shared(11, 9, 22, memberDigest(idx, 9))) }, 9, ""},
		{"data to a tombstone", func(idx *cmap) { addMember(idx, shared(11, 2, 17, memberDigest(idx, 2))) }, 9, ""},
		{"catalog dict", func(idx *cmap) {
			cs, _ := idx.get("codecs")
			cs.([]any)[0].(*cmap).set("dict", uint64(40000))
		}, -1, "names no dictionary"},
		{"catalog params", func(idx *cmap) {
			cs, _ := idx.get("codecs")
			cs.([]any)[0].(*cmap).set("params", &cmap{keys: []any{text("level")}, vals: []any{[]any{}}})
		}, -1, "not a number or a text"},
		{"dict size", func(idx *cmap) { idx.set("dicts", []any{dict(40000, 0, 64)}) }, -1, "size 0"},
		{"dict id", func(idx *cmap) { idx.set("dicts", []any{dict(0, 8, 64)}) }, -1, "id 0"},
		{"dict len", func(idx *cmap) {
			d := dict(40000, 8, 64)
			d.set("len", uint64(9))
			idx.set("dicts", []any{d})
		}, -1, "len 9 is not 8"},
		{"two dicts", func(idx *cmap) { idx.set("dicts", []any{dict(40000, 8, 64), dict(40000, 8, 72)}) }, -1, "two dictionaries"},
		{"dict on flate", func(idx *cmap) {
			idx.set("dicts", []any{dict(40000, 8, 64)})
			cs, _ := idx.get("codecs")
			c := cs.([]any)[0].(*cmap)
			c.set("name", text("flate"))
			c.set("dict", uint64(40000))
		}, -1, "a dictionary on codec"},
		{"a dict", func(idx *cmap) { idx.set("dicts", []any{dict(40000, 8, 64)}) }, -1, ""},
	} {
		idx := goldenIndex(t, golden)
		tc.change(idx)
		_, err := openBytes(withIndex(t, golden, idx, tc.live), Options{})
		if tc.refusal == "" {
			if err != nil {
				t.Errorf("%s: %v", tc.name, err)
			}
		} else if !isRefusal(err, tc.refusal) {
			t.Errorf("%s: %v, want a refusal with %q", tc.name, err, tc.refusal)
		}
	}
}

func memberDigest(idx *cmap, id uint64) []byte {
	d, _ := memberOf(idx, id).get("digest")
	return d.([]byte)
}

// shared is a member with id that has the content of the member owner.
func shared(id, owner, size uint64, digest []byte) *cmap {
	m := &cmap{}
	for _, kv := range []struct {
		k string
		v any
	}{
		{"id", id}, {"gen", uint64(3)}, {"path", text("g/shared" + strconv.FormatUint(id, 10))}, {"type", text("reg")},
		{"mode", uint64(0o644)}, {"mtime", int64(0)}, {"size", size}, {"codec", int64(-1)}, {"data", owner},
	} {
		m.set(kv.k, kv.v)
	}
	if digest != nil {
		m.set("digest", digest)
	} else {
		m.set("digest", make([]byte, 32))
	}
	return m
}

// dict is a Dict map with its blob in the first bytes of the body.
func dict(id, size, off uint64) *cmap {
	m := &cmap{}
	for _, kv := range []struct {
		k string
		v any
	}{
		{"id", id}, {"gen", uint64(1)}, {"size", size}, {"digest", make([]byte, 32)}, {"off", off}, {"len", size},
	} {
		m.set(kv.k, kv.v)
	}
	return m
}

// TestContent changes the bytes of a blob, and the reader must refuse the
// member when it reads it.
func TestContent(t *testing.T) {
	golden := readGolden(t, "plain.ect")
	a, err := openBytes(golden, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range a.Live() {
		if m.Type != "reg" || !m.HasBlob {
			continue
		}
		for _, at := range []uint64{m.Off, m.Off + m.Len - 1} {
			b := bytes.Clone(golden)
			b[at] ^= 0x40
			a, err := openBytes(b, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if err := a.Content(a.ByID(m.ID), io.Discard); !isRefusal(err, "") {
				t.Errorf("%s: a byte changed at %d: %v", m.Path, at, err)
			}
		}
	}
}
