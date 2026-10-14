package ect

import "fmt"

// The index map and its checks (format.md 8).

// Codec is an entry of the catalog (format.md 6).
type Codec struct {
	Name string
	Dict uint32 // 0 for none
}

// Dict is a Dict map (format.md 8.2).
type Dict struct {
	ID       uint32
	Gen      uint64
	Size     uint64
	Digest   []byte
	Salt     []byte // nil when not sealed
	Off, Len uint64
}

// Segment is a data segment of a sparse file (format.md 9.3).
type Segment struct{ Off, Len uint64 }

// Member is a Member map (format.md 8.3).
type Member struct {
	ID, Gen      uint64
	Path         string
	Type         string
	Mode         uint64
	HasOwner     bool
	UID, GID     uint64
	Uname, Gname *string
	Mtime        int64
	Atime, Ctime *int64
	Size         uint64
	Link         string
	Hardlink     uint64 // the id of the target, for a hardlink
	Data         uint64 // the id of the owner of the content, or 0
	Rdev         *[2]uint64
	Xattrs       map[string][]byte
	Sparse       []Segment
	IsSparse     bool
	Digest       []byte
	Codec        int64
	Chunk        uint64
	Salt         []byte
	HasBlob      bool
	Off, Len     uint64
	Chunks       []uint64
	Dead         bool
}

// PayloadSize is the length of the payload (format.md 5).
func (m *Member) PayloadSize() uint64 {
	if !m.IsSparse {
		return m.Size
	}
	var n uint64
	for _, s := range m.Sparse {
		n += s.Len
	}
	return n
}

// Live returns the members without dead, in the order of the index.
func (a *Archive) Live() []*Member {
	var out []*Member
	for _, m := range a.Members {
		if !m.Dead {
			out = append(out, m)
		}
	}
	return out
}

// ByID returns the member with an id.
func (a *Archive) ByID(id uint64) *Member { return a.byID[id] }

const (
	maxMembers = 4194304
	maxDicts   = 1024
	maxDictSz  = 1048576
	maxChunk   = 268435456
	maxXName   = 255
	maxXValue  = 65536
	maxXCount  = 1024
)

func needUint(m *cmap, key, where string) (uint64, error) {
	v, ok := m.get(key)
	if !ok {
		return 0, refusef("%s has no %s", where, key)
	}
	u, ok := v.(uint64)
	if !ok {
		return 0, refusef("%s: %s is not an unsigned integer", where, key)
	}
	return u, nil
}

func optUint(m *cmap, key, where string) (uint64, bool, error) {
	if _, ok := m.get(key); !ok {
		return 0, false, nil
	}
	u, err := needUint(m, key, where)
	return u, err == nil, err
}

func needInt(m *cmap, key, where string) (int64, error) {
	v, ok := m.get(key)
	if !ok {
		return 0, refusef("%s has no %s", where, key)
	}
	switch v := v.(type) {
	case int64:
		return v, nil
	case uint64:
		if v > 1<<63-1 {
			return 0, refusef("%s: %s is too large for an int64", where, key)
		}
		return int64(v), nil
	}
	return 0, refusef("%s: %s is not an integer", where, key)
}

func optInt(m *cmap, key, where string) (*int64, error) {
	if _, ok := m.get(key); !ok {
		return nil, nil
	}
	i, err := needInt(m, key, where)
	if err != nil {
		return nil, err
	}
	return &i, nil
}

func needText(m *cmap, key, where string) (string, error) {
	v, ok := m.get(key)
	if !ok {
		return "", refusef("%s has no %s", where, key)
	}
	t, ok := v.(text)
	if !ok {
		return "", refusef("%s: %s is not a text string", where, key)
	}
	return string(t), nil
}

func optText(m *cmap, key, where string) (*string, error) {
	if _, ok := m.get(key); !ok {
		return nil, nil
	}
	s, err := needText(m, key, where)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// needBytes gets a byte string of size bytes, or of any size for -1.
func needBytes(m *cmap, key, where string, size int) ([]byte, error) {
	v, ok := m.get(key)
	if !ok {
		return nil, refusef("%s has no %s", where, key)
	}
	b, ok := v.([]byte)
	if !ok {
		return nil, refusef("%s: %s is not a byte string", where, key)
	}
	if size >= 0 && len(b) != size {
		return nil, refusef("%s: %s has %d bytes, not %d", where, key, len(b), size)
	}
	return b, nil
}

func needArray(m *cmap, key, where string) ([]any, error) {
	v, ok := m.get(key)
	if !ok {
		return nil, refusef("%s has no %s", where, key)
	}
	a, ok := v.([]any)
	if !ok {
		return nil, refusef("%s: %s is not an array", where, key)
	}
	return a, nil
}

func needMap(m *cmap, key, where string) (*cmap, error) {
	v, ok := m.get(key)
	if !ok {
		return nil, refusef("%s has no %s", where, key)
	}
	mm, ok := v.(*cmap)
	if !ok {
		return nil, refusef("%s: %s is not a map", where, key)
	}
	return mm, nil
}

func has(m *cmap, key string) bool {
	_, ok := m.get(key)
	return ok
}

// encSalt reads the map { "salt": 16 bytes }.
func encSalt(m *cmap, where string) ([]byte, error) {
	enc, err := needMap(m, "enc", where)
	if err != nil {
		return nil, err
	}
	return needBytes(enc, "salt", where+": enc", 16)
}

func (a *Archive) parseIndex(v any, live uint64) error {
	top, ok := v.(*cmap)
	if !ok {
		return refusef("the index is not a map")
	}
	ver, err := needUint(top, "v", "the index")
	if err != nil {
		return err
	}
	if ver != 1 {
		return refusef("index version %d is not known", ver)
	}
	gen, err := needUint(top, "gen", "the index")
	if err != nil {
		return err
	}
	if gen != a.Generation {
		return refusef("the index has generation %d, and the trailer %d", gen, a.Generation)
	}
	if err := a.parseDicts(top); err != nil {
		return err
	}
	if err := a.parseCodecs(top); err != nil {
		return err
	}
	var members []any
	if v, _ := top.get("members"); v != simple(22) {
		// eictar v1.1.1 and earlier wrote null for no members.
		if members, err = needArray(top, "members", "the index"); err != nil {
			return err
		}
	}
	if len(members) > maxMembers {
		return refusef("the index has %d members, more than %d", len(members), maxMembers)
	}
	a.byID = make(map[uint64]*Member, len(members))
	var count uint64
	for i, raw := range members {
		mm, ok := raw.(*cmap)
		if !ok {
			return refusef("member %d is not a map", i)
		}
		m, err := a.parseMember(mm, fmt.Sprintf("member %d", i))
		if err != nil {
			return err
		}
		if a.byID[m.ID] != nil {
			return refusef("two members have id %d", m.ID)
		}
		a.byID[m.ID] = m
		a.Members = append(a.Members, m)
		if !m.Dead {
			count++
		}
	}
	if count != live {
		return refusef("the index has %d live members, and the trailer %d", count, live)
	}
	for _, m := range a.Members {
		if err := a.checkReferences(m); err != nil {
			return err
		}
	}
	return nil
}

func (a *Archive) parseDicts(top *cmap) error {
	a.Dicts = map[uint32]*Dict{}
	if !has(top, "dicts") {
		return nil
	}
	arr, err := needArray(top, "dicts", "the index")
	if err != nil {
		return err
	}
	if len(arr) > maxDicts {
		return refusef("the index has %d dictionaries, more than %d", len(arr), maxDicts)
	}
	for i, raw := range arr {
		where := fmt.Sprintf("dictionary %d", i)
		m, ok := raw.(*cmap)
		if !ok {
			return refusef("%s is not a map", where)
		}
		id, err := needUint(m, "id", where)
		if err != nil {
			return err
		}
		if id < 1 || id > 1<<32-1 {
			return refusef("%s: id %d is outside 1 to 2^32-1", where, id)
		}
		d := &Dict{ID: uint32(id)}
		if d.Gen, err = needUint(m, "gen", where); err != nil {
			return err
		}
		if d.Size, err = needUint(m, "size", where); err != nil {
			return err
		}
		if d.Size < 1 || d.Size > maxDictSz {
			return refusef("%s: size %d is outside 1 to %d", where, d.Size, maxDictSz)
		}
		if d.Digest, err = needBytes(m, "digest", where, 32); err != nil {
			return err
		}
		if has(m, "enc") {
			if d.Salt, err = encSalt(m, where); err != nil {
				return err
			}
		} else if a.Encrypted {
			return refusef("%s has no enc in an encrypted archive", where)
		}
		if d.Off, err = needUint(m, "off", where); err != nil {
			return err
		}
		if d.Len, err = needUint(m, "len", where); err != nil {
			return err
		}
		want := d.Size
		if d.Salt != nil {
			want += 16
		}
		if d.Len != want {
			return refusef("%s: len %d is not %d", where, d.Len, want)
		}
		if err := a.checkBlob(d.Off, d.Len, where); err != nil {
			return err
		}
		if a.Dicts[d.ID] != nil {
			return refusef("two dictionaries have id %d", d.ID)
		}
		a.Dicts[d.ID] = d
	}
	return nil
}

func (a *Archive) parseCodecs(top *cmap) error {
	if !has(top, "codecs") {
		return nil
	}
	arr, err := needArray(top, "codecs", "the index")
	if err != nil {
		return err
	}
	for i, raw := range arr {
		where := fmt.Sprintf("codec %d", i)
		m, ok := raw.(*cmap)
		if !ok {
			return refusef("%s is not a map", where)
		}
		name, err := needText(m, "name", where)
		if err != nil {
			return err
		}
		params, err := needMap(m, "params", where)
		if err != nil {
			return err
		}
		for j, k := range params.keys {
			if _, ok := k.(text); !ok {
				return refusef("%s: a parameter name is not a text string", where)
			}
			switch params.vals[j].(type) {
			case uint64, int64, float64, text:
			default:
				return refusef("%s: parameter %q is not a number or a text string", where, k)
			}
		}
		c := Codec{Name: name}
		if id, ok, err := optUint(m, "dict", where); err != nil {
			return err
		} else if ok {
			if id > 1<<32-1 || a.Dicts[uint32(id)] == nil || id == 0 {
				return refusef("%s: dict %d names no dictionary", where, id)
			}
			if name != "zstd" {
				return refusef("%s: a dictionary on codec %q", where, name)
			}
			c.Dict = uint32(id)
		}
		a.Codecs = append(a.Codecs, c)
	}
	return nil
}

// checkBlob checks that a blob lies inside [body start, index_offset).
func (a *Archive) checkBlob(off, n uint64, where string) error {
	if off < a.bodyStart || off > a.indexOffset || n > a.indexOffset-off {
		return refusef("%s: the blob at %d, of %d bytes, is not inside the body", where, off, n)
	}
	return nil
}

var types = map[string]bool{"reg": true, "dir": true, "symlink": true, "hardlink": true,
	"fifo": true, "sock": true, "chardev": true, "blockdev": true}

func (a *Archive) parseMember(mm *cmap, where string) (*Member, error) {
	m := &Member{}
	var err error
	if m.ID, err = needUint(mm, "id", where); err != nil {
		return nil, err
	}
	if m.ID == 0 {
		return nil, refusef("%s: id 0", where)
	}
	where = fmt.Sprintf("member id %d", m.ID)
	if m.Gen, err = needUint(mm, "gen", where); err != nil {
		return nil, err
	}
	if m.Path, err = needText(mm, "path", where); err != nil {
		return nil, err
	}
	if m.Type, err = needText(mm, "type", where); err != nil {
		return nil, err
	}
	if !types[m.Type] {
		return nil, refusef("%s: type %q is not known", where, m.Type)
	}
	reg := m.Type == "reg"
	if m.Mode, err = needUint(mm, "mode", where); err != nil {
		return nil, err
	}
	if m.Mode > 0o7777 {
		return nil, refusef("%s: mode %o is more than 07777", where, m.Mode)
	}
	if has(mm, "uid") != has(mm, "gid") {
		return nil, refusef("%s: uid and gid are not both present", where)
	}
	if has(mm, "uid") {
		m.HasOwner = true
		if m.UID, err = needUint(mm, "uid", where); err != nil {
			return nil, err
		}
		if m.GID, err = needUint(mm, "gid", where); err != nil {
			return nil, err
		}
	}
	if m.Uname, err = optText(mm, "uname", where); err != nil {
		return nil, err
	}
	if m.Gname, err = optText(mm, "gname", where); err != nil {
		return nil, err
	}
	if m.Mtime, err = needInt(mm, "mtime", where); err != nil {
		return nil, err
	}
	if m.Atime, err = optInt(mm, "atime", where); err != nil {
		return nil, err
	}
	if m.Ctime, err = optInt(mm, "ctime", where); err != nil {
		return nil, err
	}
	if m.Size, err = needUint(mm, "size", where); err != nil {
		return nil, err
	}
	if !reg && m.Size != 0 {
		return nil, refusef("%s: a %s with size %d", where, m.Type, m.Size)
	}
	if has(mm, "link") != (m.Type == "symlink") {
		return nil, refusef("%s: link on a %s", where, m.Type)
	}
	if m.Type == "symlink" {
		if m.Link, err = needText(mm, "link", where); err != nil {
			return nil, err
		}
	}
	if has(mm, "hardlink") != (m.Type == "hardlink") {
		return nil, refusef("%s: hardlink on a %s", where, m.Type)
	}
	if m.Type == "hardlink" {
		if m.Hardlink, err = needUint(mm, "hardlink", where); err != nil {
			return nil, err
		}
	}
	if has(mm, "data") {
		if !reg {
			return nil, refusef("%s: data on a %s", where, m.Type)
		}
		if m.Data, err = needUint(mm, "data", where); err != nil {
			return nil, err
		}
	}
	dev := m.Type == "chardev" || m.Type == "blockdev"
	if has(mm, "rdev") != dev {
		return nil, refusef("%s: rdev on a %s", where, m.Type)
	}
	if dev {
		arr, err := needArray(mm, "rdev", where)
		if err != nil {
			return nil, err
		}
		if len(arr) != 2 {
			return nil, refusef("%s: rdev has %d items", where, len(arr))
		}
		var r [2]uint64
		for i, x := range arr {
			u, ok := x.(uint64)
			if !ok {
				return nil, refusef("%s: rdev is not two unsigned integers", where)
			}
			r[i] = u
		}
		m.Rdev = &r
	}
	if err := m.parseXattrs(mm, where); err != nil {
		return nil, err
	}
	if has(mm, "sparse") {
		if !reg {
			return nil, refusef("%s: sparse on a %s", where, m.Type)
		}
		if err := m.parseSparse(mm, where); err != nil {
			return nil, err
		}
	}
	if has(mm, "digest") || reg {
		if m.Digest, err = needBytes(mm, "digest", where, 32); err != nil {
			return nil, err
		}
	}
	if m.Codec, err = needInt(mm, "codec", where); err != nil {
		return nil, err
	}
	if m.Codec < -1 || m.Codec >= int64(len(a.Codecs)) {
		return nil, refusef("%s: codec %d is not a catalog position", where, m.Codec)
	}
	if has(mm, "dead") {
		v, _ := mm.get("dead")
		if b, ok := v.(bool); !ok || !b {
			return nil, refusef("%s: dead is not true", where)
		}
		m.Dead = true
	}
	if err := a.parseBlob(m, mm, where); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Member) parseXattrs(mm *cmap, where string) error {
	if !has(mm, "xattrs") {
		return nil
	}
	x, err := needMap(mm, "xattrs", where)
	if err != nil {
		return err
	}
	if len(x.keys) > maxXCount {
		return refusef("%s: %d xattrs, more than %d", where, len(x.keys), maxXCount)
	}
	m.Xattrs = make(map[string][]byte, len(x.keys))
	for i, k := range x.keys {
		name, ok := k.(text)
		if !ok {
			return refusef("%s: an xattr name is not a text string", where)
		}
		val, ok := x.vals[i].([]byte)
		if !ok {
			return refusef("%s: xattr %q is not a byte string", where, name)
		}
		if len(name) < 1 || len(name) > maxXName || len(val) > maxXValue {
			return refusef("%s: xattr %q has a name or value outside the limits", where, name)
		}
		m.Xattrs[string(name)] = val
	}
	return nil
}

func (m *Member) parseSparse(mm *cmap, where string) error {
	arr, err := needArray(mm, "sparse", where)
	if err != nil {
		return err
	}
	m.IsSparse = true
	var end uint64
	for i, raw := range arr {
		s, ok := raw.(*cmap)
		if !ok {
			return refusef("%s: sparse segment %d is not a map", where, i)
		}
		var seg Segment
		if seg.Off, err = needUint(s, "off", where+": sparse"); err != nil {
			return err
		}
		if seg.Len, err = needUint(s, "len", where+": sparse"); err != nil {
			return err
		}
		switch {
		case seg.Len == 0:
			return refusef("%s: sparse segment %d is empty", where, i)
		case seg.Off < end:
			return refusef("%s: sparse segment %d is out of order or overlaps", where, i)
		case seg.Off > m.Size || seg.Len > m.Size-seg.Off:
			return refusef("%s: sparse segment %d ends after the size", where, i)
		}
		end = seg.Off + seg.Len
		m.Sparse = append(m.Sparse, seg)
	}
	return nil
}

// parseBlob reads chunk, chunks, enc, off and len (format.md 8.3, 8.4, 8.5).
func (a *Archive) parseBlob(m *Member, mm *cmap, where string) error {
	var err error
	hasChunks := has(mm, "chunks")
	if !hasChunks && has(mm, "chunk") {
		return refusef("%s: chunk with no chunks", where)
	}
	if hasChunks {
		if m.Type != "reg" || m.Data != 0 {
			return refusef("%s: chunks on a member with no blob of its own", where)
		}
		arr, err := needArray(mm, "chunks", where)
		if err != nil {
			return err
		}
		if len(arr) == 0 {
			return refusef("%s: chunks is empty", where)
		}
		if m.Chunk, err = needUint(mm, "chunk", where); err != nil {
			return err
		}
		if m.Chunk == 0 || m.Chunk > maxChunk {
			return refusef("%s: chunk %d is outside 1 to %d", where, m.Chunk, maxChunk)
		}
		var total uint64
		for _, x := range arr {
			n, ok := x.(uint64)
			if !ok {
				return refusef("%s: a chunk length is not an unsigned integer", where)
			}
			if n > 1<<62 || total > 1<<62 {
				return refusef("%s: the chunk lengths are too large", where)
			}
			total += n
			m.Chunks = append(m.Chunks, n)
		}
		m.HasBlob = true
		if m.Off, err = needUint(mm, "off", where); err != nil {
			return err
		}
		if m.Len, err = needUint(mm, "len", where); err != nil {
			return err
		}
		if total != m.Len {
			return refusef("%s: the chunks total %d, and len is %d", where, total, m.Len)
		}
		if err := a.checkBlob(m.Off, m.Len, where); err != nil {
			return err
		}
	} else {
		if m.Data != 0 {
			if has(mm, "off") || has(mm, "len") {
				return refusef("%s: off or len on a member with data", where)
			}
		} else {
			// No blob: eictar 1.1.0 and earlier wrote an off here, on
			// each type, with len 0 or no len.
			if _, _, err := optUint(mm, "off", where); err != nil {
				return err
			}
			if n, ok, err := optUint(mm, "len", where); err != nil {
				return err
			} else if ok && n != 0 {
				return refusef("%s: len %d with no chunks", where, n)
			}
		}
	}
	n := uint64(len(m.Chunks))
	p := m.PayloadSize()
	if m.Data == 0 && (n == 0 && p != 0 || n > 0 && (p <= m.Chunk*(n-1) || p > m.Chunk*n)) {
		return refusef("%s: a payload of %d bytes does not need %d chunks of %d", where, p, n, m.Chunk)
	}
	if has(mm, "enc") {
		if m.Type != "reg" || m.Data != 0 {
			return refusef("%s: enc on a member with no blob of its own", where)
		}
		if m.Salt, err = encSalt(mm, where); err != nil {
			return err
		}
	} else if a.Encrypted && m.HasBlob {
		return refusef("%s has chunks and no enc in an encrypted archive", where)
	}
	if m.Data != 0 && m.Codec != -1 {
		return refusef("%s: codec %d on a member with data", where, m.Codec)
	}
	return nil
}

// checkReferences checks hardlink and data (format.md 8.4, 8.5).
func (a *Archive) checkReferences(m *Member) error {
	where := fmt.Sprintf("member id %d", m.ID)
	if m.Type == "hardlink" {
		t := a.byID[m.Hardlink]
		if t == nil || t.Type != "reg" {
			return refusef("%s: hardlink %d is not a reg member", where, m.Hardlink)
		}
	}
	if m.Data != 0 {
		o := a.byID[m.Data]
		switch {
		case o == nil || o.Type != "reg" || !o.HasBlob || o.Data != 0:
			return refusef("%s: data %d is not a reg member with a blob and no data", where, m.Data)
		case o.Size != m.Size || o.IsSparse != m.IsSparse || !sameSegments(o.Sparse, m.Sparse) || string(o.Digest) != string(m.Digest):
			return refusef("%s: data %d has another size, sparse or digest", where, m.Data)
		}
	}
	return nil
}

func sameSegments(a, b []Segment) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
