package archive

import (
	"encoding/binary"
	"io"
	"sync"

	"github.com/philmalin/eictar/src/internal/format"
)

// Identical content (doc/design.md 4.3): a member whose payload is already in
// the archive shares the blob of that member, its owner, and stores nothing.

// dedup is the writer's table of owners. The capturer asks it before a file
// is compressed, and the emitter asks it before a blob is written, so a lock
// guards it.
type dedup struct {
	mu     sync.Mutex
	owners map[string]uint64 // content key -> owner id
	sizes  map[uint64]int    // payload size -> number of owners with it

	// firstNew is the first member id of this run. An owner below it is from
	// an earlier generation, and it is checked before it is first used,
	// because the match is on the digest that the index records, not on the
	// blob (doc/design.md 4.3). checked holds each result.
	firstNew uint64
	checked  map[uint64]bool
	// old reads the earlier generations, to check an old owner. It is nil
	// for a create.
	old *Reader
	// members are the earlier generations' members by id, for the check.
	members map[uint64]*format.Member
}

// newDedup makes the table, with the owners of the earlier generations. A
// tombstone still holds its blob, so it can own content too.
func newDedup(old *Reader, firstNew uint64) *dedup {
	d := &dedup{
		owners:   map[string]uint64{},
		sizes:    map[uint64]int{},
		firstNew: firstNew,
		checked:  map[uint64]bool{},
		old:      old,
		members:  map[uint64]*format.Member{},
	}
	if old != nil {
		for i := range old.index.Members {
			m := &old.index.Members[i]
			d.members[m.ID] = m
			if isOwner(m) {
				d.add(m)
			}
		}
	}
	return d
}

// isOwner reports whether m holds a blob of content that another member can
// share: a regular file with content, and not itself a sharer.
func isOwner(m *format.Member) bool {
	return m.Type == format.TypeReg && m.Data == 0 && m.Length > 0 && len(m.Digest) == format.DigestSize
}

// contentKey is what equal content means: the same payload size, the same
// sparse map and the same digest.
func contentKey(m *format.Member) string {
	b := make([]byte, 0, format.DigestSize+8+16*len(m.Sparse))
	b = append(b, m.Digest...)
	b = binary.LittleEndian.AppendUint64(b, m.Size)
	for _, s := range m.Sparse {
		b = binary.LittleEndian.AppendUint64(b, s.Offset)
		b = binary.LittleEndian.AppendUint64(b, s.Length)
	}
	return string(b)
}

func (d *dedup) add(m *format.Member) {
	key := contentKey(m)
	if _, ok := d.owners[key]; ok {
		return
	}
	d.owners[key] = m.ID
	d.sizes[m.PayloadSize()]++
}

// hasSize reports whether an owner has a payload of this size. Only then can
// a file be a copy, and only then is it worth a hash before the compression.
func (d *dedup) hasSize(payload uint64) bool {
	if d == nil || payload == 0 {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.sizes[payload] > 0
}

// usable returns the owner of m's content when there is one that m can
// share. An old owner is checked first; one that fails its check is not used
// again, and the error says why. The check reads the file outside the lock.
func (d *dedup) usable(m *format.Member) (owner uint64, err error) {
	d.mu.Lock()
	owner, ok := d.owners[contentKey(m)]
	good, known := d.checked[owner]
	old := d.members[owner]
	d.mu.Unlock()
	switch {
	case !ok:
		return 0, nil
	case owner < d.firstNew && (d.old == nil || old == nil):
		return 0, nil // cannot happen: an old owner comes from d.old
	case owner >= d.firstNew || (known && good):
		return owner, nil
	case known:
		return 0, nil
	}

	err = d.old.WriteMember(old, io.Discard)
	d.mu.Lock()
	d.checked[owner] = err == nil
	d.mu.Unlock()
	if err != nil {
		return 0, err
	}
	return owner, nil
}

// atEmit is the rule of the emitter: it shares the content of an owner that
// this run wrote, or of an old owner that passed its check, and otherwise it
// records m as a new owner. It never checks an old owner itself: that read
// would hold up every other member.
func (d *dedup) atEmit(m *format.Member) (owner uint64, share bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	key := contentKey(m)
	o, ok := d.owners[key]
	if ok && (o >= d.firstNew || d.checked[o]) {
		return o, true
	}
	// No owner, or an old one that is unchecked or damaged: m, which this
	// run writes, owns the content from now on.
	if !ok {
		d.sizes[m.PayloadSize()]++
	}
	d.owners[key] = m.ID
	return 0, false
}

// share turns m into a member that shares the content of owner.
func share(m *format.Member, owner uint64) {
	m.Data = owner
	m.Offset, m.Length, m.Chunks, m.ChunkSize = 0, 0, nil, 0
	m.Enc = nil
	m.Codec = format.NoCodec
}
