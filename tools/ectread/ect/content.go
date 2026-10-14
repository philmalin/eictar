package ect

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"

	"github.com/klauspost/compress/s2"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz/lzma"
	"golang.org/x/crypto/chacha20poly1305"
	"lukechampine.com/blake3"
)

// The content of a member: chunks (format.md 5), codecs (6), dictionaries
// (6.1), seals (7.3, 7.6) and sparse files (9.3).

func (a *Archive) digester() *blake3.Hasher {
	if a.Encrypted {
		return blake3.New(32, a.contentK)
	}
	return blake3.New(32, nil)
}

// owner is the member whose blob holds the content of m: m itself, the
// target of a hardlink, or the member that data names.
func (a *Archive) owner(m *Member) (*Member, error) {
	if m.Type == "hardlink" {
		m = a.byID[m.Hardlink]
	}
	if m == nil || m.Type != "reg" {
		return nil, errors.New("the member has no content")
	}
	if m.Data != 0 {
		return a.byID[m.Data], nil
	}
	return m, nil
}

// Payload writes the payload of a reg or hardlink member to w, and checks
// its digest at the end. On an error, what w got is not to be trusted.
func (a *Archive) Payload(m *Member, w io.Writer) error {
	o, err := a.owner(m)
	if err != nil {
		return err
	}
	h := a.digester()
	w = io.MultiWriter(w, h)
	var key []byte
	if o.HasBlob {
		switch {
		case a.Encrypted:
			key = a.subkey(o.Salt, "eictar/v1/member")
		case o.Salt != nil:
			return refusef("member id %d: enc in a plain archive", o.ID)
		}
	}
	payload := o.PayloadSize()
	off := o.Off
	for i, n := range o.Chunks {
		want := o.Chunk
		if i == len(o.Chunks)-1 {
			want = payload - o.Chunk*uint64(i)
		}
		b, err := readAt(a.f, off, n)
		if err != nil {
			return err
		}
		off += n
		if key != nil {
			if b, err = openChunk(key, o.ID, uint64(i), i == len(o.Chunks)-1, b); err != nil {
				return refusef("member id %d, chunk %d: %v", o.ID, i, err)
			}
		}
		if uint64(len(b)) != want {
			if o.Codec < 0 {
				return refusef("member id %d, chunk %d: %d bytes with no codec, not %d", o.ID, i, len(b), want)
			}
			if b, err = a.decode(a.Codecs[o.Codec], b, want); err != nil {
				return refusef("member id %d, chunk %d: %v", o.ID, i, err)
			}
		}
		if _, err := w.Write(b); err != nil {
			return err
		}
	}
	if subtle.ConstantTimeCompare(h.Sum(nil), o.Digest) != 1 {
		return refusef("member id %d: the digest of the content is wrong", o.ID)
	}
	return nil
}

func openChunk(key []byte, id, i uint64, final bool, b []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := binary.BigEndian.AppendUint64(make([]byte, 16), i)
	aad := binary.BigEndian.AppendUint64(binary.LittleEndian.AppendUint64(nil, id), i)
	if final {
		aad = append(aad, 1)
	} else {
		aad = append(aad, 0)
	}
	pt, err := aead.Open(nil, nonce, b, aad)
	if err != nil {
		return nil, errors.New("the tag is wrong")
	}
	return pt, nil
}

// Content writes the content of a reg or hardlink member: size bytes, with
// zeros in the holes of a sparse file. It checks the digest at the end.
func (a *Archive) Content(m *Member, w io.Writer) error {
	o, err := a.owner(m)
	if err != nil {
		return err
	}
	if !o.IsSparse {
		return a.Payload(m, w)
	}
	e := &expander{w: w, segs: o.Sparse}
	if err := a.Payload(m, e); err != nil {
		return err
	}
	return e.zeros(o.Size - e.pos)
}

// expander puts the bytes of the segments at their offsets.
type expander struct {
	w    io.Writer
	segs []Segment
	pos  uint64
}

var zeroBuf = make([]byte, 1<<16)

func (e *expander) zeros(n uint64) error {
	for n > 0 {
		k := min(n, uint64(len(zeroBuf)))
		if _, err := e.w.Write(zeroBuf[:k]); err != nil {
			return err
		}
		n -= k
		e.pos += k
	}
	return nil
}

func (e *expander) Write(p []byte) (int, error) {
	done := 0
	for len(p) > 0 {
		if len(e.segs) == 0 {
			return done, errors.New("more payload than segments")
		}
		s := e.segs[0]
		if e.pos < s.Off {
			if err := e.zeros(s.Off - e.pos); err != nil {
				return done, err
			}
		}
		n := min(uint64(len(p)), s.Off+s.Len-e.pos)
		if _, err := e.w.Write(p[:n]); err != nil {
			return done, err
		}
		e.pos += n
		done += int(n)
		p = p[n:]
		if e.pos == s.Off+s.Len {
			e.segs = e.segs[1:]
		}
	}
	return done, nil
}

// decode decodes one compressed chunk to exactly want bytes (format.md 6).
func (a *Archive) decode(c Codec, b []byte, want uint64) ([]byte, error) {
	br := bytes.NewReader(b)
	switch c.Name {
	case "zstd":
		return a.decodeZstd(c, b, want)
	case "flate":
		return exact(flate.NewReader(br), br, want)
	case "gzip":
		z, err := gzip.NewReader(br)
		if err != nil {
			return nil, err
		}
		z.Multistream(false)
		return exact(z, br, want)
	case "s2":
		n, err := s2.DecodedLen(b)
		if err != nil {
			return nil, err
		}
		if uint64(n) != want {
			return nil, errors.New("the S2 block states another length")
		}
		return s2.Decode(make([]byte, n), b)
	case "xz":
		r, err := lzma.Reader2Config{DictCap: int(max(4096, want))}.NewReader2(br)
		if err != nil {
			return nil, err
		}
		return exact(r, br, want)
	}
	return nil, refusef("codec %q is not known", c.Name)
}

// exact reads want bytes from r, then proves that r ends there and that src
// has nothing after the stream.
func exact(r io.Reader, src *bytes.Reader, want uint64) ([]byte, error) {
	out := make([]byte, want)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	var one [1]byte
	for {
		n, err := r.Read(one[:])
		if n > 0 {
			return nil, errors.New("the chunk decodes to more than its length")
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	if src != nil && src.Len() != 0 {
		return nil, errors.New("bytes after the compressed stream")
	}
	return out, nil
}

func (a *Archive) decodeZstd(c Codec, b []byte, want uint64) ([]byte, error) {
	var h zstd.Header
	if err := h.Decode(b); err != nil {
		return nil, err
	}
	if h.Skippable {
		return nil, errors.New("a skippable frame")
	}
	if h.DictionaryID != c.Dict {
		return nil, errors.New("the frame names another dictionary")
	}
	opts := []zstd.DOption{zstd.WithDecoderConcurrency(1)}
	if c.Dict != 0 {
		d, err := a.dict(c.Dict)
		if err != nil {
			return nil, err
		}
		opts = append(opts, zstd.WithDecoderDicts(d))
	}
	dec, err := zstd.NewReader(bytes.NewReader(b), opts...)
	if err != nil {
		return nil, err
	}
	defer dec.Close()
	return exact(dec, nil, want)
}

// dict returns a dictionary after its checks (format.md 6.1).
func (a *Archive) dict(id uint32) ([]byte, error) {
	if d, ok := a.dictCache[id]; ok {
		return d, nil
	}
	d := a.Dicts[id]
	b, err := readAt(a.f, d.Off, d.Len)
	if err != nil {
		return nil, err
	}
	if d.Salt != nil {
		if !a.Encrypted {
			return nil, refusef("dictionary %d: enc in a plain archive", id)
		}
		aead, err := chacha20poly1305.NewX(a.subkey(d.Salt, "eictar/v1/dict"))
		if err != nil {
			return nil, err
		}
		if b, err = aead.Open(nil, make([]byte, 24), b, binary.LittleEndian.AppendUint32(nil, id)); err != nil {
			return nil, refusef("dictionary %d: the tag is wrong", id)
		}
	}
	if uint64(len(b)) != d.Size {
		return nil, refusef("dictionary %d: %d bytes, not %d", id, len(b), d.Size)
	}
	h := a.digester()
	h.Write(b)
	if subtle.ConstantTimeCompare(h.Sum(nil), d.Digest) != 1 {
		return nil, refusef("dictionary %d: the digest is wrong", id)
	}
	if len(b) < 8 || !bytes.Equal(b[:4], []byte{0x37, 0xA4, 0x30, 0xEC}) || binary.LittleEndian.Uint32(b[4:]) != id {
		return nil, refusef("dictionary %d: the magic or the id is wrong", id)
	}
	a.dictCache[id] = b
	return b, nil
}
