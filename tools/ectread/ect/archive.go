// Package ect reads an eictar archive with the rules of doc/format.md, and
// with no code of eictar (doc/testing.md 5, step 2). It is a second reader:
// its results must agree with those of eictar.
package ect

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"lukechampine.com/blake3"
)

// RefusedError is a refusal (format.md 1): the archive breaks a rule, and
// the reader gives no content from it.
type RefusedError struct{ Reason string }

func (e *RefusedError) Error() string { return "refused: " + e.Reason }

func refusef(format string, a ...any) error {
	return &RefusedError{Reason: fmt.Sprintf(format, a...)}
}

// ErrWrongPassphrase is the failure of the tag of the wrapped data key.
var ErrWrongPassphrase = errors.New("the passphrase is wrong")

// ErrNeedPassphrase is returned for an encrypted archive opened with no
// passphrase.
var ErrNeedPassphrase = errors.New("the archive is encrypted, and no passphrase was given")

// Options control Open.
type Options struct {
	// Passphrase opens an encrypted archive. When it is not nil, a plain
	// archive is refused (format.md 7.5).
	Passphrase []byte
	// MaxKDFMemoryKiB, when not 0, refuses a key derivation that needs more
	// memory than this, in KiB, before it starts.
	MaxKDFMemoryKiB uint64
}

const (
	headerSize  = 64
	trailerSize = 96
	maxCryptoHd = 65536
	encryptedHF = 1 << 0
	sealedTF    = 1 << 0
	compressTF  = 1 << 1
)

var (
	headerMagic  = []byte("EICTAR\x1a\n")
	trailerMagic = []byte("EICTRAIL")
	castagnoli   = crc32.MakeTable(crc32.Castagnoli)
)

// Archive is an open archive whose index passed every check.
type Archive struct {
	f    io.ReaderAt
	size int64

	FormatMajor, FormatMinor uint16
	Encrypted                bool
	CreatedUnixNanos         int64
	UUID                     [16]byte
	Generation               uint64
	bodyStart                uint64
	indexOffset              uint64

	dataK, contentK []byte

	Codecs  []Codec
	Dicts   map[uint32]*Dict
	Members []*Member
	byID    map[uint64]*Member

	dictCache map[uint32][]byte
}

// Open reads the archive at path. The caller closes it with Close.
func Open(path string, opt Options) (*Archive, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	a, err := read(f, st.Size(), opt)
	if err != nil {
		f.Close()
		return nil, err
	}
	return a, nil
}

// Close closes the file of the archive.
func (a *Archive) Close() error {
	if c, ok := a.f.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

func readAt(f io.ReaderAt, off, n uint64) ([]byte, error) {
	b := make([]byte, n)
	if _, err := f.ReadAt(b, int64(off)); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, refusef("a read past the end of the file")
		}
		return nil, err
	}
	return b, nil
}

func read(f io.ReaderAt, size int64, opt Options) (*Archive, error) {
	if size < headerSize+trailerSize {
		return nil, refusef("the file has %d bytes, fewer than a header and a trailer", size)
	}
	a := &Archive{f: f, size: size, dictCache: map[uint32][]byte{}}
	h, err := readAt(f, 0, headerSize)
	if err != nil {
		return nil, err
	}
	cryptoLen, err := a.header(h)
	if err != nil {
		return nil, err
	}
	a.bodyStart = headerSize + uint64(cryptoLen)
	if a.bodyStart > uint64(size)-trailerSize {
		return nil, refusef("the crypto header goes into the trailer")
	}
	if opt.Passphrase != nil && !a.Encrypted {
		return nil, refusef("the archive is not encrypted, and an encrypted one was expected")
	}
	if a.Encrypted {
		if err := a.unlock(cryptoLen, opt); err != nil {
			return nil, err
		}
	}
	t, err := readAt(f, uint64(size)-trailerSize, trailerSize)
	if err != nil {
		return nil, err
	}
	idx, flags, err := a.trailer(t)
	if err != nil {
		return nil, err
	}
	raw, err := readAt(f, a.indexOffset, idx.length)
	if err != nil {
		return nil, err
	}
	if err := a.checkIndexDigest(raw, idx.digest); err != nil {
		return nil, err
	}
	plain, err := a.decodeIndex(raw, flags)
	if err != nil {
		return nil, err
	}
	v, err := decodeCBOR(plain)
	if err != nil {
		return nil, err
	}
	if err := a.parseIndex(v, idx.live); err != nil {
		return nil, err
	}
	return a, nil
}

// header checks the file header (format.md 3), and returns crypto_header_len.
func (a *Archive) header(h []byte) (uint32, error) {
	if !bytes.Equal(h[:8], headerMagic) {
		return 0, refusef("not an eictar archive: the magic is wrong")
	}
	if crc32.Checksum(h[:60], castagnoli) != binary.LittleEndian.Uint32(h[60:]) {
		return 0, refusef("the CRC of the file header is wrong")
	}
	a.FormatMajor = binary.LittleEndian.Uint16(h[8:])
	a.FormatMinor = binary.LittleEndian.Uint16(h[10:])
	if a.FormatMajor != 1 {
		return 0, refusef("format_major %d is not known", a.FormatMajor)
	}
	flags := binary.LittleEndian.Uint32(h[12:])
	if flags&^encryptedHF != 0 {
		return 0, refusef("header_flags %#x has a bit that is not known", flags)
	}
	if !allZero(h[44:60]) {
		return 0, refusef("a reserved byte of the file header is not zero")
	}
	a.Encrypted = flags&encryptedHF != 0
	a.CreatedUnixNanos = int64(binary.LittleEndian.Uint64(h[16:]))
	copy(a.UUID[:], h[24:40])
	n := binary.LittleEndian.Uint32(h[40:])
	switch {
	case !a.Encrypted && n != 0:
		return 0, refusef("a plain archive with a crypto header of %d bytes", n)
	case a.Encrypted && (n == 0 || n > maxCryptoHd):
		return 0, refusef("an encrypted archive with a crypto header of %d bytes", n)
	}
	return n, nil
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// unlock reads the crypto header (format.md 4) and opens the data key
// (format.md 7.1).
func (a *Archive) unlock(n uint32, opt Options) error {
	b, err := readAt(a.f, headerSize, uint64(n))
	if err != nil {
		return err
	}
	if n < 4 {
		return refusef("the crypto header has no length")
	}
	cl := binary.LittleEndian.Uint32(b)
	if uint64(cl) != uint64(n)-4 {
		return refusef("the crypto header holds %d bytes of CBOR, in %d bytes", cl, n)
	}
	v, err := decodeCBOR(b[4:])
	if err != nil {
		return err
	}
	m, ok := v.(*cmap)
	if !ok {
		return refusef("the crypto header is not a map")
	}
	if _, ok := m.get("recipients"); ok {
		return refusef("the crypto header has recipients")
	}
	ver, err := needUint(m, "v", "the crypto header")
	if err != nil {
		return err
	}
	if ver != 1 {
		return refusef("crypto header version %d is not known", ver)
	}
	for _, kv := range [][2]string{{"kdf", "argon2id"}, {"aead", "xchacha20poly1305"}} {
		s, err := needText(m, kv[0], "the crypto header")
		if err != nil {
			return err
		}
		if s != kv[1] {
			return refusef("the crypto header %s is %q", kv[0], s)
		}
	}
	salt, err := needBytes(m, "salt", "the crypto header", 16)
	if err != nil {
		return err
	}
	key, err := needBytes(m, "key", "the crypto header", 72)
	if err != nil {
		return err
	}
	time, err := needUint(m, "time", "the crypto header")
	if err != nil {
		return err
	}
	memory, err := needUint(m, "memory", "the crypto header")
	if err != nil {
		return err
	}
	threads, err := needUint(m, "threads", "the crypto header")
	if err != nil {
		return err
	}
	switch {
	case time < 1 || time > 64:
		return refusef("Argon2id time %d is outside 1 to 64", time)
	case threads < 1 || threads > 255:
		return refusef("Argon2id threads %d is outside 1 to 255", threads)
	case memory < 8*threads || memory > 4194304:
		return refusef("Argon2id memory %d KiB is outside %d to 4194304", memory, 8*threads)
	case opt.MaxKDFMemoryKiB != 0 && memory > opt.MaxKDFMemoryKiB:
		return refusef("Argon2id memory %d KiB is more than the limit of %d KiB", memory, opt.MaxKDFMemoryKiB)
	}
	if opt.Passphrase == nil {
		return ErrNeedPassphrase
	}
	kek := argon2.IDKey(opt.Passphrase, salt, uint32(time), uint32(memory), uint8(threads), 32)
	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return err
	}
	dataK, err := aead.Open(nil, key[:24], key[24:], append([]byte("eictar/v1/wrap"), a.UUID[:]...))
	if err != nil {
		return ErrWrongPassphrase
	}
	a.dataK = dataK
	a.contentK = a.subkey(nil, "eictar/v1/content")
	return nil
}

// subkey is an HKDF-SHA-256 subkey of the data key (format.md 7.1). The
// info is label || archive_uuid || extra.
func (a *Archive) subkey(salt []byte, label string, extra ...byte) []byte {
	info := append(append([]byte(label), a.UUID[:]...), extra...)
	k, err := hkdf.Key(sha256.New, a.dataK, salt, string(info), 32)
	if err != nil {
		panic(err) // only for a length that HKDF cannot give
	}
	return k
}

type trailerFields struct {
	length uint64
	live   uint64
	digest []byte
}

// trailer checks the trailer (format.md 10).
func (a *Archive) trailer(t []byte) (trailerFields, uint32, error) {
	var tf trailerFields
	if !bytes.Equal(t[:8], trailerMagic) {
		return tf, 0, refusef("the file does not end with a trailer")
	}
	if crc32.Checksum(t[:92], castagnoli) != binary.LittleEndian.Uint32(t[92:]) {
		return tf, 0, refusef("the CRC of the trailer is wrong")
	}
	if binary.LittleEndian.Uint16(t[8:]) != a.FormatMajor || binary.LittleEndian.Uint16(t[10:]) != a.FormatMinor {
		return tf, 0, refusef("the version of the trailer is not that of the header")
	}
	flags := binary.LittleEndian.Uint32(t[12:])
	if flags&^(sealedTF|compressTF) != 0 {
		return tf, 0, refusef("trailer_flags %#x has a bit that is not known", flags)
	}
	if !allZero(t[88:92]) {
		return tf, 0, refusef("a reserved byte of the trailer is not zero")
	}
	if flags&sealedTF != 0 && !a.Encrypted {
		return tf, 0, refusef("a sealed index in a plain archive")
	}
	a.Generation = binary.LittleEndian.Uint64(t[16:])
	a.indexOffset = binary.LittleEndian.Uint64(t[24:])
	tf.length = binary.LittleEndian.Uint64(t[32:])
	tf.live = binary.LittleEndian.Uint64(t[48:])
	tf.digest = t[56:88]
	end := uint64(a.size) - trailerSize
	if a.indexOffset < a.bodyStart || a.indexOffset > end || tf.length > end-a.indexOffset {
		return tf, 0, refusef("the index at %d, of %d bytes, is not between the body start and the trailer", a.indexOffset, tf.length)
	}
	return tf, flags, nil
}

// checkIndexDigest checks the digest of the index bytes (format.md 7.5).
func (a *Archive) checkIndexDigest(raw, want []byte) error {
	var h *blake3.Hasher
	if a.Encrypted {
		h = blake3.New(32, a.subkey(nil, "eictar/v1/index-auth"))
	} else {
		h = blake3.New(32, nil)
	}
	h.Write(a.UUID[:])
	h.Write(binary.LittleEndian.AppendUint64(nil, a.Generation))
	h.Write(raw)
	if subtle.ConstantTimeCompare(h.Sum(nil), want) != 1 {
		return refusef("the digest of the index is wrong")
	}
	return nil
}

const (
	maxIndex      = 1 << 30
	minIndexLimit = 64 << 20
)

// decodeIndex reverses the steps of format.md 8.1, to the CBOR bytes.
func (a *Archive) decodeIndex(raw []byte, flags uint32) ([]byte, error) {
	if flags&sealedTF != 0 {
		if len(raw) < 24+16 {
			return nil, refusef("the sealed index is too short")
		}
		aead, err := chacha20poly1305.NewX(a.subkey(nil, "eictar/v1/index", binary.LittleEndian.AppendUint64(nil, a.Generation)...))
		if err != nil {
			return nil, err
		}
		pt, err := aead.Open(nil, raw[:24], raw[24:], binary.LittleEndian.AppendUint64(nil, a.Generation))
		if err != nil {
			return nil, refusef("the tag of the index is wrong")
		}
		raw = pt
	}
	if flags&compressTF == 0 {
		if len(raw) > maxIndex {
			return nil, refusef("the index is more than 1 GiB")
		}
		return raw, nil
	}
	limit := min(maxIndex, max(200*uint64(len(raw)), minIndexLimit))
	dec, err := zstd.NewReader(bytes.NewReader(raw), zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(limit+1))
	if err != nil {
		return nil, err
	}
	defer dec.Close()
	out, err := io.ReadAll(io.LimitReader(dec, int64(limit)+1))
	if err != nil {
		return nil, refusef("the index does not decompress: %v", err)
	}
	if uint64(len(out)) > limit {
		return nil, refusef("the index decompresses to more than %d bytes", limit)
	}
	return out, nil
}
