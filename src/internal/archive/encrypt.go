package archive

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"sort"

	"github.com/philmalin/eictar/src/internal/crypt"
	"github.com/philmalin/eictar/src/internal/format"
)

// EncryptArchiveConfig is the encryption that --encrypt-archive gives to an
// archive made without -e (doc/design.md 9.11). Passphrase is asked only
// after the archive has opened as plaintext and the KDF parameters have been
// checked with this machine.
type EncryptArchiveConfig struct {
	Passphrase   PassphraseFunc
	Params       crypt.KDFParams
	EncryptIndex bool
	Workers      int
	MemoryLimit  int64
}

// encryptHeaders builds the file header and the crypto header of the
// encrypted archive: the uuid and the creation time of the original, a new
// random data key, and that key wrapped for the passphrase. It returns the
// keys, which the caller zeroes.
func encryptHeaders(r *Reader, ec *EncryptArchiveConfig) ([]byte, format.Header, *crypt.Keys, error) {
	params := ec.Params
	if params == (crypt.KDFParams{}) {
		params = crypt.DefaultKDFParams
	}
	if err := params.Validate(); err != nil {
		return nil, format.Header{}, nil, err
	}
	// The check comes before the prompt, as for an open (doc/design.md A.3).
	if err := checkAffordable(params); err != nil {
		return nil, format.Header{}, nil, err
	}
	pass, err := ec.Passphrase()
	if err != nil {
		return nil, format.Header{}, nil, fmt.Errorf("the passphrase: %w", err)
	}
	defer clear(pass)
	if len(pass) == 0 {
		return nil, format.Header{}, nil, errors.New("an empty passphrase cannot protect anything")
	}
	keys, salt, wrapped, err := newWrappedKeys(pass, params, r.hdr.ArchiveUUID)
	if err != nil {
		return nil, format.Header{}, nil, err
	}
	ch := &format.CryptoHeader{
		Version: format.CryptoHeaderVersion,
		KDF:     format.KDFArgon2id,
		Salt:    salt,
		Time:    params.Time,
		Memory:  params.Memory,
		Threads: params.Threads,
		AEAD:    format.AEADXChaCha20,
		Key:     wrapped,
	}
	cryptoBytes, err := ch.Marshal()
	if err != nil {
		keys.Zero()
		return nil, format.Header{}, nil, err
	}
	hdr := r.hdr
	hdr.Flags |= format.FlagEncrypted
	hdr.CryptoHeaderLen = uint32(len(cryptoBytes))
	hdrBytes, err := hdr.MarshalBinary()
	if err != nil {
		keys.Zero()
		return nil, format.Header{}, nil, err
	}
	return append(hdrBytes, cryptoBytes...), hdr, keys, nil
}

// encryptBlobs writes the dictionaries and the blobs of the kept members into
// w, sealed with w.keys, and gives each digest its keyed value. It returns the
// number of members with a blob of their own.
//
// Pass A decodes each member that holds its content, in parallel, as
// --verify does. The decode checks the old digest, and gives the new keyed
// digest and a digest of the bytes on disk. Pass B reads each blob again in
// the order of the file, seals each chunk as it is, and writes it. The digest
// of the bytes that it seals must equal the one from pass A, so no byte is
// sealed that pass A did not check.
func encryptBlobs(r *Reader, w *Writer, keep []format.Member, ec *EncryptArchiveConfig, progress Progress) (int, error) {
	// Pass A: the members that hold their own content, the empty ones too.
	// It decodes with the catalog of r, so it runs before pruneCatalog
	// gives the codecs their new positions.
	var work []*format.Member
	for i := range keep {
		if m := &keep[i]; m.Type.HasPayload() && m.Data == 0 {
			work = append(work, m)
		}
	}
	// Each worker writes only the entries of its own members, so the slice
	// needs no lock. pos is only read.
	pos := make(map[*format.Member]int, len(work))
	for i, m := range work {
		pos[m] = i
	}
	results := make([]passA, len(work))
	var firstErr error
	decodeInParallelWith(r, work, ec.Workers, ec.MemoryLimit, func(m *format.Member, set *decoderSet) error {
		keyed, raw := newDigest(w.keys), newDigest(nil)
		if err := r.writeMember(m, countWriter(keyed, progress), set, func(b []byte) { raw.Write(b) }); err != nil {
			return err
		}
		results[pos[m]] = passA{keyed: keyed.Sum(nil), raw: raw.Sum(nil)}
		return nil
	}, func(_ *format.Member, err error) {
		if firstErr == nil {
			firstErr = err
		}
	})
	if firstErr != nil {
		return 0, firstErr
	}
	got := make(map[uint64]passA, len(work))
	for i, m := range work {
		got[m.ID] = results[i]
	}

	// Each digest becomes keyed: an unkeyed digest in an encrypted archive
	// tells anyone with a copy of a file that the archive holds it
	// (doc/design.md 6.2). A digest that this run cannot give a keyed value
	// stops it.
	for i := range keep {
		m := &keep[i]
		if len(m.Digest) == 0 {
			continue
		}
		id := m.ID
		if m.Data != 0 {
			o := r.Owner(m)
			if o == nil {
				return 0, fmt.Errorf("%w: member %q shares the content of member %d, which does not exist",
					format.ErrCorruptIndex, m.Path, m.Data)
			}
			id = o.ID
		}
		d, ok := got[id]
		if !ok {
			return 0, fmt.Errorf("%w: member %q has a digest, and no content to give it a keyed one",
				format.ErrCorruptIndex, m.Path)
		}
		m.Digest = d.keyed
	}

	// The dictionaries go before the members that use them, as in a create.
	w.index.Codecs = pruneCatalog(keep, r.index.Codecs)
	if err := sealDicts(r, w, keep); err != nil {
		return 0, err
	}

	if testBetweenPasses != nil {
		testBetweenPasses()
	}

	// Pass B, in the order of the file, so that the reads are sequential.
	sort.Slice(keep, func(i, j int) bool { return keep[i].Offset < keep[j].Offset })
	bw := bufio.NewWriterSize(w.f, 1<<20)
	count := 0
	for i := range keep {
		m := &keep[i]
		if m.Length == 0 {
			// No blob of its own, so no offset and no enc (doc/format.md 8.3).
			// The index refuses a blob on a member of another type, and on
			// one that shares content, so the length says it.
			m.Offset, m.Enc = 0, nil
			continue
		}
		if err := sealMember(r, w, bw, m, got[m.ID].raw, progress); err != nil {
			return 0, err
		}
		count++
	}
	if err := bw.Flush(); err != nil {
		return 0, fmt.Errorf("writing %s: %w", w.path, err)
	}
	w.index.Members = keep
	return count, nil
}

// testBetweenPasses, when a test sets it, runs after pass A and before pass B.
var testBetweenPasses func()

// passA is what pass A finds for one member: the keyed digest of its
// content, and the plain digest of its blob as it is on disk.
type passA struct{ keyed, raw []byte }

// sealMember reads the chunks of m from r, seals each one under a new member
// key, and writes it to bw. raw is the digest of the bytes on disk from pass
// A.
func sealMember(r *Reader, w *Writer, bw *bufio.Writer, m *format.Member, raw []byte, progress Progress) error {
	sealer, err := w.newSealer(m)
	if err != nil {
		return err
	}
	h := newDigest(nil)
	off := int64(m.Offset)
	start := w.off
	chunks := make([]uint32, len(m.Chunks))
	var buf, sealed []byte
	for i, n := range m.Chunks {
		if cap(buf) < int(n) {
			buf = make([]byte, n)
		}
		buf = buf[:n]
		if _, err := r.f.ReadAt(buf, off); err != nil {
			return fmt.Errorf("%s: reading chunk %d of %q: %w", r.path, i, m.Path, err)
		}
		h.Write(buf)
		if sealed, err = sealer.Seal(sealed[:0], buf, uint64(i), i == len(m.Chunks)-1); err != nil {
			return fmt.Errorf("%q: %w", m.Path, err)
		}
		if _, err := bw.Write(sealed); err != nil {
			return fmt.Errorf("writing %s: %w", w.path, err)
		}
		if progress != nil {
			progress.Advance(int64(n))
		}
		off += int64(n)
		w.off += int64(len(sealed))
		chunks[i] = uint32(len(sealed))
	}
	if !bytes.Equal(h.Sum(nil), raw) {
		return fmt.Errorf("%w: the blob of %q changed after its check", format.ErrCorruptData, m.Path)
	}
	m.Offset, m.Length, m.Chunks = uint64(start), uint64(w.off-start), chunks
	return nil
}

// sealDicts writes each dictionary that a kept member uses, sealed with a new
// salt and with a keyed digest. loadDict checks the plain digest first. The
// dictionary keeps its id and its generation.
func sealDicts(r *Reader, w *Writer, keep []format.Member) error {
	inUse := usedDicts(keep, w.index.Codecs)
	for _, d := range r.index.Dicts {
		if !inUse[d.ID] {
			continue
		}
		content, err := loadDict(r.f, nil, false, d)
		if err != nil {
			return err
		}
		if err := w.storeDict(d.ID, content); err != nil {
			return err
		}
		w.index.Dicts[len(w.index.Dicts)-1].Generation = d.Generation
	}
	return nil
}

// payloadAndBlobs is the total of the progress meter of --encrypt-archive:
// pass A counts the decoded bytes, and pass B the bytes on disk.
func payloadAndBlobs(keep []format.Member) int64 {
	var n int64
	for _, m := range keep {
		if m.Type.HasPayload() && m.Data == 0 {
			n += int64(m.PayloadSize()) + int64(m.Length)
		}
	}
	return n
}
