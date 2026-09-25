package codec

import (
	"errors"
	"fmt"
	"io"
)

// decodeStream reads exactly plainSize bytes from a streaming decompressor
// and appends them to dst.
//
// It is the bound for the codecs whose decoders are readers (flate, gzip,
// xz): it reads no more than the index promises, and then one byte more to
// prove that the stream ends there. A chunk that decodes to more is refused
// without the surplus ever being held in memory, which is what makes a
// crafted chunk harmless.
func decodeStream(name string, r io.Reader, dst []byte, plainSize, maxPlain int) ([]byte, error) {
	if plainSize > maxPlain {
		return nil, fmt.Errorf("%s: chunk claims %d bytes, more than the %d permitted", name, plainSize, maxPlain)
	}
	start := len(dst)
	if cap(dst)-start < plainSize {
		grown := make([]byte, start, start+plainSize)
		copy(grown, dst)
		dst = grown
	}
	dst = dst[:start+plainSize]
	if n, err := io.ReadFull(r, dst[start:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%s: chunk decoded to %d bytes, index says %d", name, n, plainSize)
		}
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	var extra [1]byte
	switch n, err := r.Read(extra[:]); {
	case n > 0:
		return nil, fmt.Errorf("%s: chunk decodes to more than the %d bytes the index says", name, plainSize)
	case err != nil && !errors.Is(err, io.EOF):
		// The stream's own check (a CRC, an end marker) runs at the end.
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return dst, nil
}
