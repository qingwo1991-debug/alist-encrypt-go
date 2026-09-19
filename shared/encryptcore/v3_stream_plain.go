package encryption

import (
	"fmt"
	"io"
)

// V3StreamReader decrypts an in-order ciphertext stream that begins at the
// first byte of a chunk record (as produced by the proxy's chunk-window
// upstream Range). Records are fixed width (chunkSize+tag), decrypted chunk by
// chunk, and only the requested plaintext sub-slice is surfaced.
//
// The stream has no knowledge of the header or the trailer: the caller passes
// the cipher handle (derived from password+nonce/KDF), the chunk size, the
// index of the first record present in the stream, the number of plaintext
// bytes to skip, and the plaintext byte limit (-1 = until the stream ends).
type V3StreamReader struct {
	cipher    *V3ChunkCipher
	chunkSize int64
	r         io.Reader
	idx       int64 // next expected chunk index (for per-chunk nonce/AAD binding)
	skip      int64 // plaintext bytes to skip before yielding
	limit     int64 // max plaintext bytes to yield; -1 == until EOF
	rbuf      []byte
	boff      int
}

// NewV3StreamReader creates a reader over plaintext of a chunk-record stream.
func NewV3StreamReader(r io.Reader, cipher *V3ChunkCipher, chunkSize, firstChunkIdx int64, skip, limit int64) (*V3StreamReader, error) {
	if r == nil || cipher == nil {
		return nil, fmt.Errorf("v3: nil stream or cipher")
	}
	if chunkSize <= 0 || chunkSize > v3MaxChunkSize {
		chunkSize = v3DefaultChunkSize
	}
	if skip < 0 {
		skip = 0
	}
	return &V3StreamReader{
		cipher:    cipher,
		chunkSize: chunkSize,
		r:         r,
		idx:       firstChunkIdx,
		skip:      skip,
		limit:     limit,
	}, nil
}

func (p *V3StreamReader) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if p.limit == 0 {
		return 0, io.EOF
	}
	for {
		if p.boff < len(p.rbuf) {
			avail := p.rbuf[p.boff:]
			if p.limit >= 0 && p.limit < int64(len(avail)) {
				avail = avail[:p.limit]
			}
			n := copy(b, avail)
			p.boff += n
			if p.limit >= 0 {
				p.limit -= int64(n)
			}
			return n, nil
		}
		recordLen := p.chunkSize + int64(v3TagSize)
		if recordLen <= 0 {
			return 0, io.EOF
		}
		rec := make([]byte, recordLen)
		if _, err := io.ReadFull(p.r, rec); err != nil {
			if err == io.EOF {
				return 0, io.EOF
			}
			return 0, err
		}
		pt, err := p.cipher.Open(uint64(p.idx), rec)
		if err != nil {
			return 0, fmt.Errorf("%w: chunk %d error: %v", errV3TagMismatch, p.idx, err)
		}
		p.idx++
		p.rbuf = pt
		p.boff = 0
		if p.skip > 0 {
			sk := p.skip
			if sk > int64(len(pt)) {
				sk = int64(len(pt))
			}
			p.boff = int(sk)
			p.skip -= sk
		}
		if p.boff >= len(p.rbuf) {
			continue
		}
	}
}
