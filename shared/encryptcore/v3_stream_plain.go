package encryption

import (
	"context"
	"errors"
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
	idx       int64  // next expected chunk index (for per-chunk nonce/AAD binding)
	skip      int64  // plaintext bytes to skip before yielding
	limit     int64  // max plaintext bytes to yield; -1 == until EOF
	record    []byte // one allocation; refill only after rbuf has been consumed
	err       error  // terminal failures must not skip a failed record
	rbuf      []byte
	boff      int
	ctx       context.Context
	cache     *V3AuthenticatedRecordCache
	cacheKey  V3RecordCacheKey
	plainSize int64
	loader    V3RawRecordLoader
	lease     *V3RecordLease
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

// NewV3StreamReaderWithCache populates whole authenticated records after IO.
// It does not skip bytes in an already-open sequential upstream stream.
func NewV3StreamReaderWithCache(r io.Reader, cipher *V3ChunkCipher, chunkSize, firstChunkIdx, skip, limit int64, cache *V3AuthenticatedRecordCache, key V3RecordCacheKey, plainSize int64) (*V3StreamReader, error) {
	p, err := NewV3StreamReader(r, cipher, chunkSize, firstChunkIdx, skip, limit)
	if err != nil {
		return nil, err
	}
	if chunkSize <= 0 || chunkSize > v3MaxChunkSize || firstChunkIdx < 0 || plainSize < 0 {
		return nil, fmt.Errorf("v3: invalid cached stream geometry")
	}
	p.cache, p.cacheKey, p.plainSize = cache, key, plainSize
	return p, nil
}

// NewV3RecordReader uses cache leases before calling the raw-record transport.
// Close must be called on early termination. All uncached ciphertext transport
// allocations still require caller admission. A budget-full miss authenticates
// in the loader-owned raw buffer without publishing: the existing external
// record admission must cover this uncached buffer until consumed or Close.
func NewV3RecordReader(ctx context.Context, cipher *V3ChunkCipher, chunkSize, firstChunkIdx, skip, limit, plainSize int64, cache *V3AuthenticatedRecordCache, key V3RecordCacheKey, loader V3RawRecordLoader) (*V3StreamReader, error) {
	if ctx == nil || cache == nil || key == (V3RecordCacheKey{}) || chunkSize <= 0 || chunkSize > v3MaxChunkSize || firstChunkIdx < 0 || firstChunkIdx > int64(^uint32(0)) || skip < 0 || limit < -1 || plainSize < 0 {
		return nil, fmt.Errorf("v3: invalid record reader")
	}
	return &V3StreamReader{ctx: ctx, cipher: cipher, chunkSize: chunkSize, idx: firstChunkIdx, skip: skip, limit: limit, plainSize: plainSize, cache: cache, cacheKey: key, loader: loader}, nil
}

// Close releases the current lease without closing caller-owned transport.
func (p *V3StreamReader) Close() error {
	if p.lease != nil {
		p.lease.Release()
		p.lease = nil
	}
	p.rbuf = nil
	p.record = nil
	p.err = io.ErrClosedPipe
	return nil
}

func (p *V3StreamReader) readRecordLease(b []byte) (int, error) {
	for {
		if err := p.ctx.Err(); err != nil {
			p.Close()
			p.err = err
			return 0, err
		}
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
			if p.boff == len(p.rbuf) || p.limit == 0 {
				p.rbuf = nil
				p.record = nil
			}
			return n, nil
		}
		if p.lease != nil && int64(p.boff) < p.lease.Len() {
			nmax := int64(len(b))
			remain := p.lease.Len() - int64(p.boff)
			if nmax > remain {
				nmax = remain
			}
			if p.limit >= 0 && nmax > p.limit {
				nmax = p.limit
			}
			n, err := p.lease.ReadAt(b[:nmax], int64(p.boff))
			p.boff += n
			if p.limit >= 0 {
				p.limit -= int64(n)
			}
			if int64(p.boff) == p.lease.Len() || p.limit == 0 {
				p.lease.Release()
				p.lease = nil
			}
			return n, err
		}
		p.rbuf = nil
		p.record = nil
		if p.lease != nil {
			p.lease.Release()
			p.lease = nil
		}
		if p.plainSize == 0 || p.idx > (p.plainSize-1)/p.chunkSize {
			return 0, io.EOF
		}
		l, err := p.cache.Load(p.ctx, p.cacheKey, uint64(p.idx), p.cipher, p.chunkSize, p.plainSize, p.loader)
		if errors.Is(err, ErrV3RecordCacheFull) && p.cipher != nil && p.loader != nil {
			var raw []byte
			raw, err = p.loader(p.ctx, uint64(p.idx))
			if err == nil {
				err = p.ctx.Err()
			}
			if err == nil && int64(len(raw)) != p.chunkSize+v3TagSize {
				err = io.ErrUnexpectedEOF
			}
			if err == nil {
				p.rbuf, err = p.cipher.open(raw[:0], uint64(p.idx), raw)
			}
			if err == nil {
				err = p.ctx.Err()
			}
			if err == nil {
				length := p.plainSize - p.idx*p.chunkSize
				if length < int64(len(p.rbuf)) {
					p.rbuf = p.rbuf[:length]
				}
				p.record = raw
				p.idx++
				p.boff = 0
				if p.skip > 0 {
					sk := p.skip
					if sk > int64(len(p.rbuf)) {
						sk = int64(len(p.rbuf))
					}
					p.boff = int(sk)
					p.skip -= sk
				}
				continue
			}
			p.rbuf = nil
			p.record = nil
		}
		if err != nil {
			p.err = err
			return 0, err
		}
		p.idx++
		p.lease = l
		p.boff = 0
		if p.skip > 0 {
			sk := p.skip
			if sk > l.Len() {
				sk = l.Len()
			}
			p.boff = int(sk)
			p.skip -= sk
		}
	}
}

func (p *V3StreamReader) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if p.err != nil {
		return 0, p.err
	}
	if p.limit == 0 {
		return 0, io.EOF
	}
	if p.ctx != nil {
		return p.readRecordLease(b)
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
		if p.record == nil {
			p.record = make([]byte, recordLen)
		}
		if _, err := io.ReadFull(p.r, p.record); err != nil {
			p.err = err
			return 0, p.err
		}
		pt, err := p.cipher.open(p.record[:0], uint64(p.idx), p.record)
		if err != nil {
			p.err = fmt.Errorf("v3: chunk %d: %w", p.idx, err)
			return 0, p.err
		}
		if p.cache != nil {
			if p.idx < 0 || p.plainSize == 0 || p.idx > (p.plainSize-1)/p.chunkSize {
				p.err = fmt.Errorf("v3: stream exceeds plaintext geometry")
				return 0, p.err
			}
			length := p.plainSize - p.idx*p.chunkSize
			if length < int64(len(pt)) {
				pt = pt[:length]
			}
			p.cache.publishAuthenticated(p.cacheKey, uint64(p.idx), pt)
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
