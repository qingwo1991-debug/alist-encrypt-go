package encryption

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
)

// V3 streaming container.
//
// The record layout in content_v3.go is seek-friendly because every chunk
// record is a constant width (chunkSize + 16). A non-seekable writer cannot
// know the plaintext length up front, so for streaming we append a 16-byte
// trailer that records the final plaintext length:
//
//	[ 48-byte header (plainSize field = 0) ][ chunk records ][ 16-byte trailer ]
//
// Trailer: magic "V3E4" (4 bytes) + 4 reserved bytes + uint64 BE plaintext
// length. Random-access readers cheaply read the last 16 bytes of the
// container to learn the plaintext length; sequential readers stream the
// record bytes and trim the final chunk via that length.

const (
	v3TrailerLen      = 16
	v3TrailerMagic    = "V3E4"
	v3TrailerMagicLen = 4
)

var v3TrailerMagicBytes = []byte(v3TrailerMagic)

// DeriveV3Key derives the 32-byte AES-256-GCM key material for a password and
// a container nonce. The nonce doubles as the KDF salt so every container has
// a unique key. Iterations 0 ⇒ 600000.
func DeriveV3Key(password string, nonce []byte, iterations uint32) []byte {
	// Legacy callers have no error return: synchronously wait for bounded
	// admission instead of bypassing the shared CPU/flight limits.
	key, err := v3DefaultKDFService().key(context.Background(), password, nonce, iterations, V3KDFForeground, true)
	if err != nil {
		panic(err)
	} // process-owned default service is never shut down
	return key
}

// V3Writer emits a V3 container using the trailer layout.
type V3Writer struct {
	w         io.Writer
	chunkSize int64
	nonce     []byte
	cipher    *V3ChunkCipher

	buf     []byte // one chunk+tag allocation, reused for plaintext and ciphertext
	err     error  // terminal: never retry a partially emitted record/nonce
	index   uint64
	written int64 // total plaintext accepted
	started bool  // header already written
	closed  bool
}

// NewV3Writer builds a streaming V3 writer. chunkSize <= 0 falls back to the
// default 16 MiB.
func NewV3Writer(w io.Writer, password string, chunkSize int64) (*V3Writer, error) {
	if w == nil {
		return nil, fmt.Errorf("v3: nil writer")
	}
	if chunkSize <= 0 || chunkSize > v3MaxChunkSize {
		chunkSize = v3DefaultChunkSize
	}
	nonce := make([]byte, v3NonceFieldLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("v3: generate nonce: %w", err)
	}
	cipher, err := NewV3ChunkCipher(DeriveV3Key(password, nonce, 600000), nonce)
	if err != nil {
		return nil, err
	}
	return &V3Writer{
		w:         w,
		chunkSize: chunkSize,
		cipher:    cipher,
		nonce:     nonce,
		buf:       make([]byte, 0, chunkSize+v3TagSize),
	}, nil
}

// NonceField returns the container nonce (needed to re-derive the key when
// reading).
func (vw *V3Writer) NonceField() []byte { return append([]byte(nil), vw.nonce...) }

// writeRecord never retries a short write: bytes already emitted cannot safely
// be rolled back. All failures are sticky, including errors alongside full writes.
func (vw *V3Writer) writeRecord(p []byte) error {
	n, err := vw.w.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	return err
}

func (vw *V3Writer) fail(err error) error {
	if vw.err == nil {
		vw.err = err
	}
	return vw.err
}

func (vw *V3Writer) ensureHeader() error {
	if vw.started {
		return nil
	}
	hdr, err := NewV3Header(0, vw.nonce, vw.chunkSize, 600000)
	if err != nil {
		return err
	}
	if err := vw.writeRecord(hdr); err != nil {
		return fmt.Errorf("v3: write header: %w", err)
	}
	vw.started = true
	return nil
}

// flushChunk seals the buffered plaintext as a fixed-width chunk record:
// the plaintext is padded with zeros to chunkSize before sealing so every
// record is exactly chunkSize + tagSize (this is what the seek math relies
// on). The padding is trimmed on read using the trailer's plaintext length.
func (vw *V3Writer) flushChunk() error {
	used := len(vw.buf)
	padded := vw.buf[:vw.chunkSize]
	// The reused buffer contains the previous ciphertext, not zero padding.
	clear(padded[used:])
	rec, err := vw.cipher.seal(padded[:0], vw.index, padded)
	if err != nil {
		return err
	}
	if err := vw.writeRecord(rec); err != nil {
		return fmt.Errorf("v3: write chunk %d: %w", vw.index, err)
	}
	vw.index++
	vw.buf = vw.buf[:0]
	return nil
}

// Write implements io.Writer.
func (vw *V3Writer) Write(p []byte) (int, error) {
	if vw.err != nil {
		return 0, vw.err
	}
	if vw.closed {
		return 0, fmt.Errorf("v3: write to closed container")
	}
	if err := vw.ensureHeader(); err != nil {
		return 0, vw.fail(err)
	}
	writtenThisCall := 0
	for len(p) > 0 {
		need := int(vw.chunkSize) - len(vw.buf)
		if need == 0 {
			if err := vw.flushChunk(); err != nil {
				return writtenThisCall, vw.fail(err)
			}
			need = int(vw.chunkSize)
		}
		n := len(p)
		if n > need {
			n = need
		}
		vw.buf = append(vw.buf, p[:n]...)
		writtenThisCall += n
		vw.written += int64(n)
		p = p[n:]
		if len(vw.buf) == int(vw.chunkSize) {
			if err := vw.flushChunk(); err != nil {
				return writtenThisCall, vw.fail(err)
			}
		}
	}
	return writtenThisCall, nil
}

// Close flushes the final partial chunk (if any) and appends the trailer.
// Calling Close more than once is safe.
func (vw *V3Writer) Close() error {
	if vw.err != nil {
		return vw.err
	}
	if vw.closed {
		return nil
	}
	vw.closed = true
	if err := vw.ensureHeader(); err != nil {
		return vw.fail(err)
	}
	if len(vw.buf) > 0 {
		if err := vw.flushChunk(); err != nil {
			return vw.fail(err)
		}
	}
	t := make([]byte, v3TrailerLen)
	copy(t[:v3TrailerMagicLen], v3TrailerMagicBytes)
	binary.BigEndian.PutUint64(t[8:16], uint64(vw.written))
	if err := vw.writeRecord(t); err != nil {
		return vw.fail(fmt.Errorf("v3: write trailer: %w", err))
	}
	return nil
}

// ReadTrailerV3 reads the trailer at the end of the container and returns the
// recorded plaintext length.
func ReadTrailerV3(ra io.ReaderAt, containerSize int64) (int64, error) {
	if containerSize < V3HeaderSize+v3TrailerLen {
		return 0, fmt.Errorf("v3: container too small: %d", containerSize)
	}
	t := make([]byte, v3TrailerLen)
	if _, err := ra.ReadAt(t, containerSize-v3TrailerLen); err != nil {
		return 0, fmt.Errorf("v3: read trailer: %w", err)
	}
	if !bytes.Equal(t[:v3TrailerMagicLen], v3TrailerMagicBytes) {
		return 0, fmt.Errorf("v3: bad trailer magic")
	}
	return int64(binary.BigEndian.Uint64(t[8:16])), nil
}

// ParseV3StreamHeader extracts the per-container parameters from the leading
// header bytes. ok is false when the prefix is not a V3 stream header.
func ParseV3StreamHeader(b []byte) (nonce []byte, chunkSize uint64, kdf uint32, ok bool) {
	if len(b) < V3HeaderSize ||
		!bytes.Equal(b[:v3MagicLen], v3MagicBytes) ||
		b[6] != byte(ContentVersionV3) {
		return nil, 0, 0, false
	}
	nonce = append([]byte(nil), b[8:24]...)
	chunkSize = uint64(binary.BigEndian.Uint32(b[32:36]))
	kdf = binary.BigEndian.Uint32(b[40:44])
	return nonce, chunkSize, kdf, chunkSize > 0
}

// V3Container is the random-access view of an open V3 container.
// R must support concurrent ReadAt calls and its content must remain immutable
// for the lifetime of this view. Do not mutate its geometry/cipher fields after
// opening: authenticated plaintext is cached as one immutable chunk.
type V3Container struct {
	R         io.ReaderAt
	Size      int64
	ChunkSize uint64
	PlainSize int64
	Cipher    *V3ChunkCipher
	cache     *v3ReadCache // pointer keeps copying the view from copying a mutex
}

type v3ReadCache struct {
	mu    sync.Mutex // serialize misses; concurrent same-chunk reads decrypt once
	index uint64
	plain []byte // immutable after publication, never recycled in place
}

func (c *V3Container) readChunk(index uint64) ([]byte, error) {
	if c.cache != nil {
		c.cache.mu.Lock()
		defer c.cache.mu.Unlock()
		if c.cache.plain != nil && c.cache.index == index {
			return c.cache.plain, nil
		}
	}
	cs := int64(c.ChunkSize)
	if cs <= 0 || cs > v3MaxChunkSize {
		return nil, fmt.Errorf("v3: invalid chunk size %d", cs)
	}
	rec := make([]byte, cs+v3TagSize)
	if n, err := c.R.ReadAt(rec, V3ChunkCipherOffset(index, cs)); n != len(rec) || err != nil {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	pt, err := c.Cipher.open(rec[:0], index, rec)
	if err != nil {
		return nil, err
	}
	if c.cache != nil {
		c.cache.index, c.cache.plain = index, pt
	}
	return pt, nil
}

// OpenV3Container parses the header + trailer of a V3 container stored at ra
// (total size size) and derives the chunk cipher from password.
func OpenV3Container(ra io.ReaderAt, size int64, password string) (*V3Container, error) {
	if ra == nil {
		return nil, fmt.Errorf("v3: nil reader")
	}
	if size < V3HeaderSize+v3TrailerLen {
		return nil, fmt.Errorf("v3: container too small: %d", size)
	}
	h := make([]byte, V3HeaderSize)
	if _, err := ra.ReadAt(h, 0); err != nil {
		return nil, fmt.Errorf("v3: read header: %w", err)
	}
	nonce, chunkSize, kdf, ok := ParseV3StreamHeader(h)
	if !ok {
		return nil, fmt.Errorf("v3: not a v3 container")
	}
	plain, err := ReadTrailerV3(ra, size)
	if err != nil {
		return nil, err
	}
	cipher, err := NewV3ChunkCipher(DeriveV3Key(password, nonce, kdf), nonce)
	if err != nil {
		return nil, err
	}
	return &V3Container{R: ra, Size: size, ChunkSize: chunkSize, PlainSize: plain, Cipher: cipher, cache: &v3ReadCache{}}, nil
}

// ReadAt implements io.ReaderAt over the decrypted plaintext: only the chunk
// records intersecting the requested range are read and authenticated.
func (c *V3Container) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("v3: negative offset %d", off)
	}
	if off >= c.PlainSize {
		return 0, io.EOF
	}
	total := 0
	pos := off
	cs := int64(c.ChunkSize)
	for total < len(p) && pos < c.PlainSize {
		idx, inOff := V3ChunkForOffset(pos, cs)
		pt, err := c.readChunk(idx)
		if err != nil {
			return total, err
		}
		available := c.PlainSize - pos
		if inChunk := cs - inOff; available > inChunk {
			available = inChunk
		}
		n := copy(p[total:], pt[inOff:inOff+available])
		total += n
		pos += int64(n)
		if n == 0 {
			break
		}
	}
	// A range that runs past the container tail is a valid partial read: report
	// io.EOF exactly as io.ReaderAt contract requires.
	if total < len(p) {
		return total, io.EOF
	}
	return total, nil
}

// Sequential returns an io.Reader that decrypts the whole plaintext in order.
func (c *V3Container) Sequential() io.Reader {
	body := io.NewSectionReader(c.R, V3HeaderSize, c.Size-V3HeaderSize-v3TrailerLen)
	return &v3SeqReader{r: body, c: c, cs: int64(c.ChunkSize)}
}

type v3SeqReader struct {
	r      io.Reader
	c      *V3Container
	cs     int64
	index  uint64
	buf    []byte
	record []byte // reused only after buf has been completely consumed
	err    error
	off    int
	read   int64 // plaintext bytes already produced
}

func (s *v3SeqReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if s.err != nil {
		return 0, s.err
	}
	total := 0
	for total < len(p) {
		if s.off < len(s.buf) {
			n := copy(p[total:], s.buf[s.off:])
			s.off += n
			total += n
			s.read += int64(n)
			continue
		}
		if s.read >= s.c.PlainSize {
			return total, io.EOF
		}
		if s.record == nil {
			s.record = make([]byte, s.cs+v3TagSize)
		}
		if _, err := io.ReadFull(s.r, s.record); err != nil {
			s.err = fmt.Errorf("v3: truncated container: %w", err)
			return total, s.err
		}
		pt, err := s.c.Cipher.open(s.record[:0], s.index, s.record)
		if err != nil {
			s.err = err
			return total, s.err
		}
		s.index++
		if over := s.read + int64(len(pt)) - s.c.PlainSize; over > 0 {
			pt = pt[:int64(len(pt))-over]
		}
		s.buf = pt
		s.off = 0
	}
	return total, nil
}
