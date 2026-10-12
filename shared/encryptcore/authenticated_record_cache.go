package encryption

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
	"time"
)

// V3RecordCacheKey is an opaque, domain-separated identity, not an authorization
// token. Callers must authorize each request before consulting plaintext caches.
type V3RecordCacheKey [32]byte

// V3RecordIdentity binds plaintext to an object, authorization scope, password,
// and complete geometry. Revision must be a trustworthy object revision; without
// one, the exact URL is required and conservatively participates in the key.
// Generation is deliberately absent: playback interest is not object identity.
type V3RecordIdentity struct {
	Provider, Object, Revision, URL, Scope, Password      string
	Version, HeaderSize, PlainSize, CipherSize, ChunkSize int64
	KDFIterations                                         uint32
	Nonce                                                 []byte
}

func NewV3RecordCacheKey(id V3RecordIdentity) (V3RecordCacheKey, error) {
	var zero V3RecordCacheKey
	if id.Provider == "" || id.Object == "" || id.Scope == "" || (id.Revision == "" && id.URL == "") {
		return zero, fmt.Errorf("v3: incomplete record cache identity")
	}
	if id.Version != ContentVersionV3 || id.HeaderSize != V3HeaderSize || len(id.Nonce) != v3NonceFieldLen || id.PlainSize < 0 || id.ChunkSize <= 0 || id.ChunkSize > v3MaxChunkSize {
		return zero, fmt.Errorf("v3: invalid record cache geometry")
	}
	count := id.PlainSize / id.ChunkSize
	if id.PlainSize%id.ChunkSize != 0 {
		count++
	}
	if count > 1<<32 || count > (math.MaxInt64-V3HeaderSize)/(id.ChunkSize+v3TagSize) {
		return zero, fmt.Errorf("v3: record geometry overflow")
	}
	size := int64(V3HeaderSize) + count*(id.ChunkSize+v3TagSize)
	if id.CipherSize != size && id.CipherSize != size+v3TrailerLen {
		return zero, fmt.Errorf("v3: inconsistent container size")
	}
	h := sha256.New()
	field := func(b []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	field([]byte("alist-encrypt/v3-authenticated-record/v1"))
	for _, s := range []string{id.Provider, id.Object, id.Revision, id.Scope} {
		field([]byte(s))
	}
	if id.Revision == "" {
		field([]byte(id.URL))
	} else {
		field(nil)
	}
	password := sha256.Sum256([]byte(id.Password))
	field(password[:])
	field(id.Nonce)
	iterations := id.KDFIterations
	if iterations == 0 {
		iterations = 600000
	}
	for _, n := range []int64{id.Version, id.HeaderSize, id.PlainSize, id.CipherSize, id.ChunkSize, int64(iterations)} {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(n))
		field(b[:])
	}
	var key V3RecordCacheKey
	copy(key[:], h.Sum(nil))
	return key, nil
}

var ErrV3RecordCacheFull = errors.New("v3: authenticated record cache budget exhausted")

// V3RawRecordLoader returns an exclusively owned whole ciphertext record; the
// reader may decrypt it in place on an uncached fallback. Its allocation,
// upstream IO and concurrency remain subject to the caller's record admission.
// Load never starts goroutines or singleflight leaders and does not retain raw.
type V3RawRecordLoader func(context.Context, uint64) ([]byte, error)

type v3RecordID struct {
	key   V3RecordCacheKey
	index uint64
}
type v3RecordEntry struct {
	id      v3RecordID
	plain   []byte
	weight  int64
	refs    int
	expires time.Time
	elem    *list.Element
}

// V3AuthenticatedRecordCache owns an immutable byte-LRU. used includes resident
// backing allocations, evicted-but-leased backing allocations, and reservations
// for in-progress Open. The 4096-entry ownership cap also includes reservations
// and evicted-but-pinned entries, not just the resident LRU. There is no extra
// unbounded pinned-copy budget.
// Ciphertext buffers and uncached stream record buffers are external admission.
type V3AuthenticatedRecordCache struct {
	mu                       sync.Mutex
	maxBytes, used, reserved int64
	pending                  int
	ownedEntries             int // resident + pending + evicted-but-pinned; capped at 4096
	ttl                      time.Duration
	entries                  map[v3RecordID]*v3RecordEntry
	lru                      list.List
	now                      func() time.Time
}

func NewV3AuthenticatedRecordCache(maxBytes int64, ttl time.Duration) *V3AuthenticatedRecordCache {
	if maxBytes <= 0 {
		maxBytes = 64 << 20
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &V3AuthenticatedRecordCache{maxBytes: maxBytes, ttl: ttl, entries: make(map[v3RecordID]*v3RecordEntry), now: time.Now}
}

// V3RecordLease exposes copies through ReadAt, never a mutable backing slice.
// ReadAt and Release are safe concurrently. Release is idempotent and mandatory.
type V3RecordLease struct {
	cache    *V3AuthenticatedRecordCache
	entry    *v3RecordEntry
	released bool
}

func (l *V3RecordLease) Len() int64 {
	if l == nil {
		return 0
	}
	l.cache.mu.Lock()
	defer l.cache.mu.Unlock()
	if l.released {
		return 0
	}
	return int64(len(l.entry.plain))
}
func (l *V3RecordLease) ReadAt(p []byte, off int64) (int, error) {
	if l == nil {
		return 0, io.ErrClosedPipe
	}
	l.cache.mu.Lock()
	defer l.cache.mu.Unlock()
	if l.released {
		return 0, io.ErrClosedPipe
	}
	if off < 0 {
		return 0, fmt.Errorf("v3: negative lease offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= int64(len(l.entry.plain)) {
		return 0, io.EOF
	}
	n := copy(p, l.entry.plain[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
func (l *V3RecordLease) Release() {
	if l == nil {
		return
	}
	c := l.cache
	c.mu.Lock()
	defer c.mu.Unlock()
	if l.released {
		return
	}
	l.released = true
	e := l.entry
	l.entry = nil
	e.refs--
	if e.refs == 0 && e.elem == nil {
		c.used -= e.weight
		c.ownedEntries--
		e.plain = nil
	}
}
func (c *V3AuthenticatedRecordCache) remove(e *v3RecordEntry) {
	delete(c.entries, e.id)
	c.lru.Remove(e.elem)
	e.elem = nil
	if e.refs == 0 {
		c.used -= e.weight
		c.ownedEntries--
		e.plain = nil
	}
}
func (c *V3AuthenticatedRecordCache) get(id v3RecordID) (*V3RecordLease, bool) {
	e := c.entries[id]
	if e == nil {
		return nil, false
	}
	if !c.now().Before(e.expires) {
		c.remove(e)
		return nil, false
	}
	c.lru.MoveToFront(e.elem)
	e.refs++
	return &V3RecordLease{cache: c, entry: e}, true
}
func (c *V3AuthenticatedRecordCache) Get(key V3RecordCacheKey, index uint64) (*V3RecordLease, bool) {
	if c == nil || key == (V3RecordCacheKey{}) {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.get(v3RecordID{key, index})
}
func (c *V3AuthenticatedRecordCache) reserve(n int64) bool {
	if n <= 0 || n > c.maxBytes {
		return false
	}
	for (c.used > c.maxBytes-n || c.ownedEntries >= 4096) && c.lru.Len() > 0 {
		c.remove(c.lru.Back().Value.(*v3RecordEntry))
	}
	if c.used > c.maxBytes-n || c.ownedEntries >= 4096 {
		return false
	}
	c.used += n
	c.reserved += n
	c.pending++
	c.ownedEntries++
	return true
}

// Load authenticates inside the trust boundary; no public plaintext Put exists.
// A hit requires no cipher/KDF or loader. On miss nil cipher/loader fail closed.
// Concurrent misses may duplicate IO, but reservations bound all owned plaintext
// and no leader goroutines/waiters are created. Cancellation is cooperative at
// loader boundaries, not an implementation of Stage 4 shared cancel-wait.
func (c *V3AuthenticatedRecordCache) Load(ctx context.Context, key V3RecordCacheKey, index uint64, cipher *V3ChunkCipher, chunkSize, plainSize int64, loader V3RawRecordLoader) (*V3RecordLease, error) {
	if c == nil || ctx == nil || key == (V3RecordCacheKey{}) {
		return nil, fmt.Errorf("v3: invalid cache load")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if chunkSize <= 0 || chunkSize > v3MaxChunkSize || plainSize <= 0 || index > math.MaxUint32 || index > uint64((plainSize-1)/chunkSize) {
		return nil, fmt.Errorf("v3: invalid record index/geometry")
	}
	if l, ok := c.Get(key, index); ok {
		return l, nil
	}
	if cipher == nil || loader == nil {
		return nil, fmt.Errorf("v3: nil cipher or record loader")
	}
	c.mu.Lock()
	ok := c.reserve(chunkSize)
	c.mu.Unlock()
	if !ok {
		return nil, ErrV3RecordCacheFull
	}
	// Always retire the reservation, including failures and canceled loaders.
	transferred := false
	defer func() {
		if !transferred {
			c.mu.Lock()
			c.used -= chunkSize
			c.reserved -= chunkSize
			c.pending--
			c.ownedEntries--
			c.mu.Unlock()
		}
	}()
	raw, err := loader(ctx, index)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if int64(len(raw)) != chunkSize+v3TagSize {
		return nil, io.ErrUnexpectedEOF
	}
	pt, err := cipher.Open(index, raw)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	length := plainSize - int64(index)*chunkSize
	if length > chunkSize {
		length = chunkSize
	}
	pt = pt[:length:length]
	c.mu.Lock()
	defer c.mu.Unlock()
	id := v3RecordID{key, index}
	if l, hit := c.get(id); hit {
		return l, nil
	}
	e := &v3RecordEntry{id: id, plain: pt, weight: chunkSize, refs: 1, expires: c.now().Add(c.ttl)}
	// Atomically transfer the reservation to resident ownership.
	c.reserved -= chunkSize
	c.pending--
	transferred = true
	e.elem = c.lru.PushFront(e)
	c.entries[id] = e
	return &V3RecordLease{cache: c, entry: e}, nil
}

// publishAuthenticated is private and called only immediately after stream Open.
// The copy is reserved before allocating and never aliases the reused record.
func (c *V3AuthenticatedRecordCache) publishAuthenticated(key V3RecordCacheKey, index uint64, pt []byte) {
	if c == nil || key == (V3RecordCacheKey{}) || len(pt) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	id := v3RecordID{key, index}
	if l, ok := c.get(id); ok {
		l.entry.refs--
		return
	}
	weight := int64(len(pt))
	if !c.reserve(weight) {
		return
	}
	owned := make([]byte, len(pt))
	copy(owned, pt)
	c.reserved -= weight
	c.pending--
	e := &v3RecordEntry{id: id, plain: owned, weight: weight, expires: c.now().Add(c.ttl)}
	e.elem = c.lru.PushFront(e)
	c.entries[id] = e
}

// V3RecordCacheStats allows callers/tests to verify the shared ownership cap.
type V3RecordCacheStats struct {
	MaxBytes, OwnedBytes, ReservedBytes, ResidentBytes, PinnedEvictedBytes int64
	Entries, OwnedEntries, ReservedEntries                                 int
}

func (c *V3AuthenticatedRecordCache) Stats() V3RecordCacheStats {
	if c == nil {
		return V3RecordCacheStats{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	s := V3RecordCacheStats{MaxBytes: c.maxBytes, OwnedBytes: c.used, ReservedBytes: c.reserved, Entries: len(c.entries), OwnedEntries: c.ownedEntries, ReservedEntries: c.pending}
	for _, e := range c.entries {
		s.ResidentBytes += e.weight
	}
	s.PinnedEvictedBytes = s.OwnedBytes - s.ReservedBytes - s.ResidentBytes
	return s
}
