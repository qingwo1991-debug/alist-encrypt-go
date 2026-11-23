package proxy

import (
	"container/list"
	"io"
	"sync"
)

const maxDecryptedCacheServeBytes = 16 * 1024 * 1024

type decryptedBlockCache struct {
	mu        sync.Mutex
	maxBytes  int64
	blockSize int64
	usedBytes int64
	hitCount  uint64
	missCount uint64
	putCount  uint64
	evictions uint64
	// prefixHits counts partial hits served as a cached prefix followed by an
	// upstream continuation (see serveDecryptedCachePrefix).
	prefixHits uint64
	items      map[string]*list.Element
	lru        *list.List
}

type decryptedBlockEntry struct {
	key  string
	data []byte
}

func newDecryptedBlockCache(maxBytes, blockSize int64) *decryptedBlockCache {
	if maxBytes <= 0 || blockSize <= 0 {
		return nil
	}
	return &decryptedBlockCache{
		maxBytes:  maxBytes,
		blockSize: blockSize,
		items:     make(map[string]*list.Element),
		lru:       list.New(),
	}
}

func (c *decryptedBlockCache) getRange(baseKey string, start, length int64) ([]byte, bool) {
	if c == nil || baseKey == "" || start < 0 || length <= 0 {
		return nil, false
	}
	if length > c.maxServeBytes() {
		c.mu.Lock()
		c.missCount++
		c.mu.Unlock()
		return nil, false
	}
	// Published block data is immutable: replacement swaps the slice instead
	// of reusing its backing array. Retained slices survive replacement/eviction.
	var chunks [][]byte
	remaining := length
	blockStart := (start / c.blockSize) * c.blockSize
	blockOffset := start - blockStart

	c.mu.Lock()
	for remaining > 0 {
		key := c.blockKey(baseKey, blockStart)
		elem, ok := c.items[key]
		if !ok {
			c.missCount++
			c.mu.Unlock()
			return nil, false
		}
		entry := elem.Value.(*decryptedBlockEntry)
		need := c.blockSize - blockOffset
		if remaining < need {
			need = remaining
		}
		if int64(len(entry.data)) < blockOffset+need {
			c.missCount++
			c.mu.Unlock()
			return nil, false
		}
		chunks = append(chunks, entry.data[blockOffset:blockOffset+need])
		c.lru.MoveToFront(elem)
		remaining -= need
		blockStart += c.blockSize
		blockOffset = 0
	}
	c.hitCount++
	c.mu.Unlock()

	// Allocate exactly once for payload bytes and copy without holding the
	// cache lock. Callers receive their own buffer, never the cached arrays.
	out := make([]byte, length)
	offset := 0
	for _, chunk := range chunks {
		offset += copy(out[offset:], chunk)
	}
	return out, true
}

// getPrefix returns a copy of the contiguous cached plaintext that starts at
// start, capped at maxLen and at the cache's serve limit. It stops at the first
// missing or short block, so the result is always a gap-free prefix of the
// requested interval. A nil result means not even the first byte is cached.
func (c *decryptedBlockCache) getPrefix(baseKey string, start, maxLen int64) []byte {
	if c == nil || baseKey == "" || start < 0 || maxLen <= 0 {
		return nil
	}
	if limit := c.maxServeBytes(); maxLen > limit {
		maxLen = limit
	}
	var chunks [][]byte
	total := int64(0)
	blockStart := (start / c.blockSize) * c.blockSize
	blockOffset := start - blockStart

	c.mu.Lock()
	for total < maxLen {
		elem, ok := c.items[c.blockKey(baseKey, blockStart)]
		if !ok {
			break
		}
		entry := elem.Value.(*decryptedBlockEntry)
		if int64(len(entry.data)) <= blockOffset {
			break
		}
		chunk := entry.data[blockOffset:]
		if rem := maxLen - total; int64(len(chunk)) > rem {
			chunk = chunk[:rem]
		}
		chunks = append(chunks, chunk)
		c.lru.MoveToFront(elem)
		total += int64(len(chunk))
		if int64(len(entry.data)) < c.blockSize {
			// A short block (stream ended mid-block) breaks contiguity.
			break
		}
		blockStart += c.blockSize
		blockOffset = 0
	}
	if total > 0 {
		c.prefixHits++
	}
	c.mu.Unlock()

	if total == 0 {
		return nil
	}
	out := make([]byte, total)
	offset := 0
	for _, chunk := range chunks {
		offset += copy(out[offset:], chunk)
	}
	return out
}

func (c *decryptedBlockCache) putBlock(baseKey string, blockStart int64, data []byte) {
	if c == nil || baseKey == "" || blockStart < 0 || blockStart%c.blockSize != 0 || len(data) == 0 {
		return
	}
	if int64(len(data)) > c.blockSize {
		data = data[:c.blockSize]
	}
	key := c.blockKey(baseKey, blockStart)
	copyData := append([]byte(nil), data...)

	c.mu.Lock()
	defer c.mu.Unlock()
	if elem, ok := c.items[key]; ok {
		entry := elem.Value.(*decryptedBlockEntry)
		c.usedBytes -= int64(len(entry.data))
		entry.data = copyData
		c.usedBytes += int64(len(entry.data))
		c.putCount++
		c.lru.MoveToFront(elem)
		c.evictLocked()
		return
	}
	entry := &decryptedBlockEntry{key: key, data: copyData}
	elem := c.lru.PushFront(entry)
	c.items[key] = elem
	c.usedBytes += int64(len(copyData))
	c.putCount++
	c.evictLocked()
}

func (c *decryptedBlockCache) evictLocked() {
	for c.usedBytes > c.maxBytes {
		elem := c.lru.Back()
		if elem == nil {
			return
		}
		entry := elem.Value.(*decryptedBlockEntry)
		delete(c.items, entry.key)
		c.usedBytes -= int64(len(entry.data))
		c.lru.Remove(elem)
		c.evictions++
	}
}

func (c *decryptedBlockCache) stats() map[string]interface{} {
	if c == nil {
		return map[string]interface{}{
			"enabled": false,
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return map[string]interface{}{
		"enabled":          true,
		"entries":          len(c.items),
		"used_bytes":       c.usedBytes,
		"max_bytes":        c.maxBytes,
		"block_size":       c.blockSize,
		"hit_count":        c.hitCount,
		"miss_count":       c.missCount,
		"put_count":        c.putCount,
		"eviction_count":   c.evictions,
		"prefix_hit_count": c.prefixHits,
	}
}

func (c *decryptedBlockCache) maxServeBytes() int64 {
	if c == nil || c.maxBytes <= 0 {
		return 0
	}
	if c.maxBytes < maxDecryptedCacheServeBytes {
		return c.maxBytes
	}
	return maxDecryptedCacheServeBytes
}

func (c *decryptedBlockCache) blockKey(baseKey string, offset int64) string {
	return baseKey + "|" + itoa64(offset/c.blockSize)
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func itoa64(v int64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

type decryptedCacheReader struct {
	src        io.Reader
	cache      *decryptedBlockCache
	baseKey    string
	nextOffset int64
	blockStart int64
	pending    []byte
}

func newDecryptedCacheReader(src io.Reader, cache *decryptedBlockCache, baseKey string, start int64) io.Reader {
	if cache == nil || baseKey == "" || start < 0 {
		return src
	}
	return &decryptedCacheReader{
		src:        src,
		cache:      cache,
		baseKey:    baseKey,
		nextOffset: start,
		blockStart: (start / cache.blockSize) * cache.blockSize,
	}
}

func (r *decryptedCacheReader) Read(p []byte) (int, error) {
	n, err := r.src.Read(p)
	if n > 0 {
		r.add(p[:n])
	}
	if err == io.EOF {
		r.flushPending()
	}
	return n, err
}

func (r *decryptedCacheReader) add(data []byte) {
	for len(data) > 0 {
		blockOff := r.nextOffset - r.blockStart
		if blockOff != int64(len(r.pending)) {
			r.pending = r.pending[:0]
		}
		space := r.cache.blockSize - blockOff
		if space <= 0 {
			r.flushPending()
			r.blockStart += r.cache.blockSize
			continue
		}
		if blockOff != 0 && len(r.pending) == 0 {
			skip := int(space)
			if skip > len(data) {
				skip = len(data)
			}
			r.nextOffset += int64(skip)
			data = data[skip:]
			if r.nextOffset-r.blockStart >= r.cache.blockSize {
				r.blockStart += r.cache.blockSize
			}
			continue
		}
		take := int(space)
		if take > len(data) {
			take = len(data)
		}
		r.pending = append(r.pending, data[:take]...)
		r.nextOffset += int64(take)
		data = data[take:]
		if int64(len(r.pending)) == r.cache.blockSize {
			r.flushPending()
			r.blockStart += r.cache.blockSize
		}
	}
}

func (r *decryptedCacheReader) flushPending() {
	if len(r.pending) == 0 {
		return
	}
	r.cache.putBlock(r.baseKey, r.blockStart, r.pending)
	r.pending = r.pending[:0]
}
