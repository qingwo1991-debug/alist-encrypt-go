package mysqlstore

import (
	"bytes"
	"sync"
)

type strategyBuffer struct {
	mu    sync.Mutex
	items map[string]StrategyRecord
}

type fileMetaBuffer struct {
	mu sync.Mutex
	// items holds records waiting for the next flush.
	items map[string]FileMetaRecord
	// lastFlushed remembers the row last handed to MySQL per key (after a
	// successful flush). It survives drain, so a write that changes nothing
	// but timestamps is dropped before it reaches the database. It is bounded
	// like the pending buffer and is purely an optimisation: correctness comes
	// from the primary-key SELECT the flush performs for unknown keys.
	lastFlushed map[string]FileMetaRecord
}

// fileMetaBufferMemoryCap bounds both the pending and the lastFlushed maps.
const fileMetaBufferMemoryCap = 10000

type rangeCompatBuffer struct {
	mu    sync.Mutex
	items map[string]RangeCompatRecord
}

func newStrategyBuffer() *strategyBuffer {
	return &strategyBuffer{items: make(map[string]StrategyRecord)}
}

func newFileMetaBuffer() *fileMetaBuffer {
	return &fileMetaBuffer{
		items:       make(map[string]FileMetaRecord),
		lastFlushed: make(map[string]FileMetaRecord),
	}
}

func newRangeCompatBuffer() *rangeCompatBuffer {
	return &rangeCompatBuffer{items: make(map[string]RangeCompatRecord)}
}

func (b *strategyBuffer) upsert(record StrategyRecord) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.items[record.KeyHash] = record
}

func (b *strategyBuffer) drain() []StrategyRecord {
	b.mu.Lock()
	old := b.items
	b.items = make(map[string]StrategyRecord)
	b.mu.Unlock()

	out := make([]StrategyRecord, 0, len(old))
	for _, value := range old {
		out = append(out, value)
	}
	return out
}

func (b *fileMetaBuffer) upsert(record FileMetaRecord) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.items[record.KeyHash] = record
}

// FileMetaWriteEqual reports whether two file_meta rows are identical in
// every column that carries information. Timestamps (updated_at,
// last_accessed) are deliberately excluded: they are stamped by the write
// itself, so a row whose only difference is a newer timestamp is a no-op
// rewrite. raw_url / raw_url_auth_scope / sign ARE part of the comparison,
// so a refreshed signed URL is always written.
func FileMetaWriteEqual(a, b FileMetaRecord) bool {
	return a.ProviderHost == b.ProviderHost &&
		a.OriginalPath == b.OriginalPath &&
		a.EncryptedPath == b.EncryptedPath &&
		a.Name == b.Name &&
		a.Size == b.Size &&
		a.CiphertextSize == b.CiphertextSize &&
		a.ContentVersion == b.ContentVersion &&
		a.HeaderLen == b.HeaderLen &&
		bytes.Equal(a.NonceField, b.NonceField) &&
		a.ChunkSize == b.ChunkSize &&
		a.KDFIterations == b.KDFIterations &&
		a.ETag == b.ETag &&
		a.ContentType == b.ContentType &&
		a.StatusCode == b.StatusCode &&
		a.RawURL == b.RawURL &&
		a.RawURLAuthScope == b.RawURLAuthScope &&
		a.Sign == b.Sign &&
		a.Active == b.Active
}

// fileMetaWriteUnchanged reports whether writing incoming would leave the
// stored row informationally identical. It folds the fields the SQL upsert
// itself preserves from the existing row into the comparison first, so a
// size-only write is not treated as "different" merely because the caller
// did not repeat the URL or geometry it does not know about.
//
// upstream_fetched_at is only consulted when the caller recorded a real
// upstream fetch (FileMetaRecord.explicitFetch). The DAO write path stamps
// it with "now" on every cache publish, so the stamp alone must not defeat
// dedup; a caller-supplied fetch time that moved is honoured and forces the
// write.
func fileMetaWriteUnchanged(incoming, stored FileMetaRecord) bool {
	if fileMetaUpstreamFetchedChanged(incoming, stored) {
		return false
	}
	return FileMetaWriteEqual(inheritFileMetaFields(incoming, stored), stored)
}

// fileMetaUpstreamFetchedChanged reports whether an explicitly supplied
// upstream fetch time really moved relative to the stored row.
func fileMetaUpstreamFetchedChanged(incoming, stored FileMetaRecord) bool {
	if !incoming.explicitFetch || incoming.UpstreamFetchedAt.IsZero() {
		return false
	}
	if stored.UpstreamFetchedAt.IsZero() {
		return true
	}
	return !incoming.UpstreamFetchedAt.Equal(stored.UpstreamFetchedAt)
}

// inheritFileMetaFields fills fields the incoming record leaves empty from
// the existing row for the same key. Only fields the SQL upsert itself would
// have preserved are inherited, so the no-op comparison sees the row MySQL
// would actually end up storing. Timestamps are never inherited here.
func inheritFileMetaFields(record, from FileMetaRecord) FileMetaRecord {
	if record.RawURL == "" {
		record.RawURL = from.RawURL
		record.RawURLAuthScope = from.RawURLAuthScope
	}
	if record.Sign == "" {
		record.Sign = from.Sign
	}
	if record.EncryptedPath == "" {
		record.EncryptedPath = from.EncryptedPath
	}
	if record.Name == "" {
		record.Name = from.Name
	}
	if record.ProviderHost == "" {
		record.ProviderHost = from.ProviderHost
	}
	// A zero status means "not observed" (the DAO writer never sets it; the
	// size resolver stores 200/206). Keep the stored observation rather than
	// letting the two write paths flip it back and forth.
	if record.StatusCode == 0 {
		record.StatusCode = from.StatusCode
	}
	if record.ETag == "" {
		record.ETag = from.ETag
	}
	if record.ContentType == "" {
		record.ContentType = from.ContentType
	}
	return record
}

func (b *fileMetaBuffer) drain() []FileMetaRecord {
	b.mu.Lock()
	old := b.items
	b.items = make(map[string]FileMetaRecord)
	b.mu.Unlock()

	out := make([]FileMetaRecord, 0, len(old))
	for _, value := range old {
		out = append(out, value)
	}
	return out
}

// markFlushed records the rows a successful flush wrote, so an identical
// later write can be skipped without a database round trip. Rows that were
// filtered out as unchanged must not be passed here.
func (b *fileMetaBuffer) markFlushed(records []FileMetaRecord) {
	if len(records) == 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, r := range records {
		if _, exists := b.lastFlushed[r.KeyHash]; !exists && len(b.lastFlushed) >= fileMetaBufferMemoryCap {
			// Bound the map; drop one arbitrary entry rather than refuse to
			// learn. The worst case is one extra SELECT/UPSERT for that key.
			for k := range b.lastFlushed {
				delete(b.lastFlushed, k)
				break
			}
		}
		r.explicitFetch = false
		r.NonceField = append([]byte(nil), r.NonceField...)
		b.lastFlushed[r.KeyHash] = r
	}
}

// rememberFlushed publishes rows that a flush found unchanged (so they were
// not written) into lastFlushed, using the record that was about to be
// written. This lets the in-memory fast path skip the SELECT next time.
func (b *fileMetaBuffer) rememberFlushed(records []FileMetaRecord) {
	if len(records) == 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, r := range records {
		if _, exists := b.lastFlushed[r.KeyHash]; !exists && len(b.lastFlushed) >= fileMetaBufferMemoryCap {
			for k := range b.lastFlushed {
				delete(b.lastFlushed, k)
				break
			}
		}
		r.explicitFetch = false
		r.NonceField = append([]byte(nil), r.NonceField...)
		b.lastFlushed[r.KeyHash] = r
	}
}

func (b *rangeCompatBuffer) upsert(record RangeCompatRecord) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.items[record.KeyHash] = record
}

func (b *rangeCompatBuffer) drain() []RangeCompatRecord {
	b.mu.Lock()
	old := b.items
	b.items = make(map[string]RangeCompatRecord)
	b.mu.Unlock()

	out := make([]RangeCompatRecord, 0, len(old))
	for _, value := range old {
		out = append(out, value)
	}
	return out
}

// reEnqueue puts records back into the buffer after a failed flush.
// Caps the buffer at 10000 records to prevent unbounded growth.
func (b *strategyBuffer) reEnqueue(records []StrategyRecord) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, r := range records {
		if len(b.items) >= 10000 {
			break
		}
		b.items[r.KeyHash] = r
	}
}

// reEnqueue puts records back into the buffer after a failed flush.
// Caps the buffer at 10000 records to prevent unbounded growth. A newer
// pending write for the same key wins over the retry; the retried row only
// lends fields the newer one lacks so a transient flush error cannot drop
// the only copy of a signed URL or mapping.
func (b *fileMetaBuffer) reEnqueue(records []FileMetaRecord) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, r := range records {
		if len(b.items) >= fileMetaBufferMemoryCap {
			break
		}
		if pending, ok := b.items[r.KeyHash]; ok {
			b.items[r.KeyHash] = inheritFileMetaFields(pending, r)
			continue
		}
		b.items[r.KeyHash] = r
	}
}

// reEnqueue puts records back into the buffer after a failed flush.
// Caps the buffer at 10000 records to prevent unbounded growth.
func (b *rangeCompatBuffer) reEnqueue(records []RangeCompatRecord) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, r := range records {
		if len(b.items) >= 10000 {
			break
		}
		b.items[r.KeyHash] = r
	}
}
