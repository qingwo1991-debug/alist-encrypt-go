package mysqlstore

import "sync"

type strategyBuffer struct {
	mu    sync.Mutex
	items map[string]StrategyRecord
}

type fileMetaBuffer struct {
	mu    sync.Mutex
	items map[string]FileMetaRecord
}

type rangeCompatBuffer struct {
	mu    sync.Mutex
	items map[string]RangeCompatRecord
}

func newStrategyBuffer() *strategyBuffer {
	return &strategyBuffer{items: make(map[string]StrategyRecord)}
}

func newFileMetaBuffer() *fileMetaBuffer {
	return &fileMetaBuffer{items: make(map[string]FileMetaRecord)}
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
// Caps the buffer at 10000 records to prevent unbounded growth.
func (b *fileMetaBuffer) reEnqueue(records []FileMetaRecord) {
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
