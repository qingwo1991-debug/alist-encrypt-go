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

func newStrategyBuffer() *strategyBuffer {
	return &strategyBuffer{items: make(map[string]StrategyRecord)}
}

func newFileMetaBuffer() *fileMetaBuffer {
	return &fileMetaBuffer{items: make(map[string]FileMetaRecord)}
}

func (b *strategyBuffer) upsert(record StrategyRecord) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.items[record.KeyHash] = record
}

func (b *strategyBuffer) drain() []StrategyRecord {
	b.mu.Lock()
	defer b.mu.Unlock()

	out := make([]StrategyRecord, 0, len(b.items))
	for _, value := range b.items {
		out = append(out, value)
	}
	b.items = make(map[string]StrategyRecord)
	return out
}

func (b *fileMetaBuffer) upsert(record FileMetaRecord) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.items[record.KeyHash] = record
}

func (b *fileMetaBuffer) drain() []FileMetaRecord {
	b.mu.Lock()
	defer b.mu.Unlock()

	out := make([]FileMetaRecord, 0, len(b.items))
	for _, value := range b.items {
		out = append(out, value)
	}
	b.items = make(map[string]FileMetaRecord)
	return out
}
