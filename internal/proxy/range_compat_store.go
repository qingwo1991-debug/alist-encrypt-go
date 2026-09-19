package proxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// RangeCompatState tracks learned upstream range compatibility state.
type RangeCompatState struct {
	Incompatible         bool
	ConsecutiveFailures  int
	ConsecutiveSuccesses int
	NextProbeAt          time.Time
	LastReason           string
	LastCheckedAt        time.Time
	LastAccessed         time.Time
	UpdatedAt            time.Time
}

// RangeCompatStore persists range compatibility learning state.
type RangeCompatStore interface {
	Get(key string) (RangeCompatState, bool, error)
	Upsert(key string, state RangeCompatState) error
	// Close flushes any buffered state and releases background resources.
	// It is idempotent and safe to call from the server shutdown path.
	Close() error
}

type memoryRangeCompatStore struct {
	mu    sync.RWMutex
	items map[string]RangeCompatState
}

func NewMemoryRangeCompatStore() RangeCompatStore {
	return &memoryRangeCompatStore{
		items: make(map[string]RangeCompatState),
	}
}

func (s *memoryRangeCompatStore) Close() error { return nil }

func (s *memoryRangeCompatStore) Get(key string) (RangeCompatState, bool, error) {
	if key == "" {
		return RangeCompatState{}, false, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, ok := s.items[key]
	return state, ok, nil
}

func (s *memoryRangeCompatStore) Upsert(key string, state RangeCompatState) error {
	if key == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if state.UpdatedAt.IsZero() {
		state.UpdatedAt = now
	}
	state.LastAccessed = now
	s.items[key] = state
	return nil
}

func (s *memoryRangeCompatStore) Stats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return map[string]interface{}{
		"entries": len(s.items),
		"mode":    "memory",
	}
}

// flushIntervalFileRangeCompat is the maximum cadence at which the file-backed
// range compatibility store persists. Learned state is kept in memory for
// immediate reads; a background flusher coalesces concurrent writes into a
// single file write per interval, so ordinary video seeks never hit the disk
// (moving a `save()` per Upsert into the background). The value is a package
// level var so tests can shorten the window.
var fileRangeCompatFlushInterval = 750 * time.Millisecond

const fileRangeCompatMaxFlushDepth = 1

// fileRangeCompatStore persists range compatibility to a JSON file.
// Survives restarts so that learned data accumulates over time.
//
// Writes are debounced: Upsert only updates the in-memory map and signals a
// background flusher; the flusher writes the whole file at most once per
// flushInterval. Close() performs a final synchronous flush so shutdown does
// not lose the tail of learned state.
type fileRangeCompatStore struct {
	mu       sync.RWMutex
	path     string
	items    map[string]RangeCompatState
	dirty    bool
	writeCnt int64

	touchCh chan struct{} // buffered(1) non-blocking signal "something changed"
	stopCh  chan struct{}
	doneCh  chan struct{}
	once    sync.Once
}

func NewFileRangeCompatStore(path string) (RangeCompatStore, error) {
	if path == "" {
		return NewMemoryRangeCompatStore(), nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	s := &fileRangeCompatStore{
		path:    path,
		items:   make(map[string]RangeCompatState),
		touchCh: make(chan struct{}, fileRangeCompatMaxFlushDepth),
		stopCh:  make(chan struct{}),
		doneCh:  make(chan struct{}),
	}
	s.load()
	go s.loop()
	return s, nil
}

func (s *fileRangeCompatStore) load() {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	json.Unmarshal(data, &s.items)
	// Purge entries older than 30 days
	cutoff := time.Now().Add(-30 * 24 * time.Hour)
	for k, v := range s.items {
		if v.LastAccessed.Before(cutoff) {
			delete(s.items, k)
		}
	}
}

// persist writes data to the JSON file atomically (tmp + rename).
func (s *fileRangeCompatStore) persist(data []byte) {
	tmpPath := s.path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return
	}
	os.Rename(tmpPath, s.path)
}

// loop is the background flusher. It waits for a change signal, then debounces
// for fileRangeCompatFlushInterval while concurrent writes keep arriving, and
// finally writes the file once. On shutdown it does a final flush and closes
// doneCh so Close() can block until the tail is persisted.
func (s *fileRangeCompatStore) loop() {
	defer close(s.doneCh)
	interval := fileRangeCompatFlushInterval
	timer := time.NewTimer(interval)
	if !timer.Stop() {
		<-timer.C
	}
	for {
		select {
		case <-s.stopCh:
			timer.Stop()
			s.flushLocked()
			return
		case <-s.touchCh:
			// Debounce: keep resetting the window while writes keep arriving.
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(interval)
			// Drain any queued signals so a burst of writes is one flush.
			select {
			case <-s.touchCh:
			default:
			}
		case <-timer.C:
			if !s.flushLocked() {
				// Nothing was dirty: park the timer instead of spinning an idle
				// ticker forever. The next Upsert will re-arm it.
				timer.Stop()
				select {
				case <-timer.C:
				default:
				}
			} else {
				timer.Reset(interval)
			}
		}
	}
}

// flushLocked snapshots the dirty map under lock, then writes once outside.
// It returns true when a write actually happened; it never makes progress on
// a clean map. Called by the background flusher or by Close(). Errors are
// swallowed: range learning is an optimization, never a correctness
// dependency.
func (s *fileRangeCompatStore) flushLocked() bool {
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return false
	}
	s.dirty = false
	s.writeCnt++
	data, err := json.Marshal(s.items)
	s.mu.Unlock()
	if err != nil {
		return false
	}
	s.persist(data)
	return true
}

func (s *fileRangeCompatStore) Close() error {
	s.once.Do(func() { close(s.stopCh) })
	<-s.doneCh
	return nil
}

func (s *fileRangeCompatStore) Get(key string) (RangeCompatState, bool, error) {
	if key == "" {
		return RangeCompatState{}, false, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, ok := s.items[key]
	return state, ok, nil
}

func (s *fileRangeCompatStore) Upsert(key string, state RangeCompatState) error {
	if key == "" {
		return nil
	}
	s.mu.Lock()
	if state.UpdatedAt.IsZero() {
		state.UpdatedAt = time.Now()
	}
	state.LastAccessed = time.Now()
	s.items[key] = state
	s.dirty = true
	s.mu.Unlock()
	// Signal the flusher without blocking the request path; if the buffer is
	// already full a flush is already pending and this write is covered.
	select {
	case s.touchCh <- struct{}{}:
	default:
	}
	return nil
}

func (s *fileRangeCompatStore) Stats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return map[string]interface{}{
		"entries":       len(s.items),
		"mode":          "file",
		"path":          s.path,
		"persist_count": s.writeCnt,
	}
}
