package storage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	bolt "go.etcd.io/bbolt"
)

const (
	FilenameReadIndexNotReady = "notready"
	FilenameReadIndexBuilding = "building"
	FilenameReadIndexReady    = "ready"
	FilenameReadIndexRebuild  = "rebuild"
	filenameReadCacheLimit    = 256
)

var (
	filenameReadIndex            = []byte("filename_read_candidates_v1")
	filenameReadIndexMarker      = []byte("ready")
	ErrFilenameReadIndexNotReady = errors.New("filename read index not ready; retry later")
	ErrFilenameReadAmbiguous     = errors.New("ambiguous filename read mapping")
)

// FilenameReadIndexProgress contains no paths, credentials or audit values.
// The index is always rebuilt before NewStore returns, including after rollback
// to an older writer which did not know about this derived bucket.
type FilenameReadIndexProgress struct {
	State      string    `json:"state"`
	Scanned    uint64    `json:"scanned"`
	Total      uint64    `json:"total"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
}

type filenameReadCacheEntry struct {
	rec   FilenameRecord
	found bool
}

func (s *Store) FilenameReadIndexStatus() FilenameReadIndexProgress {
	if s == nil {
		return FilenameReadIndexProgress{State: FilenameReadIndexNotReady}
	}
	s.filenameProgressMu.RLock()
	defer s.filenameProgressMu.RUnlock()
	p := s.filenameProgress
	if p.State == "" {
		p.State = FilenameReadIndexNotReady
	}
	return p
}

func (s *Store) setFilenameReadState(state string) {
	s.filenameProgressMu.Lock()
	s.filenameProgress.State = state
	s.filenameProgressMu.Unlock()
}

// RebuildFilenameReadIndex replaces only derived data in one atomic transaction.
// Reads during an explicit rebuild return a retryable error, never a false miss
// or a primary scan. Startup rebuild finishes before the store can be served.
func (s *Store) RebuildFilenameReadIndex() error {
	if err := s.filenameReady(); err != nil {
		return err
	}
	s.filenameRebuildMu.Lock()
	defer s.filenameRebuildMu.Unlock()
	s.filenameProgressMu.Lock()
	s.filenameProgress = FilenameReadIndexProgress{State: FilenameReadIndexBuilding, StartedAt: time.Now().UTC()}
	s.filenameProgressMu.Unlock()
	log.Printf("filename read index: state=building")
	err := s.update(func(tx *bolt.Tx) error {
		if tx.Bucket(filenameReadIndex) != nil {
			if err := tx.DeleteBucket(filenameReadIndex); err != nil {
				return err
			}
		}
		idx, err := tx.CreateBucket(filenameReadIndex)
		if err != nil {
			return err
		}
		b := tx.Bucket(filenameReservations)
		if b != nil {
			s.filenameProgressMu.Lock()
			s.filenameProgress.Total = uint64(b.Stats().KeyN)
			s.filenameProgressMu.Unlock()
			if err := b.ForEach(func(k, raw []byte) error {
				if err := addFilenameReadCandidate(idx, k, raw); err != nil {
					return err
				}
				s.filenameProgressMu.Lock()
				s.filenameProgress.Scanned++
				progress := s.filenameProgress
				s.filenameProgressMu.Unlock()
				if progress.Scanned%10000 == 0 {
					log.Printf("filename read index: state=building scanned=%d total=%d", progress.Scanned, progress.Total)
				}
				return nil
			}); err != nil {
				return err
			}
		}
		return idx.Put(filenameReadIndexMarker, []byte{1})
	})
	s.filenameProgressMu.Lock()
	s.filenameProgress.FinishedAt = time.Now().UTC()
	if err != nil {
		s.filenameProgress.State = FilenameReadIndexRebuild
	} else {
		s.filenameProgress.State = FilenameReadIndexReady
	}
	progress := s.filenameProgress
	s.filenameProgressMu.Unlock()
	// Never log record values or errors that could include original paths.
	log.Printf("filename read index: state=%s scanned=%d total=%d elapsed=%s", progress.State, progress.Scanned, progress.Total, progress.FinishedAt.Sub(progress.StartedAt))
	return err
}

func filenameCandidateKey(rec FilenameRecord, id []byte) []byte {
	return append(filenameKey(rec.Origin, rec.OriginalPath), id...)
}

func decodeFilenameReadPrimary(id, raw []byte) (FilenameRecord, error) {
	var rec FilenameRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return rec, err
	}
	if !validFilenameOrigin(rec.Origin) || !validFilenamePath(rec.OriginalPath) || !validFilenamePath(rec.EncryptedPath) || !bytes.Equal(id, filenameKey(rec.Origin, rec.EncryptedPath)) {
		return rec, errors.New("invalid filename primary for read index")
	}
	return rec, nil
}

func addFilenameReadCandidate(idx *bolt.Bucket, id, raw []byte) error {
	rec, err := decodeFilenameReadPrimary(id, raw)
	if err != nil {
		return err
	}
	return idx.Put(filenameCandidateKey(rec, id), []byte{1})
}

// putFilenamePrimary maintains candidate membership even for generic Store
// mutation APIs. Completion retains its candidate; status comes from primary.
func putFilenamePrimary(tx *bolt.Tx, id, raw []byte) error {
	b := tx.Bucket(filenameReservations)
	idx := tx.Bucket(filenameReadIndex)
	if b == nil || idx == nil || !bytes.Equal(idx.Get(filenameReadIndexMarker), []byte{1}) {
		return ErrFilenameReadIndexNotReady
	}
	if old := b.Get(id); old != nil {
		rec, err := decodeFilenameReadPrimary(id, old)
		if err != nil {
			return err
		}
		if err := idx.Delete(filenameCandidateKey(rec, id)); err != nil {
			return err
		}
	}
	if raw == nil {
		return b.Delete(id)
	}
	if err := addFilenameReadCandidate(idx, id, raw); err != nil {
		return err
	}
	return b.Put(id, raw)
}

// FindFilenameReservationForRead is only a routing hint, not authorization.
// It performs one prefix seek, checks at most two candidate IDs, and point-loads
// primary only when uniqueness is proven. It NEVER scans primary records.
func (s *Store) FindFilenameReservationForRead(origin, original string) (FilenameRecord, bool, error) {
	if err := s.filenameReady(); err != nil {
		return FilenameRecord{}, false, err
	}
	if !validFilenameOrigin(origin) || !validFilenamePath(original) {
		return FilenameRecord{}, false, errors.New("invalid filename read lookup")
	}
	if s.FilenameReadIndexStatus().State != FilenameReadIndexReady {
		return FilenameRecord{}, false, ErrFilenameReadIndexNotReady
	}
	s.filenameReadMu.RLock()
	defer s.filenameReadMu.RUnlock()
	if s.FilenameReadIndexStatus().State != FilenameReadIndexReady {
		return FilenameRecord{}, false, ErrFilenameReadIndexNotReady
	}
	prefix := filenameKey(origin, original)
	cacheKey := string(prefix)
	s.filenameCacheMu.Lock()
	entry, cached := s.filenameReadCache[cacheKey]
	s.filenameCacheMu.Unlock()
	if cached {
		return entry.rec, entry.found, nil
	}
	var rec FilenameRecord
	found := false
	s.filenameReadTxns.Add(1)
	err := s.db.View(func(tx *bolt.Tx) error {
		idx := tx.Bucket(filenameReadIndex)
		if idx == nil || !bytes.Equal(idx.Get(filenameReadIndexMarker), []byte{1}) {
			return ErrFilenameReadIndexNotReady
		}
		c := idx.Cursor()
		k, _ := c.Seek(prefix)
		if !bytes.HasPrefix(k, prefix) {
			return nil
		}
		if len(k) != len(prefix)+64 {
			return ErrFilenameReadIndexNotReady
		}
		id := append([]byte(nil), k[len(prefix):]...)
		next, _ := c.Next()
		if bytes.HasPrefix(next, prefix) {
			return ErrFilenameReadAmbiguous
		}
		b := tx.Bucket(filenameReservations)
		if b == nil || b.Get(id) == nil {
			return ErrFilenameReadIndexNotReady
		}
		var err error
		rec, err = decodeFilenameReadPrimary(id, b.Get(id))
		if err != nil {
			return fmt.Errorf("%w: invalid primary", ErrFilenameReadIndexNotReady)
		}
		if rec.Origin != origin || rec.OriginalPath != original {
			return ErrFilenameReadIndexNotReady
		}
		found = true
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrFilenameReadIndexNotReady) {
			s.setFilenameReadState(FilenameReadIndexRebuild)
		}
		return FilenameRecord{}, false, err
	}
	s.filenameCacheMu.Lock()
	if s.filenameReadCache == nil || len(s.filenameReadCache) >= filenameReadCacheLimit {
		s.filenameReadCache = make(map[string]filenameReadCacheEntry)
	}
	s.filenameReadCache[cacheKey] = filenameReadCacheEntry{rec: rec, found: found}
	s.filenameCacheMu.Unlock()
	return rec, found, nil
}

// FilenameReadTxnCount counts actual read-index Bolt transactions, excluding
// cache hits, for deterministic transaction-budget tests and diagnostics.
func (s *Store) FilenameReadTxnCount() uint64 {
	if s == nil {
		return 0
	}
	return s.filenameReadTxns.Load()
}
