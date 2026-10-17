package storage

import (
	"encoding/json"
	"fmt"
	"github.com/alist-encrypt-go/internal/recovery"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	// Bucket names
	BucketUsers    = []byte("users")
	BucketPasswd   = []byte("passwd")
	BucketConfig   = []byte("config")
	BucketFileInfo = []byte("fileinfo")
	BucketFileSize = []byte("filesize")
	BucketDirSync  = []byte("dirsync")
	BucketStats    = []byte("stats")
)

// Store represents the BoltDB storage
type Store struct {
	db            *bolt.DB
	path          string
	closeOnce     sync.Once
	closeErr      error
	recoveryState *recovery.State
	// writeTxns counts completed write transactions. It exists so batch-write
	// paths (e.g. directory listings) can assert the transaction budget they
	// target rather than blindly trusting benchmarks.
	writeTxns          atomic.Uint64
	filenameReadMu     sync.RWMutex
	filenameCacheMu    sync.Mutex
	filenameReadCache  map[string]filenameReadCacheEntry
	filenameReadTxns   atomic.Uint64
	filenameProgressMu sync.RWMutex
	filenameProgress   FilenameReadIndexProgress
	filenameRebuildMu  sync.Mutex
}

// update runs fn inside a single BoltDB write transaction and counts it.
func (s *Store) update(fn func(*bolt.Tx) error) error {
	// Serialize cache publication with commits: no reader can publish a stale
	// positive/negative result after a primary mutation. Invalidating on all
	// writes also covers generic bucket APIs without an unbounded key registry.
	s.filenameReadMu.Lock()
	defer s.filenameReadMu.Unlock()
	s.writeTxns.Add(1)
	err := s.db.Update(fn)
	s.filenameCacheMu.Lock()
	s.filenameReadCache = nil
	s.filenameCacheMu.Unlock()
	return err
}

// WriteTxnCount returns the cumulative number of write transactions issued
// against this store. Exported for tests and observability.
func (s *Store) WriteTxnCount() uint64 {
	if s == nil || s.db == nil {
		return 0
	}
	return s.writeTxns.Load()
}

// BucketTx exposes scoped operations within a single BoltDB write transaction.
type BucketTx struct {
	b               *bolt.Bucket
	primaryFilename bool
}

// NewStore creates a new BoltDB store
func NewStore(dataDir string) (*Store, error) {
	return NewStoreWithRecovery(dataDir, recovery.Load(dataDir))
}

// NewStoreWithRecovery shares the immutable startup state with the server.
// It must not be used to install or remove a fence on a running instance.
func NewStoreWithRecovery(dataDir string, state *recovery.State) (*Store, error) {
	if state == nil {
		state = recovery.Load(dataDir)
	}
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	dbPath := filepath.Join(dataDir, "alist-encrypt.db")
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	err = db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(BucketConfig); b != nil {
			raw := b.Get([]byte(recovery.StickyKey))
			if b.Bucket([]byte(recovery.StickyKey)) != nil {
				raw = []byte("invalid nested recovery marker")
			}
			state = recovery.WithSticky(state, raw)
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	store := &Store{
		db:            db,
		path:          dbPath,
		recoveryState: state,
	}

	// Initialize buckets
	if err := store.initBuckets(); err != nil {
		db.Close()
		return nil, err
	}

	// Never trust a previous derived index: an older binary may have written
	// primary audit records since the last upgrade.
	if err := store.RebuildFilenameReadIndex(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to rebuild filename read index: %w", err)
	}
	return store, nil
}

func (s *Store) initBuckets() error {
	return s.update(func(tx *bolt.Tx) error {
		buckets := [][]byte{BucketUsers, BucketPasswd, BucketConfig, BucketFileInfo, BucketFileSize, BucketDirSync, BucketStats}
		for _, bucket := range buckets {
			if _, err := tx.CreateBucketIfNotExists(bucket); err != nil {
				return fmt.Errorf("failed to create bucket %s: %w", bucket, err)
			}
		}
		return nil
	})
}

// RecoveryState returns the immutable state after sticky database inspection.
func (s *Store) RecoveryState() *recovery.State { return s.recoveryState }

// Close closes the database
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.closeErr = s.db.Close()
	})
	return s.closeErr
}

// Get retrieves a value from a bucket
func (s *Store) Get(bucket []byte, key string) ([]byte, error) {
	var value []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if b == nil {
			return fmt.Errorf("bucket not found: %s", bucket)
		}
		raw := b.Get([]byte(key))
		if raw != nil {
			value = append([]byte(nil), raw...)
		}
		return nil
	})
	return value, err
}

// Set stores a value in a bucket
func (s *Store) Set(bucket []byte, key string, value []byte) error {
	return s.update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if b == nil {
			return fmt.Errorf("bucket not found: %s", bucket)
		}
		if string(bucket) == string(filenameReservations) {
			return putFilenamePrimary(tx, []byte(key), value)
		}
		return b.Put([]byte(key), value)
	})
}

// Delete removes a key from a bucket
func (s *Store) Delete(bucket []byte, key string) error {
	return s.update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if b == nil {
			return fmt.Errorf("bucket not found: %s", bucket)
		}
		if string(bucket) == string(filenameReservations) {
			return putFilenamePrimary(tx, []byte(key), nil)
		}
		return b.Delete([]byte(key))
	})
}

// UpdateBucket runs multiple operations against one bucket in a single write transaction.
func (s *Store) UpdateBucket(bucket []byte, fn func(*BucketTx) error) error {
	return s.update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if b == nil {
			return fmt.Errorf("bucket not found: %s", bucket)
		}
		return fn(&BucketTx{b: b, primaryFilename: string(bucket) == string(filenameReservations)})
	})
}

// GetJSON retrieves and unmarshals a JSON value within the transaction.
func (tx *BucketTx) GetJSON(key string, v interface{}) error {
	raw := tx.b.Get([]byte(key))
	if raw == nil {
		return nil
	}
	return json.Unmarshal(raw, v)
}

// SetJSON marshals and stores a JSON value within the transaction.
func (tx *BucketTx) SetJSON(key string, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if tx.primaryFilename {
		return putFilenamePrimary(tx.b.Tx(), []byte(key), data)
	}
	return tx.b.Put([]byte(key), data)
}

// Delete removes a key within the transaction.
func (tx *BucketTx) Delete(key string) error {
	if tx.primaryFilename {
		return putFilenamePrimary(tx.b.Tx(), []byte(key), nil)
	}
	return tx.b.Delete([]byte(key))
}

// GetAll retrieves all key-value pairs from a bucket
func (s *Store) GetAll(bucket []byte) (map[string][]byte, error) {
	result := make(map[string][]byte)
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if b == nil {
			return fmt.Errorf("bucket not found: %s", bucket)
		}
		return b.ForEach(func(k, v []byte) error {
			result[string(k)] = append([]byte(nil), v...)
			return nil
		})
	})
	return result, err
}

// GetJSON retrieves and unmarshals a JSON value
func (s *Store) GetJSON(bucket []byte, key string, v interface{}) error {
	data, err := s.Get(bucket, key)
	if err != nil {
		return err
	}
	if data == nil {
		return nil
	}
	return json.Unmarshal(data, v)
}

// SetJSON marshals and stores a JSON value
func (s *Store) SetJSON(bucket []byte, key string, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.Set(bucket, key, data)
}

// ListKeys returns all keys in a bucket
func (s *Store) ListKeys(bucket []byte) ([]string, error) {
	var keys []string
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if b == nil {
			return fmt.Errorf("bucket not found: %s", bucket)
		}
		return b.ForEach(func(k, v []byte) error {
			keys = append(keys, string(k))
			return nil
		})
	})
	return keys, err
}
