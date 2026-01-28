package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	bolt "go.etcd.io/bbolt"
)

var (
	// Bucket names
	BucketUsers    = []byte("users")
	BucketPasswd   = []byte("passwd")
	BucketConfig   = []byte("config")
	BucketFileInfo = []byte("fileinfo")
)

// Store represents the BoltDB storage
type Store struct {
	db   *bolt.DB
	path string
}

// NewStore creates a new BoltDB store
func NewStore(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	dbPath := filepath.Join(dataDir, "alist-encrypt.db")
	db, err := bolt.Open(dbPath, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	store := &Store{
		db:   db,
		path: dbPath,
	}

	// Initialize buckets
	if err := store.initBuckets(); err != nil {
		db.Close()
		return nil, err
	}

	return store, nil
}

func (s *Store) initBuckets() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		buckets := [][]byte{BucketUsers, BucketPasswd, BucketConfig, BucketFileInfo}
		for _, bucket := range buckets {
			if _, err := tx.CreateBucketIfNotExists(bucket); err != nil {
				return fmt.Errorf("failed to create bucket %s: %w", bucket, err)
			}
		}
		return nil
	})
}

// Close closes the database
func (s *Store) Close() error {
	return s.db.Close()
}

// Get retrieves a value from a bucket
func (s *Store) Get(bucket []byte, key string) ([]byte, error) {
	var value []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if b == nil {
			return fmt.Errorf("bucket not found: %s", bucket)
		}
		value = b.Get([]byte(key))
		return nil
	})
	return value, err
}

// Set stores a value in a bucket
func (s *Store) Set(bucket []byte, key string, value []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if b == nil {
			return fmt.Errorf("bucket not found: %s", bucket)
		}
		return b.Put([]byte(key), value)
	})
}

// Delete removes a key from a bucket
func (s *Store) Delete(bucket []byte, key string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if b == nil {
			return fmt.Errorf("bucket not found: %s", bucket)
		}
		return b.Delete([]byte(key))
	})
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
			result[string(k)] = v
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
