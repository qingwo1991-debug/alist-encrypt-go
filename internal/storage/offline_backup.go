package storage

import (
	"context"
	"errors"
	bolt "go.etcd.io/bbolt"
	"time"
)

// CreateOfflineSnapshot never creates or migrates the source. The caller must
// hold exclusive service lifetime ownership, not merely a Bolt read lock.
func CreateOfflineSnapshot(ctx context.Context, source, dir, name string, o SnapshotOptions) (m SnapshotManifest, err error) {
	db, err := bolt.Open(source, 0600, &bolt.Options{ReadOnly: true, Timeout: 100 * time.Millisecond})
	if err != nil {
		return m, err
	}
	defer func() { err = errors.Join(err, db.Close()) }()
	return (&Store{db: db, path: source}).CreateSnapshot(ctx, dir, name, o)
}
