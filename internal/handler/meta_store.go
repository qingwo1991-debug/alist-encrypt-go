package handler

import (
	"context"
	"time"

	"github.com/alist-encrypt-go/internal/storage/mysqlstore"
)

type FileMeta struct {
	ProviderKey  string
	OriginalPath string
	Size         int64
	ETag         string
	ContentType  string
	StatusCode   int
	UpdatedAt    time.Time
	LastAccessed time.Time
}

type FileMetaStore interface {
	Get(ctx context.Context, providerKey, originalPath string) (FileMeta, bool, error)
	Upsert(ctx context.Context, meta FileMeta) error
	Cleanup(ctx context.Context, cutoff time.Time) error
}

// MySQLFileMetaWriter bridges dao.FileMetaStoreWriter to the MySQL file_meta table.
type MySQLFileMetaWriter struct {
	store *mysqlstore.Store
}

func NewMySQLFileMetaWriter(store *mysqlstore.Store) *MySQLFileMetaWriter {
	return &MySQLFileMetaWriter{store: store}
}

func (w *MySQLFileMetaWriter) UpsertFileMeta(path string, size int64, rawURL, sign string, upstreamFetchedAt time.Time) error {
	if w == nil || w.store == nil {
		return nil
	}
	return w.store.UpsertFileMeta(context.Background(), mysqlstore.FileMetaRecord{
		ProviderHost:      "",
		OriginalPath:      path,
		Size:              size,
		RawURL:            rawURL,
		Sign:              sign,
		LastAccessed:      time.Now(),
		UpstreamFetchedAt: upstreamFetchedAt,
		Active:            true,
	})
}
