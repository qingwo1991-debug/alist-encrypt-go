package handler

import (
	"context"
	"net/url"
	"time"

	"github.com/alist-encrypt-go/internal/dao"
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

func (w *MySQLFileMetaWriter) UpsertFileMeta(info *dao.FileInfo) error {
	if w == nil || w.store == nil {
		return nil
	}
	if info == nil {
		return nil
	}
	providerHost := ""
	if parsed, err := url.Parse(info.RawURL); err == nil {
		providerHost = parsed.Host
	}
	return w.store.UpsertFileMeta(context.Background(), mysqlstore.FileMetaRecord{
		ProviderHost:      providerHost,
		OriginalPath:      info.Path,
		EncryptedPath:     info.EncryptedPath,
		Name:              info.Name,
		Size:              info.Size,
		CiphertextSize:    info.CiphertextSize,
		ContentVersion:    info.ContentVersion,
		HeaderLen:         info.HeaderLen,
		NonceField:        append([]byte(nil), info.NonceField...),
		RawURL:            info.RawURL,
		Sign:              info.Sign,
		LastAccessed:      time.Now(),
		UpstreamFetchedAt: info.UpstreamFetchedAt,
		Active:            true,
	})
}
