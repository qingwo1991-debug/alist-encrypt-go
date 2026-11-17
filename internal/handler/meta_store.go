package handler

import (
	"context"
	"net/url"
	"strings"
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
	return w.store.UpsertFileMeta(context.Background(), fileMetaRecordFromInfo(info))
}

// GetFileInfoByPath hydrates a FileInfo from the freshest file_meta row that
// carries confirmed content metadata. Rows are keyed by provider host, which
// varies with the raw URL observed at write time, so the lookup is by display
// path only. Only content_version>0 rows qualify, which also guarantees the
// record describes a file (directories never carry content metadata).
func (w *MySQLFileMetaWriter) GetFileInfoByPath(ctx context.Context, path string) (*dao.FileInfo, bool) {
	if w == nil || w.store == nil || strings.TrimSpace(path) == "" {
		return nil, false
	}
	record, ok, err := w.store.GetFileMetaByPath(ctx, path)
	if err != nil || !ok || record == nil {
		return nil, false
	}
	return &dao.FileInfo{
		Path:              record.OriginalPath,
		EncryptedPath:     record.EncryptedPath,
		Name:              record.Name,
		Size:              record.Size,
		CiphertextSize:    record.CiphertextSize,
		ContentVersion:    record.ContentVersion,
		HeaderLen:         record.HeaderLen,
		NonceField:        append([]byte(nil), record.NonceField...),
		ChunkSize:         record.ChunkSize,
		KDFIterations:     record.KDFIterations,
		RawURL:            record.RawURL,
		RawURLAuthScope:   record.RawURLAuthScope,
		Sign:              record.Sign,
		UpstreamFetchedAt: record.UpstreamFetchedAt,
	}, true
}

func fileMetaRecordFromInfo(info *dao.FileInfo) mysqlstore.FileMetaRecord {
	providerHost := ""
	if parsed, err := url.Parse(info.RawURL); err == nil {
		providerHost = parsed.Host
	}
	return mysqlstore.FileMetaRecord{
		ProviderHost:      providerHost,
		OriginalPath:      info.Path,
		EncryptedPath:     info.EncryptedPath,
		Name:              info.Name,
		Size:              info.Size,
		CiphertextSize:    info.CiphertextSize,
		ContentVersion:    info.ContentVersion,
		HeaderLen:         info.HeaderLen,
		NonceField:        append([]byte(nil), info.NonceField...),
		ChunkSize:         info.ChunkSize,
		KDFIterations:     info.KDFIterations,
		RawURL:            info.RawURL,
		RawURLAuthScope:   info.RawURLAuthScope,
		Sign:              info.Sign,
		LastAccessed:      time.Now(),
		UpstreamFetchedAt: info.UpstreamFetchedAt,
		Active:            true,
	}
}
