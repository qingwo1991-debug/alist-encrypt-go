package handler

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/alist-encrypt-go/internal/config"
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
	return fileInfoFromFileMetaRecord(record), true
}

// GetFileInfosByPaths resolves many display paths with a few IN (...) queries
// instead of one full table scan per path. Each hit carries the same field
// mapping as GetFileInfoByPath; paths without a qualifying row are absent.
func (w *MySQLFileMetaWriter) GetFileInfosByPaths(ctx context.Context, paths []string) map[string]*dao.FileInfo {
	if w == nil || w.store == nil || len(paths) == 0 {
		return nil
	}
	records, err := w.store.GetFileMetaByPaths(ctx, paths)
	if err != nil {
		return nil
	}
	infos := make(map[string]*dao.FileInfo, len(records))
	for p, record := range records {
		if record == nil {
			continue
		}
		infos[p] = fileInfoFromFileMetaRecord(record)
	}
	return infos
}

// fileInfoFromFileMetaRecord applies the FileInfo hydration shared by the
// single-path and batch readers.
func fileInfoFromFileMetaRecord(record *mysqlstore.FileMetaRecord) *dao.FileInfo {
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
	}
}

// StableFileMetaProviderHost returns the provider_host every new MySQL
// file_meta row is keyed on: the alist origin's host, falling back to the
// store's sentinel when no origin is configured. The size resolver and probe
// scheduler derive their key as ProviderKey(cfg.GetAlistURL(), path), i.e. the
// same host, so their key-hash lookups keep hitting the stable row.
func StableFileMetaProviderHost(cfg *config.Config) string {
	if cfg != nil {
		if parsed, err := url.Parse(cfg.GetAlistURL()); err == nil && parsed.Host != "" {
			return parsed.Host
		}
	}
	return mysqlstore.StableProviderHostSentinel
}

// PreserveFileMetaStoredRow adapts preserveV2FileMetaRecord to the store's
// flush-time merger hook. stored is the row currently in MySQL; incoming is
// the pending write, reconciled in place.
func PreserveFileMetaStoredRow(stored, incoming *mysqlstore.FileMetaRecord) {
	if stored == nil || incoming == nil {
		return
	}
	preserveV2FileMetaRecord(stored, incoming)
}

// fileMetaRecordFromInfo maps a DAO FileInfo to a file_meta row. The raw-URL
// host is recorded only for diagnostics: the store keys every row on the
// stable (alist-origin) host so a path occupies one row regardless of which
// CDN host served it. The URL itself is kept in raw_url.
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
