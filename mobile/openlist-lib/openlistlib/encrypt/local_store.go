package encrypt

import (
	"database/sql"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/OpenListTeam/OpenList/v4/openlistlib/internal"
	_ "github.com/mattn/go-sqlite3"
	log "github.com/sirupsen/logrus"
)

type StreamStrategy string

const (
	StreamStrategyRange   StreamStrategy = "range"
	StreamStrategyChunked StreamStrategy = "chunked"
	StreamStrategyFull    StreamStrategy = "full"
)

type storeRecordKind int

const (
	recordKindSize storeRecordKind = iota
	recordKindStrategy
)

type storeRecord struct {
	kind         storeRecordKind
	key          string
	providerHost string
	originalPath string
	networkType  string
	strategy     StreamStrategy
	size         int64
	accessedAt   time.Time
}

type localStore struct {
	db             *sql.DB
	mu             sync.Mutex
	buffer         []storeRecord
	flushThreshold int
	flushing       bool
	closed         bool
}

type LocalSizeRecord struct {
	Key          string `json:"key"`
	ProviderHost string `json:"provider_host"`
	OriginalPath string `json:"original_path"`
	EncryptedPath string `json:"encrypted_path,omitempty"`
	Name         string `json:"name,omitempty"`
	Size         int64  `json:"size"`
	CiphertextSize int64 `json:"ciphertext_size,omitempty"`
	ContentVersion int   `json:"content_version,omitempty"`
	HeaderLen    int64  `json:"header_len,omitempty"`
	NonceField   []byte `json:"nonce_field,omitempty"`
	RawURL       string `json:"raw_url,omitempty"`
	Sign         string `json:"sign,omitempty"`
	UpstreamFetchedAt int64 `json:"upstream_fetched_at,omitempty"`
	LastAccessed int64  `json:"last_accessed"`
	UpdatedAt    int64  `json:"updated_at"`
}

type LocalStrategyRecord struct {
	Key          string `json:"key"`
	NetworkType  string `json:"network_type"`
	Strategy     string `json:"strategy"`
	ProviderHost string `json:"provider_host"`
	OriginalPath string `json:"original_path"`
	LastAccessed int64  `json:"last_accessed"`
	UpdatedAt    int64  `json:"updated_at"`
}

type LocalExport struct {
	Sizes      []LocalSizeRecord     `json:"sizes"`
	Strategies []LocalStrategyRecord `json:"strategies"`
}

type LocalSyncStatusRecord struct {
	Name              string `json:"name"`
	LastSuccessAt     int64  `json:"last_success_at"`
	LastCycleImported int    `json:"last_cycle_imported"`
	TotalImported     int64  `json:"total_imported"`
	LastError         string `json:"last_error"`
	SyncMode          string `json:"sync_mode"`
	UpdatedAt         int64  `json:"updated_at"`
}

type LocalSyncCycleRecord struct {
	CycleAt      int64  `json:"cycle_at"`
	Imported     int    `json:"imported"`
	OK           bool   `json:"ok"`
	ErrorSummary string `json:"error_summary"`
}

type LocalProviderCatalogRecord struct {
	ProviderKey string `json:"provider_key"`
	DisplayName string `json:"display_name"`
	SourceMask  int    `json:"source_mask"`
	FirstSeenAt int64  `json:"first_seen_at"`
	LastSeenAt  int64  `json:"last_seen_at"`
	UpdatedAt   int64  `json:"updated_at"`
}

const defaultFlushThreshold = 20

func newLocalStore(baseDir string) (*localStore, error) {
	if baseDir == "" {
		return nil, nil
	}
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, err
	}
	dbPath := filepath.Join(baseDir, "local_media.db")
	// Run backup asynchronously to avoid blocking service startup on large DB copies.
	go func() {
		if err := backupLocalStoreDB(dbPath); err != nil {
			log.Warnf("[%s] local store backup failed: %v", internal.TagCache, err)
		}
	}()
	dsn := dbPath + "?_journal=WAL&_busy_timeout=5000&_foreign_keys=ON"
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := db.Exec("PRAGMA synchronous=NORMAL"); err != nil {
		_ = db.Close()
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(30 * time.Minute)
	db.SetConnMaxIdleTime(10 * time.Minute)
	if err := initLocalSchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &localStore{
		db:             db,
		flushThreshold: defaultFlushThreshold,
	}, nil
}

func backupLocalStoreDB(dbPath string) error {
	info, err := os.Stat(dbPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Size() <= 0 {
		return nil
	}
	dir := filepath.Dir(dbPath)
	base := filepath.Base(dbPath)
	backupPath := filepath.Join(dir, base+".bak-"+time.Now().Format("20060102150405"))

	src, err := os.Open(dbPath)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.Create(backupPath)
	if err != nil {
		return err
	}
	defer dst.Close()
	if _, err := io.Copy(dst, src); err != nil {
		return err
	}
	// Close dst before cleanup to avoid file lock issues on Windows
	dst.Close()
	src.Close()

	// Clean up old backup files, keeping only the 2 most recent.
	cleanupOldBackups(dir, base, 2)
	return nil
}

// cleanupOldBackups removes old .bak-* backup files, keeping only the newest `keep` files.
func cleanupOldBackups(dir, baseName string, keep int) {
	pattern := filepath.Join(dir, baseName+".bak-*")
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) <= keep {
		return
	}
	// Sort by name descending (timestamp format ensures lexicographic = chronological order).
	for i := 0; i < len(matches)-1; i++ {
		for j := i + 1; j < len(matches); j++ {
			if matches[i] < matches[j] {
				matches[i], matches[j] = matches[j], matches[i]
			}
		}
	}
	// Remove all but the newest `keep` files.
	for _, old := range matches[keep:] {
		if err := os.Remove(old); err != nil {
			log.Warnf("[%s] failed to remove old backup %s: %v", internal.TagCache, old, err)
		}
	}
}

func initLocalSchema(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS local_media_size (
            key TEXT PRIMARY KEY,
            provider_host TEXT NOT NULL,
            original_path TEXT NOT NULL,
            encrypted_path TEXT NOT NULL DEFAULT '',
            name TEXT NOT NULL DEFAULT '',
            size INTEGER NOT NULL,
            ciphertext_size INTEGER NOT NULL DEFAULT 0,
            content_version INTEGER NOT NULL DEFAULT 0,
            header_len INTEGER NOT NULL DEFAULT 0,
            nonce_field BLOB NULL,
            raw_url TEXT NOT NULL DEFAULT '',
            sign TEXT NOT NULL DEFAULT '',
            upstream_fetched_at INTEGER NOT NULL DEFAULT 0,
            last_accessed INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );`,
		`CREATE INDEX IF NOT EXISTS idx_local_media_size_accessed ON local_media_size(last_accessed);`,
		`CREATE TABLE IF NOT EXISTS local_media_strategy (
            key TEXT NOT NULL,
            network_type TEXT NOT NULL,
            strategy TEXT NOT NULL,
            provider_host TEXT NOT NULL,
            original_path TEXT NOT NULL,
            last_accessed INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            PRIMARY KEY (key, network_type)
        );`,
		`CREATE INDEX IF NOT EXISTS idx_local_media_strategy_accessed ON local_media_strategy(last_accessed);`,
		`CREATE TABLE IF NOT EXISTS local_sync_checkpoint (
	            name TEXT PRIMARY KEY,
	            since INTEGER NOT NULL,
	            cursor TEXT NOT NULL DEFAULT '',
	            updated_at INTEGER NOT NULL
	        );`,
		`CREATE TABLE IF NOT EXISTS local_range_compat (
	            key TEXT PRIMARY KEY,
	            blocked_until INTEGER NOT NULL DEFAULT 0,
	            failures INTEGER NOT NULL DEFAULT 0,
	            updated_at INTEGER NOT NULL
	        );`,
		`CREATE INDEX IF NOT EXISTS idx_local_range_compat_blocked_until ON local_range_compat(blocked_until);`,
		`CREATE TABLE IF NOT EXISTS local_range_probe_target (
	            key TEXT PRIMARY KEY,
	            sample_url TEXT NOT NULL,
	            source_path TEXT NOT NULL,
	            next_probe_at INTEGER NOT NULL DEFAULT 0,
	            updated_at INTEGER NOT NULL
	        );`,
		`CREATE INDEX IF NOT EXISTS idx_local_range_probe_next_probe ON local_range_probe_target(next_probe_at);`,
		`CREATE TABLE IF NOT EXISTS local_sync_status (
	            name TEXT PRIMARY KEY,
	            last_success_at INTEGER NOT NULL DEFAULT 0,
	            last_cycle_imported INTEGER NOT NULL DEFAULT 0,
	            total_imported INTEGER NOT NULL DEFAULT 0,
	            last_error TEXT NOT NULL DEFAULT '',
	            sync_mode TEXT NOT NULL DEFAULT '',
	            updated_at INTEGER NOT NULL
	        );`,
		`CREATE TABLE IF NOT EXISTS local_sync_cycle (
	            id INTEGER PRIMARY KEY AUTOINCREMENT,
	            name TEXT NOT NULL,
	            cycle_at INTEGER NOT NULL,
	            imported INTEGER NOT NULL DEFAULT 0,
	            ok INTEGER NOT NULL DEFAULT 0,
	            error_summary TEXT NOT NULL DEFAULT '',
	            updated_at INTEGER NOT NULL
	        );`,
		`CREATE INDEX IF NOT EXISTS idx_local_sync_cycle_name_time ON local_sync_cycle(name, cycle_at DESC);`,
		`CREATE TABLE IF NOT EXISTS local_provider_catalog (
	            provider_key TEXT PRIMARY KEY,
	            display_name TEXT NOT NULL DEFAULT '',
	            source_mask INTEGER NOT NULL DEFAULT 0,
	            first_seen_at INTEGER NOT NULL DEFAULT 0,
	            last_seen_at INTEGER NOT NULL DEFAULT 0,
	            updated_at INTEGER NOT NULL
	        );`,
		`CREATE INDEX IF NOT EXISTS idx_local_provider_catalog_updated_at ON local_provider_catalog(updated_at DESC);`,
		`CREATE TABLE IF NOT EXISTS local_db_meta (
	            key TEXT PRIMARY KEY,
	            value TEXT NOT NULL,
	            updated_at INTEGER NOT NULL
	        );`,
		`INSERT INTO local_db_meta (key, value, updated_at)
	        VALUES ('schema_version', '4', strftime('%s','now'))
	        ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at;`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	return migrateLocalSchema(db)
}

func migrateLocalSchema(db *sql.DB) error {
	migrations := []string{
		`ALTER TABLE local_media_size ADD COLUMN encrypted_path TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE local_media_size ADD COLUMN name TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE local_media_size ADD COLUMN ciphertext_size INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE local_media_size ADD COLUMN content_version INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE local_media_size ADD COLUMN header_len INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE local_media_size ADD COLUMN nonce_field BLOB NULL`,
		`ALTER TABLE local_media_size ADD COLUMN raw_url TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE local_media_size ADD COLUMN sign TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE local_media_size ADD COLUMN upstream_fetched_at INTEGER NOT NULL DEFAULT 0`,
	}
	for _, stmt := range migrations {
		if _, err := db.Exec(stmt); err != nil {
			if strings.Contains(err.Error(), "duplicate column name") {
				continue
			}
			return err
		}
	}
	return nil
}

func (s *localStore) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	_ = s.Flush(true)
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

func (s *localStore) Cleanup(sizeOlderThan, strategyOlderThan time.Duration) error {
	if s == nil || s.db == nil {
		return nil
	}
	if sizeOlderThan <= 0 {
		sizeOlderThan = time.Duration(defaultLocalSizeRetentionDays) * 24 * time.Hour
	}
	if strategyOlderThan <= 0 {
		strategyOlderThan = time.Duration(defaultLocalStrategyRetentionDays) * 24 * time.Hour
	}
	sizeCutoff := time.Now().Add(-sizeOlderThan).Unix()
	if _, err := s.db.Exec("DELETE FROM local_media_size WHERE last_accessed < ?", sizeCutoff); err != nil {
		return err
	}
	strategyCutoff := time.Now().Add(-strategyOlderThan).Unix()
	if _, err := s.db.Exec("DELETE FROM local_media_strategy WHERE last_accessed < ?", strategyCutoff); err != nil {
		return err
	}
	if _, err := s.db.Exec("DELETE FROM local_range_compat WHERE blocked_until > 0 AND blocked_until < ?", time.Now().Unix()); err != nil {
		return err
	}
	return nil
}

func (s *localStore) GetSize(key string) (int64, bool) {
	if s == nil || s.db == nil || key == "" {
		return 0, false
	}
	row := s.db.QueryRow("SELECT size FROM local_media_size WHERE key = ?", key)
	var size int64
	if err := row.Scan(&size); err != nil {
		return 0, false
	}
	if size <= 0 {
		return 0, false
	}
	return size, true
}

func (s *localStore) GetFileMeta(key string) (*LocalSizeRecord, bool) {
	if s == nil || s.db == nil || key == "" {
		return nil, false
	}
	row := s.db.QueryRow(`SELECT provider_host, original_path, encrypted_path, name, size, ciphertext_size, content_version, header_len, nonce_field, raw_url, sign, upstream_fetched_at, last_accessed, updated_at
		FROM local_media_size WHERE key = ?`, key)
	var rec LocalSizeRecord
	rec.Key = key
	if err := row.Scan(
		&rec.ProviderHost,
		&rec.OriginalPath,
		&rec.EncryptedPath,
		&rec.Name,
		&rec.Size,
		&rec.CiphertextSize,
		&rec.ContentVersion,
		&rec.HeaderLen,
		&rec.NonceField,
		&rec.RawURL,
		&rec.Sign,
		&rec.UpstreamFetchedAt,
		&rec.LastAccessed,
		&rec.UpdatedAt,
	); err != nil {
		return nil, false
	}
	return &rec, true
}

func (s *localStore) GetStrategy(key, networkType string) (StreamStrategy, bool) {
	if s == nil || s.db == nil || key == "" || networkType == "" {
		return "", false
	}
	for _, candidate := range []string{strings.ToLower(networkType), "any"} {
		row := s.db.QueryRow("SELECT strategy FROM local_media_strategy WHERE key = ? AND network_type = ?", key, candidate)
		var strategy string
		if err := row.Scan(&strategy); err != nil {
			continue
		}
		if strategy != "" {
			return StreamStrategy(strategy), true
		}
	}
	return "", false
}

func (s *localStore) AddSize(key, providerHost, originalPath string, size int64, accessedAt time.Time) {
	if s == nil || key == "" || size <= 0 || providerHost == "" || originalPath == "" {
		return
	}
	if GetNetworkState() == NetworkStateOffline {
		return
	}
	s.enqueue(storeRecord{
		kind:         recordKindSize,
		key:          key,
		providerHost: providerHost,
		originalPath: originalPath,
		size:         size,
		accessedAt:   accessedAt,
	})
}

func (s *localStore) AddStrategy(key, providerHost, originalPath, networkType string, strategy StreamStrategy, accessedAt time.Time) {
	if s == nil || key == "" || providerHost == "" || originalPath == "" || networkType == "" || strategy == "" {
		return
	}
	if GetNetworkState() == NetworkStateOffline {
		return
	}
	s.enqueue(storeRecord{
		kind:         recordKindStrategy,
		key:          key,
		providerHost: providerHost,
		originalPath: originalPath,
		networkType:  strings.ToLower(networkType),
		strategy:     strategy,
		accessedAt:   accessedAt,
	})
}

func (s *localStore) Flush(force bool) error {
	if s == nil || s.db == nil {
		return nil
	}
	if GetNetworkState() == NetworkStateOffline {
		return nil
	}
	s.mu.Lock()
	if len(s.buffer) == 0 {
		s.mu.Unlock()
		return nil
	}
	batch := s.buffer
	s.buffer = nil
	s.flushing = true
	s.mu.Unlock()

	err := s.flushBatch(batch)

	s.mu.Lock()
	s.flushing = false
	s.mu.Unlock()

	return err
}

func (s *localStore) enqueue(record storeRecord) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.buffer = append(s.buffer, record)
	if len(s.buffer) < s.flushThreshold || s.flushing {
		s.mu.Unlock()
		return
	}
	batch := s.buffer
	s.buffer = nil
	s.flushing = true
	s.mu.Unlock()

	go s.flushBatchAsync(batch)
}

func (s *localStore) flushBatchAsync(batch []storeRecord) {
	if err := s.flushBatch(batch); err != nil {
		// 异步刷盘失败不能丢数据：回灌到队列头并延迟重试
		log.Warnf("[%s] local_store async flush failed, requeue batch size=%d: %v", internal.TagCache, len(batch), err)
		s.mu.Lock()
		if !s.closed {
			s.buffer = append(batch, s.buffer...)
		}
		s.flushing = false
		s.mu.Unlock()
		time.Sleep(500 * time.Millisecond)
		return
	}

	s.mu.Lock()
	s.flushing = false
	if len(s.buffer) < s.flushThreshold {
		s.mu.Unlock()
		return
	}
	next := s.buffer
	s.buffer = nil
	s.flushing = true
	s.mu.Unlock()

	go s.flushBatchAsync(next)
}

func (s *localStore) flushBatch(batch []storeRecord) error {
	if s.db == nil {
		return nil
	}
	if len(batch) == 0 {
		return nil
	}
	if GetNetworkState() == NetworkStateOffline {
		s.mu.Lock()
		if !s.closed {
			s.buffer = append(batch, s.buffer...)
		}
		s.mu.Unlock()
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	insertSize, err := tx.Prepare(`INSERT INTO local_media_size
        (key, provider_host, original_path, encrypted_path, name, size, ciphertext_size, content_version, header_len, nonce_field, raw_url, sign, upstream_fetched_at, last_accessed, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET
        provider_host=excluded.provider_host,
        original_path=excluded.original_path,
        encrypted_path=excluded.encrypted_path,
        name=excluded.name,
        size=excluded.size,
        ciphertext_size=excluded.ciphertext_size,
        content_version=excluded.content_version,
        header_len=excluded.header_len,
        nonce_field=excluded.nonce_field,
        raw_url=excluded.raw_url,
        sign=excluded.sign,
        upstream_fetched_at=excluded.upstream_fetched_at,
        last_accessed=excluded.last_accessed,
        updated_at=excluded.updated_at`)
	if err != nil {
		return err
	}
	defer insertSize.Close()

	insertStrategy, err := tx.Prepare(`INSERT INTO local_media_strategy
        (key, network_type, strategy, provider_host, original_path, last_accessed, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(key, network_type) DO UPDATE SET
        strategy=excluded.strategy,
        provider_host=excluded.provider_host,
        original_path=excluded.original_path,
        last_accessed=excluded.last_accessed,
        updated_at=excluded.updated_at`)
	if err != nil {
		return err
	}
	defer insertStrategy.Close()

	for _, record := range batch {
		ts := record.accessedAt.Unix()
		switch record.kind {
		case recordKindSize:
			if _, err := insertSize.Exec(record.key, record.providerHost, record.originalPath, "", "", record.size, 0, 0, 0, nil, "", "", 0, ts, ts); err != nil {
				return err
			}
		case recordKindStrategy:
			if _, err := insertStrategy.Exec(record.key, record.networkType, record.strategy, record.providerHost, record.originalPath, ts, ts); err != nil {
				return err
			}
		}
	}

	return tx.Commit()
}

func (s *localStore) GetSnapshot(key string) (*LocalSizeRecord, []LocalStrategyRecord, error) {
	if s == nil || s.db == nil || key == "" {
		return nil, nil, nil
	}
	row := s.db.QueryRow("SELECT provider_host, original_path, encrypted_path, name, size, ciphertext_size, content_version, header_len, nonce_field, raw_url, sign, upstream_fetched_at, last_accessed, updated_at FROM local_media_size WHERE key = ?", key)
	var sizeRec LocalSizeRecord
	sizeRec.Key = key
	if err := row.Scan(&sizeRec.ProviderHost, &sizeRec.OriginalPath, &sizeRec.EncryptedPath, &sizeRec.Name, &sizeRec.Size, &sizeRec.CiphertextSize, &sizeRec.ContentVersion, &sizeRec.HeaderLen, &sizeRec.NonceField, &sizeRec.RawURL, &sizeRec.Sign, &sizeRec.UpstreamFetchedAt, &sizeRec.LastAccessed, &sizeRec.UpdatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil, nil
		}
		return nil, nil, err
	}

	rows, err := s.db.Query("SELECT network_type, strategy, provider_host, original_path, last_accessed, updated_at FROM local_media_strategy WHERE key = ?", key)
	if err != nil {
		return &sizeRec, nil, err
	}
	defer rows.Close()

	strategies := make([]LocalStrategyRecord, 0)
	for rows.Next() {
		var rec LocalStrategyRecord
		rec.Key = key
		if err := rows.Scan(&rec.NetworkType, &rec.Strategy, &rec.ProviderHost, &rec.OriginalPath, &rec.LastAccessed, &rec.UpdatedAt); err != nil {
			return &sizeRec, strategies, err
		}
		strategies = append(strategies, rec)
	}
	if err := rows.Err(); err != nil {
		return &sizeRec, strategies, err
	}
	return &sizeRec, strategies, nil
}

func (s *localStore) ExportAll() (*LocalExport, error) {
	if s == nil || s.db == nil {
		return &LocalExport{}, nil
	}
	data := &LocalExport{}

	rows, err := s.db.Query("SELECT key, provider_host, original_path, encrypted_path, name, size, ciphertext_size, content_version, header_len, nonce_field, raw_url, sign, upstream_fetched_at, last_accessed, updated_at FROM local_media_size")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var rec LocalSizeRecord
		if err := rows.Scan(&rec.Key, &rec.ProviderHost, &rec.OriginalPath, &rec.EncryptedPath, &rec.Name, &rec.Size, &rec.CiphertextSize, &rec.ContentVersion, &rec.HeaderLen, &rec.NonceField, &rec.RawURL, &rec.Sign, &rec.UpstreamFetchedAt, &rec.LastAccessed, &rec.UpdatedAt); err != nil {
			_ = rows.Close()
			return nil, err
		}
		data.Sizes = append(data.Sizes, rec)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	_ = rows.Close()

	rows, err = s.db.Query("SELECT key, network_type, strategy, provider_host, original_path, last_accessed, updated_at FROM local_media_strategy")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var rec LocalStrategyRecord
		if err := rows.Scan(&rec.Key, &rec.NetworkType, &rec.Strategy, &rec.ProviderHost, &rec.OriginalPath, &rec.LastAccessed, &rec.UpdatedAt); err != nil {
			_ = rows.Close()
			return nil, err
		}
		data.Strategies = append(data.Strategies, rec)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	_ = rows.Close()

	return data, nil
}

func (s *localStore) Import(data *LocalExport) error {
	if s == nil || s.db == nil || data == nil {
		return nil
	}
	if GetNetworkState() == NetworkStateOffline {
		return errors.New("network offline: import blocked")
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	insertSize, err := tx.Prepare(`INSERT INTO local_media_size
        (key, provider_host, original_path, encrypted_path, name, size, ciphertext_size, content_version, header_len, nonce_field, raw_url, sign, upstream_fetched_at, last_accessed, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET
        provider_host=excluded.provider_host,
        original_path=excluded.original_path,
        encrypted_path=excluded.encrypted_path,
        name=excluded.name,
        size=excluded.size,
        ciphertext_size=excluded.ciphertext_size,
        content_version=excluded.content_version,
        header_len=excluded.header_len,
        nonce_field=excluded.nonce_field,
        raw_url=excluded.raw_url,
        sign=excluded.sign,
        upstream_fetched_at=excluded.upstream_fetched_at,
        last_accessed=excluded.last_accessed,
        updated_at=excluded.updated_at`)
	if err != nil {
		return err
	}
	defer insertSize.Close()

	insertStrategy, err := tx.Prepare(`INSERT INTO local_media_strategy
        (key, network_type, strategy, provider_host, original_path, last_accessed, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(key, network_type) DO UPDATE SET
        strategy=excluded.strategy,
        provider_host=excluded.provider_host,
        original_path=excluded.original_path,
        last_accessed=excluded.last_accessed,
        updated_at=excluded.updated_at`)
	if err != nil {
		return err
	}
	defer insertStrategy.Close()

	now := time.Now().Unix()
	for _, rec := range data.Sizes {
		key := rec.Key
		if key == "" && rec.ProviderHost != "" && rec.OriginalPath != "" {
			key = buildLocalKey(rec.ProviderHost, rec.OriginalPath)
		}
		if key == "" || rec.ProviderHost == "" || rec.OriginalPath == "" || rec.Size <= 0 {
			continue
		}
		lastAccessed := rec.LastAccessed
		updatedAt := rec.UpdatedAt
		if lastAccessed <= 0 {
			lastAccessed = now
		}
		if updatedAt <= 0 {
			updatedAt = now
		}
		if _, err := insertSize.Exec(key, rec.ProviderHost, rec.OriginalPath, rec.EncryptedPath, rec.Name, rec.Size, rec.CiphertextSize, rec.ContentVersion, rec.HeaderLen, rec.NonceField, rec.RawURL, rec.Sign, rec.UpstreamFetchedAt, lastAccessed, updatedAt); err != nil {
			return err
		}
	}

	for _, rec := range data.Strategies {
		key := rec.Key
		if key == "" && rec.ProviderHost != "" && rec.OriginalPath != "" {
			key = buildLocalKey(rec.ProviderHost, rec.OriginalPath)
		}
		if key == "" || rec.ProviderHost == "" || rec.OriginalPath == "" || rec.Strategy == "" || rec.NetworkType == "" {
			continue
		}
		lastAccessed := rec.LastAccessed
		updatedAt := rec.UpdatedAt
		if lastAccessed <= 0 {
			lastAccessed = now
		}
		if updatedAt <= 0 {
			updatedAt = now
		}
		if _, err := insertStrategy.Exec(key, strings.ToLower(rec.NetworkType), rec.Strategy, rec.ProviderHost, rec.OriginalPath, lastAccessed, updatedAt); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *localStore) LoadRangeCompat(now time.Time) (map[string]time.Time, error) {
	if s == nil || s.db == nil {
		return map[string]time.Time{}, nil
	}
	ts := now.Unix()
	rows, err := s.db.Query("SELECT key, blocked_until FROM local_range_compat WHERE blocked_until > ?", ts)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]time.Time)
	for rows.Next() {
		var key string
		var blockedUntil int64
		if err := rows.Scan(&key, &blockedUntil); err != nil {
			return nil, err
		}
		if key == "" || blockedUntil <= ts {
			continue
		}
		out[key] = time.Unix(blockedUntil, 0)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *localStore) UpsertRangeCompat(key string, blockedUntil time.Time, failures int) error {
	if s == nil || s.db == nil || strings.TrimSpace(key) == "" {
		return nil
	}
	if failures < 0 {
		failures = 0
	}
	blockedTS := blockedUntil.Unix()
	if blockedUntil.IsZero() {
		blockedTS = 0
	}
	_, err := s.db.Exec(`INSERT INTO local_range_compat (key, blocked_until, failures, updated_at)
	        VALUES (?, ?, ?, ?)
	        ON CONFLICT(key) DO UPDATE SET
	        blocked_until=excluded.blocked_until,
	        failures=excluded.failures,
	        updated_at=excluded.updated_at`, key, blockedTS, failures, time.Now().Unix())
	return err
}

func (s *localStore) DeleteRangeCompat(key string) error {
	if s == nil || s.db == nil || strings.TrimSpace(key) == "" {
		return nil
	}
	_, err := s.db.Exec("DELETE FROM local_range_compat WHERE key = ?", key)
	return err
}

func (s *localStore) LoadRangeProbeTargets() (map[string]rangeProbeTarget, error) {
	if s == nil || s.db == nil {
		return map[string]rangeProbeTarget{}, nil
	}
	rows, err := s.db.Query("SELECT key, sample_url, source_path, next_probe_at FROM local_range_probe_target")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]rangeProbeTarget)
	for rows.Next() {
		var key string
		var sampleURL string
		var sourcePath string
		var nextProbeAt int64
		if err := rows.Scan(&key, &sampleURL, &sourcePath, &nextProbeAt); err != nil {
			return nil, err
		}
		if strings.TrimSpace(key) == "" || strings.TrimSpace(sampleURL) == "" {
			continue
		}
		target := rangeProbeTarget{
			Key:        key,
			URL:        sampleURL,
			SourcePath: sourcePath,
		}
		if nextProbeAt > 0 {
			target.NextProbeAt = time.Unix(nextProbeAt, 0)
		}
		out[key] = target
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *localStore) UpsertRangeProbeTarget(target rangeProbeTarget) error {
	if s == nil || s.db == nil {
		return nil
	}
	key := strings.TrimSpace(target.Key)
	sampleURL := strings.TrimSpace(target.URL)
	if key == "" || sampleURL == "" {
		return nil
	}
	nextProbeAt := target.NextProbeAt.Unix()
	if target.NextProbeAt.IsZero() {
		nextProbeAt = 0
	}
	_, err := s.db.Exec(`INSERT INTO local_range_probe_target (key, sample_url, source_path, next_probe_at, updated_at)
	        VALUES (?, ?, ?, ?, ?)
	        ON CONFLICT(key) DO UPDATE SET
	        sample_url=excluded.sample_url,
	        source_path=excluded.source_path,
	        next_probe_at=excluded.next_probe_at,
	        updated_at=excluded.updated_at`, key, sampleURL, target.SourcePath, nextProbeAt, time.Now().Unix())
	return err
}

func (s *localStore) DeleteRangeProbeTarget(key string) error {
	if s == nil || s.db == nil || strings.TrimSpace(key) == "" {
		return nil
	}
	_, err := s.db.Exec("DELETE FROM local_range_probe_target WHERE key = ?", key)
	return err
}

func (s *localStore) Counts() (int, int, error) {
	if s == nil || s.db == nil {
		return 0, 0, nil
	}
	row := s.db.QueryRow("SELECT COUNT(1) FROM local_media_size")
	var sizeCount int
	if err := row.Scan(&sizeCount); err != nil {
		return 0, 0, err
	}
	row = s.db.QueryRow("SELECT COUNT(1) FROM local_media_strategy")
	var strategyCount int
	if err := row.Scan(&strategyCount); err != nil {
		return sizeCount, 0, err
	}
	return sizeCount, strategyCount, nil
}

func (s *localStore) CountRangeCompat() (int, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	row := s.db.QueryRow("SELECT COUNT(1) FROM local_range_compat")
	var count int
	if err := row.Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (s *localStore) CountRangeProbeTargets() (int, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	row := s.db.QueryRow("SELECT COUNT(1) FROM local_range_probe_target")
	var count int
	if err := row.Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (s *localStore) CountsExtended() (int, int, int, int, error) {
	sizeCount, strategyCount, err := s.Counts()
	if err != nil {
		return 0, 0, 0, 0, err
	}
	rangeCompatCount, err := s.CountRangeCompat()
	if err != nil {
		return sizeCount, strategyCount, 0, 0, err
	}
	rangeProbeCount, err := s.CountRangeProbeTargets()
	if err != nil {
		return sizeCount, strategyCount, rangeCompatCount, 0, err
	}
	return sizeCount, strategyCount, rangeCompatCount, rangeProbeCount, nil
}

func (s *localStore) GetSyncCheckpoint(name string) (int64, string, error) {
	if s == nil || s.db == nil || name == "" {
		return 0, "", nil
	}
	row := s.db.QueryRow("SELECT since, cursor FROM local_sync_checkpoint WHERE name = ?", name)
	var since int64
	var cursor string
	if err := row.Scan(&since, &cursor); err != nil {
		if err == sql.ErrNoRows {
			return 0, "", nil
		}
		return 0, "", err
	}
	return since, cursor, nil
}

func (s *localStore) SaveSyncCheckpoint(name string, since int64, cursor string) error {
	if s == nil || s.db == nil || name == "" {
		return nil
	}
	if since < 0 {
		since = 0
	}
	_, err := s.db.Exec(`INSERT INTO local_sync_checkpoint (name, since, cursor, updated_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(name) DO UPDATE SET
        since=excluded.since,
        cursor=excluded.cursor,
        updated_at=excluded.updated_at`, name, since, cursor, time.Now().Unix())
	return err
}

func (s *localStore) GetSyncStatus(name string) (*LocalSyncStatusRecord, error) {
	if s == nil || s.db == nil || strings.TrimSpace(name) == "" {
		return nil, nil
	}
	row := s.db.QueryRow(`SELECT name, last_success_at, last_cycle_imported, total_imported, last_error, sync_mode, updated_at
        FROM local_sync_status WHERE name = ?`, name)
	rec := &LocalSyncStatusRecord{}
	if err := row.Scan(&rec.Name, &rec.LastSuccessAt, &rec.LastCycleImported, &rec.TotalImported, &rec.LastError, &rec.SyncMode, &rec.UpdatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return rec, nil
}

func (s *localStore) UpsertSyncStatus(status LocalSyncStatusRecord) error {
	if s == nil || s.db == nil || strings.TrimSpace(status.Name) == "" {
		return nil
	}
	if status.LastCycleImported < 0 {
		status.LastCycleImported = 0
	}
	if status.TotalImported < 0 {
		status.TotalImported = 0
	}
	now := time.Now().Unix()
	updatedAt := status.UpdatedAt
	if updatedAt <= 0 {
		updatedAt = now
	}
	_, err := s.db.Exec(`INSERT INTO local_sync_status
        (name, last_success_at, last_cycle_imported, total_imported, last_error, sync_mode, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(name) DO UPDATE SET
        last_success_at=excluded.last_success_at,
        last_cycle_imported=excluded.last_cycle_imported,
        total_imported=excluded.total_imported,
        last_error=excluded.last_error,
        sync_mode=excluded.sync_mode,
        updated_at=excluded.updated_at`,
		status.Name, status.LastSuccessAt, status.LastCycleImported, status.TotalImported, status.LastError, status.SyncMode, updatedAt)
	return err
}

func (s *localStore) AppendSyncCycle(name string, cycle LocalSyncCycleRecord, maxRows int) error {
	if s == nil || s.db == nil || strings.TrimSpace(name) == "" {
		return nil
	}
	if maxRows <= 0 {
		maxRows = 200
	}
	if cycle.Imported < 0 {
		cycle.Imported = 0
	}
	cycleAt := cycle.CycleAt
	if cycleAt <= 0 {
		cycleAt = time.Now().Unix()
	}
	okInt := 0
	if cycle.OK {
		okInt = 1
	}
	if _, err := s.db.Exec(`INSERT INTO local_sync_cycle (name, cycle_at, imported, ok, error_summary, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)`, name, cycleAt, cycle.Imported, okInt, cycle.ErrorSummary, time.Now().Unix()); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM local_sync_cycle
        WHERE name = ? AND id NOT IN (
            SELECT id FROM local_sync_cycle WHERE name = ? ORDER BY cycle_at DESC, id DESC LIMIT ?
        )`, name, name, maxRows)
	return err
}

func (s *localStore) ListRecentSyncCycles(name string, limit int) ([]LocalSyncCycleRecord, error) {
	if s == nil || s.db == nil || strings.TrimSpace(name) == "" {
		return []LocalSyncCycleRecord{}, nil
	}
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.db.Query(`SELECT cycle_at, imported, ok, error_summary
        FROM local_sync_cycle WHERE name = ? ORDER BY cycle_at DESC, id DESC LIMIT ?`, name, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]LocalSyncCycleRecord, 0, limit)
	for rows.Next() {
		var rec LocalSyncCycleRecord
		var okInt int
		if err := rows.Scan(&rec.CycleAt, &rec.Imported, &okInt, &rec.ErrorSummary); err != nil {
			return nil, err
		}
		rec.OK = okInt == 1
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *localStore) ListProviderCatalog() ([]LocalProviderCatalogRecord, error) {
	if s == nil || s.db == nil {
		return []LocalProviderCatalogRecord{}, nil
	}
	rows, err := s.db.Query(`SELECT provider_key, display_name, source_mask, first_seen_at, last_seen_at, updated_at
        FROM local_provider_catalog ORDER BY provider_key ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]LocalProviderCatalogRecord, 0, 64)
	for rows.Next() {
		var rec LocalProviderCatalogRecord
		if err := rows.Scan(&rec.ProviderKey, &rec.DisplayName, &rec.SourceMask, &rec.FirstSeenAt, &rec.LastSeenAt, &rec.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *localStore) UpsertProviderCatalog(entries []LocalProviderCatalogRecord) error {
	if s == nil || s.db == nil || len(entries) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()
	stmt, err := tx.Prepare(`INSERT INTO local_provider_catalog
        (provider_key, display_name, source_mask, first_seen_at, last_seen_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(provider_key) DO UPDATE SET
        display_name=CASE WHEN excluded.display_name != '' THEN excluded.display_name ELSE local_provider_catalog.display_name END,
        source_mask=(local_provider_catalog.source_mask | excluded.source_mask),
        first_seen_at=CASE
            WHEN local_provider_catalog.first_seen_at <= 0 THEN excluded.first_seen_at
            WHEN excluded.first_seen_at > 0 AND excluded.first_seen_at < local_provider_catalog.first_seen_at THEN excluded.first_seen_at
            ELSE local_provider_catalog.first_seen_at
        END,
        last_seen_at=CASE
            WHEN excluded.last_seen_at > local_provider_catalog.last_seen_at THEN excluded.last_seen_at
            ELSE local_provider_catalog.last_seen_at
        END,
        updated_at=excluded.updated_at`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	now := time.Now().Unix()
	for _, rec := range entries {
		key := normalizeProviderToken(rec.ProviderKey)
		if key == "" {
			continue
		}
		displayName := strings.TrimSpace(rec.DisplayName)
		sourceMask := rec.SourceMask
		if sourceMask < 0 {
			sourceMask = 0
		}
		firstSeenAt := rec.FirstSeenAt
		if firstSeenAt <= 0 {
			firstSeenAt = now
		}
		lastSeenAt := rec.LastSeenAt
		if lastSeenAt <= 0 {
			lastSeenAt = now
		}
		updatedAt := rec.UpdatedAt
		if updatedAt <= 0 {
			updatedAt = now
		}
		if _, err := stmt.Exec(key, displayName, sourceMask, firstSeenAt, lastSeenAt, updatedAt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *localStore) CountProviderCatalog() (int, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	row := s.db.QueryRow("SELECT COUNT(1) FROM local_provider_catalog")
	var count int
	if err := row.Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (s *localStore) GetMeta(key string) (string, int64, error) {
	if s == nil || s.db == nil || strings.TrimSpace(key) == "" {
		return "", 0, nil
	}
	row := s.db.QueryRow("SELECT value, updated_at FROM local_db_meta WHERE key = ?", key)
	var value string
	var updatedAt int64
	if err := row.Scan(&value, &updatedAt); err != nil {
		if err == sql.ErrNoRows {
			return "", 0, nil
		}
		return "", 0, err
	}
	return value, updatedAt, nil
}

func (s *localStore) SetMeta(key, value string) error {
	if s == nil || s.db == nil || strings.TrimSpace(key) == "" {
		return nil
	}
	_, err := s.db.Exec(`INSERT INTO local_db_meta (key, value, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`, key, value, time.Now().Unix())
	return err
}
