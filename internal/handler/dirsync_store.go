package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/alist-encrypt-go/internal/storage"
	"github.com/alist-encrypt-go/internal/storage/mysqlstore"
)

const (
	dirSyncBucketSnapshotPrefix = "snapshot:"
	dirSyncBucketStatusPrefix   = "status:"
	dirSyncPrimaryStatusName    = "primary"
)

type DirListSnapshot struct {
	ScopeKey      string    `json:"scope_key"`
	ProviderHost  string    `json:"provider_host"`
	DisplayPath   string    `json:"display_path"`
	AuthScopeHash string    `json:"auth_scope_hash"`
	RuleVersion   string    `json:"rule_version"`
	ItemCount     int       `json:"item_count"`
	Stale         bool      `json:"stale"`
	SyncState     string    `json:"sync_state"`
	LastSyncAt    time.Time `json:"last_sync_at"`
	LastSuccessAt time.Time `json:"last_success_at"`
	NextRefreshAt time.Time `json:"next_refresh_at"`
	LastError     string    `json:"last_error"`
	SourceMode    string    `json:"source_mode"`
	PayloadJSON   []byte    `json:"payload_json"`
	UpdatedAt     time.Time `json:"updated_at"`
	LastAccessed  time.Time `json:"last_accessed"`
}

type DirSyncStatus struct {
	Name                string    `json:"name"`
	JobID               string    `json:"job_id"`
	JobType             string    `json:"job_type"`
	Status              string    `json:"status"`
	Mode                string    `json:"mode"`
	ScanConfigured      bool      `json:"scan_configured"`
	TotalDirsEstimate   int       `json:"total_dirs_estimate"`
	TotalDirsDiscovered int       `json:"total_dirs_discovered"`
	DirsScanned         int       `json:"dirs_scanned"`
	DirsSucceeded       int       `json:"dirs_succeeded"`
	DirsFailed          int       `json:"dirs_failed"`
	DirsSkipped         int       `json:"dirs_skipped"`
	ItemsSynced         int       `json:"items_synced"`
	StartedAt           time.Time `json:"started_at"`
	UpdatedAt           time.Time `json:"updated_at"`
	FinishedAt          time.Time `json:"finished_at"`
	NextRunAt           time.Time `json:"next_run_at"`
	LastError           string    `json:"last_error"`
	LastSuccessAt       time.Time `json:"last_success_at"`
}

type DirSyncStore interface {
	GetSnapshot(ctx context.Context, scopeKey string) (*DirListSnapshot, bool, error)
	UpsertSnapshot(ctx context.Context, snap DirListSnapshot) error
	CountSnapshots(ctx context.Context) (total, fresh, stale, syncing int64, err error)
	GetStatus(ctx context.Context, name string) (*DirSyncStatus, bool, error)
	UpsertStatus(ctx context.Context, status DirSyncStatus) error
}

type BoltDirSyncStore struct {
	store *storage.Store
}

func NewBoltDirSyncStore(store *storage.Store) *BoltDirSyncStore {
	if store == nil {
		return nil
	}
	return &BoltDirSyncStore{store: store}
}

func (s *BoltDirSyncStore) GetSnapshot(_ context.Context, scopeKey string) (*DirListSnapshot, bool, error) {
	if s == nil || s.store == nil {
		return nil, false, nil
	}
	var snap DirListSnapshot
	if err := s.store.GetJSON(storage.BucketDirSync, dirSyncBucketSnapshotPrefix+scopeKey, &snap); err != nil {
		return nil, false, err
	}
	if snap.ScopeKey == "" {
		return nil, false, nil
	}
	return &snap, true, nil
}

func (s *BoltDirSyncStore) UpsertSnapshot(_ context.Context, snap DirListSnapshot) error {
	if s == nil || s.store == nil {
		return nil
	}
	return s.store.SetJSON(storage.BucketDirSync, dirSyncBucketSnapshotPrefix+snap.ScopeKey, snap)
}

func (s *BoltDirSyncStore) CountSnapshots(_ context.Context) (total, fresh, stale, syncing int64, err error) {
	if s == nil || s.store == nil {
		return 0, 0, 0, 0, nil
	}
	items, err := s.store.GetAll(storage.BucketDirSync)
	if err != nil {
		return
	}
	for key, value := range items {
		if len(key) < len(dirSyncBucketSnapshotPrefix) || key[:len(dirSyncBucketSnapshotPrefix)] != dirSyncBucketSnapshotPrefix {
			continue
		}
		var snap DirListSnapshot
		if jsonErr := json.Unmarshal(value, &snap); jsonErr != nil {
			continue
		}
		total++
		if snap.Stale {
			stale++
		}
		if snap.SyncState == "syncing" {
			syncing++
		}
		if !snap.Stale && snap.SyncState == "fresh" {
			fresh++
		}
	}
	return
}

func (s *BoltDirSyncStore) GetStatus(_ context.Context, name string) (*DirSyncStatus, bool, error) {
	if s == nil || s.store == nil {
		return nil, false, nil
	}
	var status DirSyncStatus
	if err := s.store.GetJSON(storage.BucketDirSync, dirSyncBucketStatusPrefix+name, &status); err != nil {
		return nil, false, err
	}
	if status.Name == "" {
		return nil, false, nil
	}
	return &status, true, nil
}

func (s *BoltDirSyncStore) UpsertStatus(_ context.Context, status DirSyncStatus) error {
	if s == nil || s.store == nil {
		return nil
	}
	if status.Name == "" {
		status.Name = dirSyncPrimaryStatusName
	}
	return s.store.SetJSON(storage.BucketDirSync, dirSyncBucketStatusPrefix+status.Name, status)
}

type MySQLDirSyncStore struct {
	store *mysqlstore.Store
}

func NewMySQLDirSyncStore(store *mysqlstore.Store) *MySQLDirSyncStore {
	if store == nil {
		return nil
	}
	return &MySQLDirSyncStore{store: store}
}

func (s *MySQLDirSyncStore) GetSnapshot(ctx context.Context, scopeKey string) (*DirListSnapshot, bool, error) {
	rec, ok, err := s.store.GetDirSnapshot(ctx, scopeKey)
	if err != nil || !ok || rec == nil {
		return nil, ok, err
	}
	return &DirListSnapshot{
		ScopeKey:      rec.ScopeKey,
		ProviderHost:  rec.ProviderHost,
		DisplayPath:   rec.DisplayPath,
		AuthScopeHash: rec.AuthScopeHash,
		RuleVersion:   rec.RuleVersion,
		ItemCount:     rec.ItemCount,
		Stale:         rec.Stale,
		SyncState:     rec.SyncState,
		LastSyncAt:    rec.LastSyncAt,
		LastSuccessAt: rec.LastSuccessAt,
		NextRefreshAt: rec.NextRefreshAt,
		LastError:     rec.LastError,
		SourceMode:    rec.SourceMode,
		PayloadJSON:   []byte(rec.PayloadJSON),
		UpdatedAt:     rec.UpdatedAt,
		LastAccessed:  rec.LastAccessed,
	}, true, nil
}

func (s *MySQLDirSyncStore) UpsertSnapshot(ctx context.Context, snap DirListSnapshot) error {
	return s.store.UpsertDirSnapshot(ctx, mysqlstore.DirSnapshotRecord{
		ScopeKey:      snap.ScopeKey,
		ProviderHost:  snap.ProviderHost,
		DisplayPath:   snap.DisplayPath,
		AuthScopeHash: snap.AuthScopeHash,
		RuleVersion:   snap.RuleVersion,
		ItemCount:     snap.ItemCount,
		Stale:         snap.Stale,
		SyncState:     snap.SyncState,
		LastSyncAt:    snap.LastSyncAt,
		LastSuccessAt: snap.LastSuccessAt,
		NextRefreshAt: snap.NextRefreshAt,
		LastError:     snap.LastError,
		SourceMode:    snap.SourceMode,
		PayloadJSON:   string(snap.PayloadJSON),
		UpdatedAt:     snap.UpdatedAt,
		LastAccessed:  snap.LastAccessed,
		Active:        true,
	})
}

func (s *MySQLDirSyncStore) CountSnapshots(ctx context.Context) (total, fresh, stale, syncing int64, err error) {
	return s.store.CountDirSnapshots(ctx)
}

func (s *MySQLDirSyncStore) GetStatus(ctx context.Context, name string) (*DirSyncStatus, bool, error) {
	rec, ok, err := s.store.GetDirSyncStatus(ctx, name)
	if err != nil || !ok || rec == nil {
		return nil, ok, err
	}
	return &DirSyncStatus{
		Name:                rec.Name,
		JobID:               rec.JobID,
		JobType:             rec.JobType,
		Status:              rec.Status,
		Mode:                rec.Mode,
		ScanConfigured:      rec.ScanConfigured,
		TotalDirsEstimate:   rec.TotalDirsEstimate,
		TotalDirsDiscovered: rec.TotalDirsDiscovered,
		DirsScanned:         rec.DirsScanned,
		DirsSucceeded:       rec.DirsSucceeded,
		DirsFailed:          rec.DirsFailed,
		DirsSkipped:         rec.DirsSkipped,
		ItemsSynced:         rec.ItemsSynced,
		StartedAt:           rec.StartedAt,
		UpdatedAt:           rec.UpdatedAt,
		FinishedAt:          rec.FinishedAt,
		NextRunAt:           rec.NextRunAt,
		LastError:           rec.LastError,
		LastSuccessAt:       rec.LastSuccessAt,
	}, true, nil
}

func (s *MySQLDirSyncStore) UpsertStatus(ctx context.Context, status DirSyncStatus) error {
	if status.Name == "" {
		status.Name = dirSyncPrimaryStatusName
	}
	return s.store.UpsertDirSyncStatus(ctx, mysqlstore.DirSyncStatusRecord{
		Name:                status.Name,
		JobID:               status.JobID,
		JobType:             status.JobType,
		Status:              status.Status,
		Mode:                status.Mode,
		ScanConfigured:      status.ScanConfigured,
		TotalDirsEstimate:   status.TotalDirsEstimate,
		TotalDirsDiscovered: status.TotalDirsDiscovered,
		DirsScanned:         status.DirsScanned,
		DirsSucceeded:       status.DirsSucceeded,
		DirsFailed:          status.DirsFailed,
		DirsSkipped:         status.DirsSkipped,
		ItemsSynced:         status.ItemsSynced,
		StartedAt:           status.StartedAt,
		UpdatedAt:           status.UpdatedAt,
		FinishedAt:          status.FinishedAt,
		NextRunAt:           status.NextRunAt,
		LastError:           status.LastError,
		LastSuccessAt:       status.LastSuccessAt,
	})
}

func ruleVersion(cfgScope string) string {
	if cfgScope == "" {
		return "v1"
	}
	return fmt.Sprintf("v1:%s", cfgScope)
}
