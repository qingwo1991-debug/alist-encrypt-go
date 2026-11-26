package handler

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/storage/mysqlstore"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

// fakeFileMetaPersistence records calls and stands in for *mysqlstore.Store.
type fakeFileMetaPersistence struct {
	gets        int // key-hash lookups
	getsByPath  int // path lookups (fallback)
	upserts     []mysqlstore.FileMetaRecord
	stored      *mysqlstore.FileMetaRecord // returned by GetFileMeta / ByPath
	getErr      error
	getFound    bool
	byPathFound bool
}

func (f *fakeFileMetaPersistence) GetFileMeta(_ context.Context, _, _ string) (*mysqlstore.FileMetaRecord, bool, error) {
	f.gets++
	if f.getErr != nil {
		return nil, false, f.getErr
	}
	return f.stored, f.getFound, nil
}

func (f *fakeFileMetaPersistence) GetFileMetaByPath(_ context.Context, _ string) (*mysqlstore.FileMetaRecord, bool, error) {
	f.getsByPath++
	return f.stored, f.byPathFound, nil
}

func (f *fakeFileMetaPersistence) UpsertFileMeta(_ context.Context, record mysqlstore.FileMetaRecord) error {
	f.upserts = append(f.upserts, record)
	return nil
}

func (f *fakeFileMetaPersistence) CleanupFileMeta(context.Context, time.Time) error { return nil }

// TestMySQLFileMetaStoreUpsertHasNoPreWriteRead locks in change 3: the
// request path must not perform a GetFileMeta round trip before enqueueing.
func TestMySQLFileMetaStoreUpsertHasNoPreWriteRead(t *testing.T) {
	f := &fakeFileMetaPersistence{stored: &mysqlstore.FileMetaRecord{Size: 1}, getFound: true}
	s := newMySQLFileMetaStore(f)
	meta := FileMeta{ProviderKey: "alist.example:5244", OriginalPath: "/m/a.mp4", Size: 12345, StatusCode: 206, ContentType: "video/mp4"}
	if err := s.Upsert(context.Background(), meta); err != nil {
		t.Fatal(err)
	}
	if f.gets != 0 || f.getsByPath != 0 {
		t.Fatalf("Upsert performed a read before writing: gets=%d byPath=%d", f.gets, f.getsByPath)
	}
	if len(f.upserts) != 1 {
		t.Fatalf("upserts=%d, want 1", len(f.upserts))
	}
	// Identical in-memory write is coalesced without touching storage at all.
	if err := s.Upsert(context.Background(), meta); err != nil {
		t.Fatal(err)
	}
	if len(f.upserts) != 1 {
		t.Fatalf("identical write reached storage: upserts=%d", len(f.upserts))
	}
	// A changed size is enqueued.
	meta.Size = 999
	if err := s.Upsert(context.Background(), meta); err != nil {
		t.Fatal(err)
	}
	if len(f.upserts) != 2 {
		t.Fatalf("changed size not enqueued: upserts=%d", len(f.upserts))
	}
}

// TestMySQLFileMetaStoreUpsertRecordIsSizeOnly: the handler enqueues a bare
// size observation; geometry/URL/sign reconciliation is the store's job at
// flush time. The record must not carry a legacy key hash (the store keys on
// the stable host) so all writers for a path converge on one row.
func TestMySQLFileMetaStoreUpsertRecordIsSizeOnly(t *testing.T) {
	f := &fakeFileMetaPersistence{}
	s := newMySQLFileMetaStore(f)
	if err := s.Upsert(context.Background(), FileMeta{ProviderKey: "cdn99.example", OriginalPath: "/m/a.mp4", Size: 12345, ETag: "e", ContentType: "video/mp4", StatusCode: 206}); err != nil {
		t.Fatal(err)
	}
	got := f.upserts[0]
	if got.KeyHash != "" || got.ProviderHost != "" {
		t.Fatalf("record carries a legacy identity; store must assign the stable key: %+v", got)
	}
	if got.OriginalPath != "/m/a.mp4" || got.Size != 12345 || got.ETag != "e" || got.ContentType != "video/mp4" || got.StatusCode != 206 || !got.Active {
		t.Fatalf("size observation not mapped: %+v", got)
	}
	if got.ContentVersion != 0 || got.RawURL != "" || got.Sign != "" {
		t.Fatalf("size-only record must not invent geometry/url: %+v", got)
	}
}

// TestMySQLFileMetaStoreGetFallsBackToPath: when the key-hash lookup misses
// (caller used a rotating raw-URL host), Get answers from the path lookup so
// the size resolver / probe scheduler stay correct after the one-row-per-path
// migration.
func TestMySQLFileMetaStoreGetFallsBackToPath(t *testing.T) {
	stored := &mysqlstore.FileMetaRecord{OriginalPath: "/m/a.mp4", Size: 12345, StatusCode: 206, ContentType: "video/mp4", ETag: "e"}
	f := &fakeFileMetaPersistence{stored: stored, byPathFound: true}
	s := newMySQLFileMetaStore(f)
	meta, ok, err := s.Get(context.Background(), "cdn7.example", "/m/a.mp4")
	if err != nil || !ok {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	if meta.Size != 12345 || meta.ProviderKey != "cdn7.example" || meta.OriginalPath != "/m/a.mp4" || meta.StatusCode != 206 {
		t.Fatalf("fallback meta: %+v", meta)
	}
	if f.gets != 1 || f.getsByPath != 1 {
		t.Fatalf("expected one key-hash lookup then one path lookup: gets=%d byPath=%d", f.gets, f.getsByPath)
	}

	// Key-hash hit: no path lookup.
	f = &fakeFileMetaPersistence{stored: stored, getFound: true}
	s = newMySQLFileMetaStore(f)
	if _, ok, _ := s.Get(context.Background(), "alist.example", "/m/a.mp4"); !ok {
		t.Fatal("key-hash hit not returned")
	}
	if f.getsByPath != 0 {
		t.Fatalf("path lookup used on a key-hash hit: %d", f.getsByPath)
	}
	// Both miss: not found, no error.
	f = &fakeFileMetaPersistence{}
	s = newMySQLFileMetaStore(f)
	if _, ok, err := s.Get(context.Background(), "x", "/m/a.mp4"); ok || err != nil {
		t.Fatalf("miss: ok=%v err=%v", ok, err)
	}
	// Read error propagates.
	f = &fakeFileMetaPersistence{getErr: errors.New("db down")}
	s = newMySQLFileMetaStore(f)
	if _, ok, err := s.Get(context.Background(), "x", "/m/a.mp4"); ok || err == nil {
		t.Fatalf("error not propagated: ok=%v err=%v", ok, err)
	}
}

// TestStableFileMetaProviderHostMatchesResolverKey: the stable host must be
// exactly what ProviderKey(cfg.GetAlistURL(), path) derives, so GetFileMeta's
// key-hash lookup (used via metaStore.Get) resolves the stable row directly.
func TestStableFileMetaProviderHostMatchesResolverKey(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AlistServer.ServerHost = "alist.internal"
	cfg.AlistServer.ServerPort = 5244
	host := StableFileMetaProviderHost(cfg)
	if host != "alist.internal:5244" {
		t.Fatalf("host=%q", host)
	}
	if ProviderKey(cfg.GetAlistURL(), "/x") != host {
		t.Fatalf("resolver key %q != stable host %q", ProviderKey(cfg.GetAlistURL(), "/x"), host)
	}
	parsed, _ := url.Parse(cfg.GetAlistURL())
	if mysqlstore.KeyHash(parsed.Host, "/x") != mysqlstore.KeyHash(host, "/x") {
		t.Fatal("key hashes diverge")
	}
	// HTTPS default port collapses to bare host, matching both sides.
	cfg.AlistServer.HTTPS = true
	cfg.AlistServer.ServerPort = 443
	if got := StableFileMetaProviderHost(cfg); got != "alist.internal" || ProviderKey(cfg.GetAlistURL(), "/x") != got {
		t.Fatalf("https default port: host=%q key=%q", got, ProviderKey(cfg.GetAlistURL(), "/x"))
	}
	// IPv6 host is kept bracketed by BuildAlistURL and parsed back identically.
	cfg.AlistServer.HTTPS = false
	cfg.AlistServer.ServerPort = 0
	cfg.AlistServer.ServerHost = "::1"
	if got := StableFileMetaProviderHost(cfg); got != ProviderKey(cfg.GetAlistURL(), "/x") || got == "" {
		t.Fatalf("ipv6: host=%q key=%q", got, ProviderKey(cfg.GetAlistURL(), "/x"))
	}
	// No config: sentinel.
	if StableFileMetaProviderHost(nil) != mysqlstore.StableProviderHostSentinel {
		t.Fatal("nil config must yield the sentinel")
	}
}

// TestPreserveFileMetaStoredRowAdapter: the exported adapter delegates to
// preserveV2FileMetaRecord and tolerates nils.
func TestPreserveFileMetaStoredRowAdapter(t *testing.T) {
	PreserveFileMetaStoredRow(nil, nil)
	stored := &mysqlstore.FileMetaRecord{Size: 4096, CiphertextSize: 4128, ContentVersion: encryption.ContentVersionV3, HeaderLen: 64, NonceField: []byte("n"), ChunkSize: 4096, KDFIterations: 10, RawURL: "https://cdn/a", Sign: "s"}
	incoming := &mysqlstore.FileMetaRecord{Size: 4128, StatusCode: 206}
	PreserveFileMetaStoredRow(stored, incoming)
	if incoming.Size != 4096 || incoming.ContentVersion != encryption.ContentVersionV3 || incoming.RawURL != "https://cdn/a" || incoming.Sign != "s" || incoming.ChunkSize != 4096 {
		t.Fatalf("adapter did not reconcile: %+v", incoming)
	}
	if incoming.StatusCode != 206 {
		t.Fatalf("adapter must keep the observation: %+v", incoming)
	}
}
