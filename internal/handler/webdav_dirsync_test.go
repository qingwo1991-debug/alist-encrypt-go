package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/storage"
)

// seedDirSnapshot writes a request-fill snapshot for the given display dir.
func seedDirSnapshot(t *testing.T, store DirSyncStore, dirPath, scopeKey string, content []map[string]interface{}) {
	t.Helper()
	payload, err := json.Marshal(map[string]interface{}{
		"code": 200,
		"data": map[string]interface{}{
			"total":   len(content),
			"content": content,
		},
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	now := time.Now()
	if err := store.UpsertSnapshot(context.Background(), DirListSnapshot{
		ScopeKey:      scopeKey,
		ProviderHost:  "http://127.0.0.1:5244",
		DisplayPath:   dirPath,
		AuthScopeHash: "test",
		RuleVersion:   "v1",
		ItemCount:     len(content),
		Stale:         false,
		SyncState:     "fresh",
		LastSyncAt:    now,
		LastSuccessAt: now,
		NextRefreshAt: now.Add(time.Minute),
		LastError:     "",
		SourceMode:    dirSyncModeReq,
		PayloadJSON:   payload,
		UpdatedAt:     now,
		LastAccessed:  now,
	}); err != nil {
		t.Fatalf("upsert snapshot: %v", err)
	}
}

// newWebDAVSnapshotHandler builds a WebDAVHandler with a passwd whitelist and a
// Bolt-backed dir-sync store.
func newWebDAVSnapshotTestHandler(t *testing.T) (*WebDAVHandler, DirSyncStore, *dao.FileDAO) {
	t.Helper()
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	cfg := config.DefaultConfig()
	cfg.AlistServer.PasswdList = []config.PasswdInfo{{
		Password: "test-secret",
		EncType:  "aesctr",
		Enable:   true,
		EncName:  true,
		EncPath:  []string{"/156联通云盘/encrypt/*"},
	}}

	fileDAO := dao.NewFileDAO(store)
	passwdDAO := dao.NewPasswdDAO(store, cfg)
	h := &WebDAVHandler{
		cfg:       cfg,
		fileDAO:   fileDAO,
		passwdDAO: passwdDAO,
		negCache:  nil,
	}
	dirStore := NewBoltDirSyncStore(store)
	h.SetDirSyncStore(dirStore)
	return h, dirStore, fileDAO
}

func TestServeSnapshotListingCacheHit(t *testing.T) {
	h, dirStore, _ := newWebDAVSnapshotTestHandler(t)

	scopeKey := buildDirScopeKey("/156联通云盘/encrypt", "anon")
	seedDirSnapshot(t, dirStore, "/156联通云盘/encrypt", scopeKey, []map[string]interface{}{
		{"name": "01-电影.mkv", "path": "/156联通云盘/encrypt/01-电影.mkv", "size": 1024, "is_dir": false},
		{"name": "sub", "path": "/156联通云盘/encrypt/sub", "size": 0, "is_dir": true},
	})

	r := httptest.NewRequest("PROPFIND", "/dav/156联通云盘/encrypt/", nil)
	r.Header.Set("Depth", "1")
	body, ok := h.serveSnapshotListing(r, "/156联通云盘/encrypt")
	if !ok {
		t.Fatalf("expected cache hit for whitelisted dir")
	}
	if len(body) == 0 {
		t.Fatalf("expected non-empty multistatus body")
	}
	for _, want := range []string{"156联通云盘/encrypt", "01-电影.mkv", "sub", "HTTP/1.1 200 OK", "multistatus"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("body missing %q; body=%s", want, string(body))
		}
	}
	if !strings.Contains(string(body), "<D:collection/>") {
		t.Errorf("expected a collection resourcetype for %q dir", "sub")
	}
}

func TestServeSnapshotListingDepthZeroFallsThrough(t *testing.T) {
	h, dirStore, _ := newWebDAVSnapshotTestHandler(t)
	scopeKey := buildDirScopeKey("/156联通云盘/encrypt", "anon")
	seedDirSnapshot(t, dirStore, "/156联通云盘/encrypt", scopeKey, []map[string]interface{}{
		{"name": "a.txt", "path": "/156联通云盘/encrypt/a.txt", "size": 1, "is_dir": false},
	})

	r := httptest.NewRequest(http.MethodGet, "/PROPFIND", nil)
	r.Header.Set("Depth", "0")
	if _, ok := h.serveSnapshotListing(r, "/156联通云盘/encrypt"); ok {
		t.Fatalf("Depth:0 PROPFIND must not be served from directory snapshot")
	}
}

func TestServeSnapshotListingNonWhitelistedFallsThrough(t *testing.T) {
	h, _, _ := newWebDAVSnapshotTestHandler(t)
	r := httptest.NewRequest(http.MethodGet, "/PROPFIND", nil)
	r.Header.Set("Depth", "1")
	if _, ok := h.serveSnapshotListing(r, "/156联通云盘/other"); ok {
		t.Fatalf("non-whitelisted directory must not be served from snapshot")
	}
}

func TestServeSnapshotListingRejectsPoisonPayload(t *testing.T) {
	// A payload whose content claims to belong to a DIFFERENT directory must be
	// rejected by validateSnapshotForDir — e.g. a leftover root-mounted name.
	h, dirStore, _ := newWebDAVSnapshotTestHandler(t)
	scopeKey := buildDirScopeKey("/156联通云盘/encrypt", "anon")
	seedDirSnapshot(t, dirStore, "/156联通云盘/encrypt", scopeKey, []map[string]interface{}{
		{"name": "156联通云盘", "path": "/156联通云盘/encrypt/156联通云盘", "size": 0, "is_dir": true},
		// poison item: a sibling path not under the dir
		{"name": "other", "path": "/elsewhere/other", "size": 1, "is_dir": false},
	})

	r := httptest.NewRequest(http.MethodGet, "/PROPFIND", nil)
	r.Header.Set("Depth", "1")
	if _, ok := h.serveSnapshotListing(r, "/156联通云盘/encrypt"); ok {
		t.Fatalf("snapshot containing out-of-dir item must not be served")
	}
}

func TestPersistWebDAVSnapshotWritesSharedPayload(t *testing.T) {
	h, dirStore, _ := newWebDAVSnapshotTestHandler(t)
	r := httptest.NewRequest(http.MethodGet, "/PROPFIND",
		strings.NewReader("<?xml version=\"1.0\"?><D:propfind xmlns:D=\"DAV:\"><D:prop><D:getcontentlength/></D:prop></D:propfind>"))
	r.Header.Set("Depth", "1")
	// dirRequest + whitelist
	h.persistWebDAVSnapshot(r, "/156联通云盘/encrypt", []propfindEntry{
		{Path: "/156联通云盘/encrypt", Name: "", Size: 0, IsDir: true}, // self
		{Path: "/156联通云盘/encrypt/01-电影.mkv", Name: "01-电影.mkv", Size: 1234, IsDir: false},
		{Path: "/156联通云盘/encrypt/sub", Name: "sub", Size: 0, IsDir: true},
	})

	scopeKey := buildDirScopeKey("/156联通云盘/encrypt", "anon")
	snap, ok, _ := dirStore.GetSnapshot(context.Background(), scopeKey)
	if !ok || snap == nil {
		t.Fatalf("expected snapshot persisted under scope key")
	}
	if snap.SourceMode != dirSyncModeReq {
		t.Fatalf("source mode=%s want %s", snap.SourceMode, dirSyncModeReq)
	}
	if !strings.Contains(string(snap.PayloadJSON), "01-电影.mkv") {
		t.Fatalf("payload missing decrypted child name: %s", string(snap.PayloadJSON))
	}
	if strings.Contains(string(snap.PayloadJSON), `"name":""`) || strings.Contains(string(snap.PayloadJSON), `"name":`+`""`+`,`) {
		t.Fatalf("self response leaked into payload: %s", string(snap.PayloadJSON))
	}
	if snap.ItemCount != 2 {
		t.Fatalf("item count=%d, want 2 (self dropped)", snap.ItemCount)
	}
	// Pluggable HTTP+WebDAV reuse: this very snapshot must validate and serve.
	body, ok := h.serveSnapshotListing(r, "/156联通云盘/encrypt")
	if !ok {
		t.Fatalf("persisted snapshot should be servable by serveSnapshot")
	}
	for _, want := range []string{"01-电影.mkv", "sub", "1234"} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("served body missing %q:\n%s", want, string(body))
		}
	}
}

func TestBuildSnapshotMultistatusRoot(t *testing.T) {
	h, _, _ := newWebDAVSnapshotTestHandler(t)
	body := h.buildSnapshotMultistatus("/", []byte(`{"code":200,"data":{"content":[{"name":"hello.txt","size":55,"is_dir":false,"path":"/hello.txt"}]}}`))
	if len(body) == 0 {
		t.Fatal("expected multistatus for root")
	}
	if !strings.Contains(string(body), "/dav/hello.txt") {
		t.Fatalf("expected child href, got:\n%s", string(body))
	}
}
