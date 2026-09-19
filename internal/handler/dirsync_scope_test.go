package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/storage"
)

func scopeHeader(auth, cookie string) http.Header {
	h := make(http.Header)
	if auth != "" {
		h.Set("Authorization", auth)
	}
	if cookie != "" {
		h.Set("Cookie", cookie)
	}
	return h
}

func TestAuthScopeHashDistinguishesCredentialsAndAnonymous(t *testing.T) {
	hashA := authScopeHash(scopeHeader("Bearer tokenA", ""))
	hashB := authScopeHash(scopeHeader("Bearer tokenB", ""))
	if hashA == "anon" || hashB == "anon" {
		t.Fatalf("credentialed callers must not collapse to anonymous scope: a=%q b=%q", hashA, hashB)
	}
	if hashA == hashB {
		t.Fatalf("different credentials must map to different scopes: %q", hashA)
	}
	if c := authScopeHash(nil); c != "anon" {
		t.Fatalf("nil headers should map to anon, got %q", c)
	}
	// A Cookie can also identify a session.
	if c := authScopeHash(scopeHeader("", "openlist_token=abcd")); c == "anon" || c == hashA {
		t.Fatalf("cookie identity not derived: %q", c)
	}
	// Whitespace-insensitive: the same credential with padding is the same scope.
	if c := authScopeHash(scopeHeader("  Bearer tokenA  ", "")); c != hashA {
		t.Fatalf("scope hash should trim whitespace: got %q want %q", c, hashA)
	}
	// The dir scope key embeds the credential: different creds never collide.
	if buildDirScopeKey("/library", hashA) == buildDirScopeKey("/library", hashB) {
		t.Fatal("different credentials collide on the same directory scope key")
	}
	if got := buildDirScopeKey("/library", ""); !strings.HasSuffix(got, "::anon") {
		t.Fatalf("missing cred must suffix the anon scope key, got %q", got)
	}
}

func TestSnapshotScopeMatchesIsolation(t *testing.T) {
	cfg := &config.Config{}
	cfg.AlistServer = config.AlistServer{ServerHost: "alist.test", ServerPort: 5244, HTTPS: false}
	url := cfg.GetAlistURL()
	h := &AlistHandler{cfg: cfg}

	if !h.snapshotScopeMatches(&DirListSnapshot{AuthScopeHash: "hashA", ProviderHost: url}, "hashA") {
		t.Fatal("same-credential snapshot rejected")
	}
	if h.snapshotScopeMatches(&DirListSnapshot{AuthScopeHash: "hashB", ProviderHost: url}, "hashA") {
		t.Fatal("different-credential snapshot accepted (scope leak)")
	}
	if h.snapshotScopeMatches(&DirListSnapshot{AuthScopeHash: "hashA", ProviderHost: "https://stale.example"}, "hashA") {
		t.Fatal("different-provider snapshot accepted (cross-upstream reuse)")
	}
	// Legacy/metadata-blank rows are treated as non-matching so nothing leaks.
	if !h.snapshotScopeMatches(&DirListSnapshot{}, "hashA") {
		t.Fatal("blank-metadata row should never gate on unknown scope")
	}
}

// TestHandleFsListIsolatesSnapshotsByAuthScope seeds one snapshot per credential
// for the SAME upstream directory and asserts each credential is served only
// its own view, even though both live in the same snapshot store.
func TestHandleFsListIsolatesSnapshotsByAuthScope(t *testing.T) {
	passwd := &config.PasswdInfo{
		Password:  "testpass",
		EncType:   "aesctr",
		Enable:    true,
		EncName:   true,
		EncSuffix: "",
		EncPath:   []string{"/tenant_cloud/encrypt/*"},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/fs/list", func(w http.ResponseWriter, r *http.Request) {
		// Live fallback that must never be served while a scoped snapshot hits.
		writeJSONResponse(w, map[string]interface{}{
			"code": 200, "message": "success",
			"data": map[string]interface{}{
				"content": []interface{}{map[string]interface{}{
					"name": "live", "path": "/tenant_cloud/encrypt/live", "is_dir": true, "size": float64(0), "type": float64(1)}},
				"total": float64(1),
			},
		})
	})
	srv := newSocketTestServer(t, mux)
	defer srv.Close()

	handler, _ := newTestAlistHandler(t, srv.URL, passwd)
	handler.dirSyncStart.Do(func() {})
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("create snapshot store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	dirStore := NewBoltDirSyncStore(store)
	handler.SetDirSyncStore(dirStore)

	hashA := authScopeHash(scopeHeader("Bearer tokenA", ""))
	hashB := authScopeHash(scopeHeader("Bearer tokenB", ""))
	future := time.Now().Add(2 * time.Minute)
	seed := func(name, credHash string) {
		scopeKey := buildDirScopeKey("/tenant_cloud/encrypt", credHash)
		payload := `{"code":200,"message":"success","data":{"content":[{"name":"` + name + `","path":"/tenant_cloud/encrypt/` + name + `","is_dir":true,"size":0,"type":1}],"total":1}}`
		err := dirStore.UpsertSnapshot(t.Context(), DirListSnapshot{
			ScopeKey:      scopeKey,
			DisplayPath:   "/tenant_cloud/encrypt",
			ProviderHost:  handler.cfg.GetAlistURL(),
			AuthScopeHash: credHash,
			SourceMode:    dirSyncModeReq,
			SyncState:     "fresh",
			NextRefreshAt: future,
			ItemCount:     1,
			PayloadJSON:   []byte(payload),
		})
		if err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	seed("forA", hashA)
	seed("forB", hashB)

	request := func(token string) string {
		req := httptest.NewRequest(http.MethodPost, "/api/fs/list", strings.NewReader(`{"path":"/tenant_cloud/encrypt","page":1,"per_page":1000}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		handler.HandleFsList(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		return rec.Body.String()
	}

	bodyA := request("tokenA")
	bodyB := request("tokenB")
	if !strings.Contains(bodyA, "forA") || strings.Contains(bodyA, "forB") {
		t.Fatalf("credential A served cross-scope content: %s", bodyA)
	}
	if !strings.Contains(bodyB, "forB") || strings.Contains(bodyB, "forA") {
		t.Fatalf("credential B served cross-scope content: %s", bodyB)
	}
}

// TestFsListConcurrentColdFlightsStayPerCredential hammers the cold path with
// two credentials targeting the same directory concurrently. The upstream mock
// returns per-credential content, so any A/B cross-sharing in the singleflight
// coalescing (the P0 listing-leak fix) is caught.
func TestFsListConcurrentColdFlightsStayPerCredential(t *testing.T) {
	passwd := &config.PasswdInfo{
		Password:  "testpass",
		EncType:   "aesctr",
		Enable:    true,
		EncName:   true,
		EncSuffix: "",
		EncPath:   []string{"/vault_cloud/encrypt/*"},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/fs/list", func(w http.ResponseWriter, r *http.Request) {
		name := "same"
		switch strings.TrimSpace(r.Header.Get("Authorization")) {
		case "Bearer tokenA":
			name = "fromA"
		case "Bearer tokenB":
			name = "fromB"
		}
		writeJSONResponse(w, map[string]interface{}{
			"code": 200, "message": "success",
			"data": map[string]interface{}{
				"content": []interface{}{map[string]interface{}{
					"name": name, "path": "/vault_cloud/encrypt/" + name, "is_dir": true, "size": float64(0), "type": float64(1)}},
				"total": float64(1),
			},
		})
	})
	srv := newSocketTestServer(t, mux)
	defer srv.Close()

	handler, _ := newTestAlistHandler(t, srv.URL, passwd)
	handler.dirSyncStart.Do(func() {})
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("create snapshot store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	handler.SetDirSyncStore(NewBoltDirSyncStore(store))

	request := func(token string) string {
		req := httptest.NewRequest(http.MethodPost, "/api/fs/list", strings.NewReader(`{"path":"/vault_cloud/encrypt","page":1,"per_page":1000}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		handler.HandleFsList(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("list status=%d body=%s", rec.Code, rec.Body.String())
		}
		return rec.Body.String()
	}

	const concurrency = 32
	var wg sync.WaitGroup
	okA, okB := make(chan bool, concurrency), make(chan bool, concurrency)
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				body := request("tokenA")
				okA <- strings.Contains(body, "fromA") && !strings.Contains(body, "fromB")
			} else {
				body := request("tokenB")
				okB <- strings.Contains(body, "fromB") && !strings.Contains(body, "fromA")
			}
		}(i)
	}
	wg.Wait()
	close(okA)
	close(okB)
	for v := range okA {
		if !v {
			t.Fatal("credential A saw credential B's cold listing")
		}
	}
	for v := range okB {
		if !v {
			t.Fatal("credential B saw credential A's cold listing")
		}
	}
}
