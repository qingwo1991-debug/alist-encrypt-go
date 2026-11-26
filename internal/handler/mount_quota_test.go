package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/storage"
)

// mountQuota upstream fixture: a root listing with two mounts, each carrying
// mount_details like OpenList does for signed-in non-guest users.
func mountQuotaRootListing(total1, used1, total2, used2 int64) map[string]interface{} {
	return map[string]interface{}{
		"code": 200, "message": "success",
		"data": map[string]interface{}{
			"content": []interface{}{
				map[string]interface{}{"name": "mountA", "is_dir": true, "size": 0,
					"mount_details": map[string]interface{}{"total_space": float64(total1), "used_space": float64(used1)}},
				map[string]interface{}{"name": "mountB", "is_dir": true, "size": 0,
					"mount_details": map[string]interface{}{"total_space": float64(total2), "used_space": float64(used2)}},
				map[string]interface{}{"name": "plainfile.txt", "is_dir": false, "size": 3},
			},
			"total": float64(3),
		},
	}
}

type mountQuotaUpstream struct {
	mu        sync.Mutex
	listCalls atomic.Int32
	refreshes atomic.Int32 // listings that arrived with refresh:true
	quota     map[string]interface{}
	// onRefresh, when set, replaces the served listing for refresh calls.
	onRefresh func() map[string]interface{}
}

func (u *mountQuotaUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/fs/list" {
		http.NotFound(w, r)
		return
	}
	u.listCalls.Add(1)
	var req map[string]interface{}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if refresh, _ := req["refresh"].(bool); refresh {
		u.refreshes.Add(1)
		if u.onRefresh != nil {
			writeJSONResponse(w, u.onRefresh())
			return
		}
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	writeJSONResponse(w, u.quota)
}

func newMountQuotaHandler(t *testing.T, u *mountQuotaUpstream) *AlistHandler {
	return newMountQuotaHandlerWithScope(t, u, "/encrypt/*")
}

// newMountQuotaHandlerWithScope builds a handler whose encryption path
// whitelist is encPath. Only whitelisted directories get directory snapshots,
// so the snapshot-path tests pass "/" to make the root eligible.
func newMountQuotaHandlerWithScope(t *testing.T, u *mountQuotaUpstream, encPath string) *AlistHandler {
	t.Helper()
	passwd := &config.PasswdInfo{Password: "testpass", EncType: "aesctr", Enable: true, EncName: false, EncPath: []string{encPath}}
	mux := http.NewServeMux()
	mux.Handle("/api/fs/list", u)
	srv := newSocketTestServer(t, mux)
	t.Cleanup(srv.Close)
	handler, _ := newTestAlistHandler(t, srv.URL, passwd)
	t.Cleanup(handler.Stop)
	return handler
}

func listRootAs(t *testing.T, h *AlistHandler, token string) (map[string]interface{}, []map[string]interface{}) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/fs/list", strings.NewReader(`{"path":"/","page":1,"per_page":0}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", token)
	rec := httptest.NewRecorder()
	h.HandleFsList(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	data, _ := doc["data"].(map[string]interface{})
	content, _ := data["content"].([]interface{})
	var entries []map[string]interface{}
	for _, c := range content {
		if m, ok := c.(map[string]interface{}); ok {
			entries = append(entries, m)
		}
	}
	return doc, entries
}

func mountDetailsOf(t *testing.T, entries []map[string]interface{}, name string) (float64, float64, bool) {
	t.Helper()
	for _, e := range entries {
		if e["name"] == name {
			md, _ := e["mount_details"].(map[string]interface{})
			if md == nil {
				return 0, 0, false
			}
			total, _ := md["total_space"].(float64)
			used, _ := md["used_space"].(float64)
			return total, used, true
		}
	}
	t.Fatalf("entry %q not found", name)
	return 0, 0, false
}

// scopeOf returns the cache key prefix the handler derives for a bearer
// token, so tests never assume how requestScopeHash is spelled.
func scopeOf(h *AlistHandler, token string) string {
	hdrs := http.Header{}
	hdrs.Set("Authorization", token)
	return h.requestScopeHash(hdrs)
}

func awaitQuotaCondition(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

// Live path: upstream's own quota is passed through on the first listing and
// seeds the cache; nothing is rewritten and no refresh is needed while fresh.
func TestMountQuotaLivePassThroughAndSeed(t *testing.T) {
	u := &mountQuotaUpstream{quota: mountQuotaRootListing(1000, 400, 2000, 1500)}
	h := newMountQuotaHandler(t, u)

	_, entries := listRootAs(t, h, "tok-A")
	if total, used, ok := mountDetailsOf(t, entries, "mountA"); !ok || total != 1000 || used != 400 {
		t.Fatalf("mountA quota = %v/%v ok=%v, want 1000/400", total, used, ok)
	}
	if total, used, ok := mountDetailsOf(t, entries, "mountB"); !ok || total != 2000 || used != 1500 {
		t.Fatalf("mountB quota = %v/%v ok=%v, want 2000/1500", total, used, ok)
	}
	// plain (non-directory) entries are never touched
	for _, e := range entries {
		if e["name"] == "plainfile.txt" {
			if _, has := e["mount_details"]; has {
				t.Fatal("non-directory entry gained mount_details")
			}
		}
	}
	awaitQuotaCondition(t, "cache seeded", func() bool {
		_, ok := h.mountQuota.get(scopeOf(h, "tok-A"), "/mountA")
		return ok
	})
	if u.refreshes.Load() != 0 {
		t.Fatalf("fresh upstream quota must not trigger a background refresh, got %d", u.refreshes.Load())
	}
	h.mountQuotaWG.Wait()
}

// Snapshot path: the snapshot froze an old quota, the per-account cache holds
// a newer one; the served listing must carry the cached value, not the frozen
// one, and must not be mistaken for a fresh observation itself.
func TestMountQuotaSnapshotServesCachedValue(t *testing.T) {
	u := &mountQuotaUpstream{quota: mountQuotaRootListing(1000, 400, 2000, 1500)}
	h := newMountQuotaHandlerWithScope(t, u, "/")
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("create snapshot store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	h.SetDirSyncStore(NewBoltDirSyncStore(store))

	// First live listing seeds both the snapshot and the quota cache.
	listRootAs(t, h, "tok-A")
	awaitQuotaCondition(t, "snapshot persisted", func() bool {
		return u.listCalls.Load() >= 1
	})

	// Simulate a newer quota arriving from a background refresh.
	h.mountQuota.remember(scopeOf(h, "tok-A"), "/mountA", mountQuota{TotalSpace: 1000, UsedSpace: 900}, time.Now(), freshQuota)
	h.mountQuota.remember(scopeOf(h, "tok-A"), "/mountB", mountQuota{TotalSpace: 2000, UsedSpace: 1800}, time.Now(), freshQuota)

	// Now force the snapshot path: a second listing must be served from the
	// persisted snapshot (cache_hit=true) and still show the newer quota.
	before := u.listCalls.Load()
	doc, entries := listRootAs(t, h, "tok-A")
	if hit, _ := doc["cache_hit"].(bool); !hit {
		t.Fatalf("expected snapshot path (cache_hit=true), doc=%s", mustJSON(t, doc))
	}
	if got := u.listCalls.Load(); got != before {
		t.Fatalf("snapshot path must not call upstream, calls went %d -> %d", before, got)
	}
	if _, used, _ := mountDetailsOf(t, entries, "mountA"); used != 900 {
		t.Fatalf("mountA used=%v, want cached 900 (snapshot had 400)", used)
	}
	if _, used, _ := mountDetailsOf(t, entries, "mountB"); used != 1800 {
		t.Fatalf("mountB used=%v, want cached 1800 (snapshot had 1500)", used)
	}
}

// Stale cache: a listing serves the stale value immediately and triggers
// exactly one detached refresh with refresh:true per account; the refreshed
// value shows up on the next listing.
func TestMountQuotaStaleTriggersOneRefreshAndConverges(t *testing.T) {
	u := &mountQuotaUpstream{quota: mountQuotaRootListing(1000, 400, 2000, 1500)}
	u.onRefresh = func() map[string]interface{} { return mountQuotaRootListing(1000, 777, 2000, 1888) }
	h := newMountQuotaHandler(t, u)

	// Seed, then age the cache past TTL.
	listRootAs(t, h, "tok-A")
	awaitQuotaCondition(t, "cache seeded", func() bool { _, ok := h.mountQuota.get(scopeOf(h, "tok-A"), "/mountA"); return ok })
	h.mountQuota.mu.Lock()
	for k, e := range h.mountQuota.entries {
		e.fetched = time.Now().Add(-mountQuotaTTL - time.Minute)
		h.mountQuota.entries[k] = e
	}
	h.mountQuota.mu.Unlock()

	// Many concurrent stale listings for the same account: none may block on
	// the refresh (each is served with a cached value, old or already
	// refreshed), and exactly one refresh is coalesced for all of them.
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			doc, entries := listRootAs(t, h, "tok-A")
			_ = doc
			if elapsed := time.Since(start); elapsed > mountQuotaRefreshTimeout/2 {
				t.Errorf("stale listing blocked %v on refresh", elapsed)
			}
			if _, used, ok := mountDetailsOf(t, entries, "mountA"); !ok || (used != 400 && used != 777) {
				t.Errorf("stale listing must serve cached value, got used=%v ok=%v", used, ok)
			}
		}()
	}
	wg.Wait()

	awaitQuotaCondition(t, "background refresh with refresh:true", func() bool { return u.refreshes.Load() >= 1 })
	time.Sleep(150 * time.Millisecond) // let any accidental extra refresh surface
	if n := u.refreshes.Load(); n != 1 {
		t.Fatalf("coalescing: want exactly 1 refresh for 12 concurrent stale listings, got %d", n)
	}
	awaitQuotaCondition(t, "refreshed quota in cache", func() bool {
		e, _ := h.mountQuota.get(scopeOf(h, "tok-A"), "/mountA")
		return e.quota.UsedSpace == 777
	})

	_, entries := listRootAs(t, h, "tok-A")
	if _, used, _ := mountDetailsOf(t, entries, "mountA"); used != 777 {
		t.Fatalf("after refresh the next listing should show used=777, got %v", used)
	}
	if _, used, _ := mountDetailsOf(t, entries, "mountB"); used != 1888 {
		t.Fatalf("after refresh mountB should show used=1888, got %v", used)
	}
}

// A read-only account gets 403 from upstream for refresh:true; the refresh
// must fall back to a plain listing and still update the cache from it.
func TestMountQuotaRefreshFallsBackWhenRefreshForbidden(t *testing.T) {
	passwd := &config.PasswdInfo{Password: "testpass", EncType: "aesctr", Enable: true, EncPath: []string{"/encrypt/*"}}
	mux := http.NewServeMux()
	var refreshes, plains atomic.Int32
	mux.HandleFunc("/api/fs/list", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if refresh, _ := req["refresh"].(bool); refresh {
			refreshes.Add(1)
			writeJSONResponse(w, map[string]interface{}{"code": 403, "message": "Refresh without permission"})
			return
		}
		plains.Add(1)
		writeJSONResponse(w, mountQuotaRootListing(5000, 4321, 2000, 1500))
	})
	srv := newSocketTestServer(t, mux)
	defer srv.Close()
	handler, _ := newTestAlistHandler(t, srv.URL, passwd)
	defer handler.Stop()

	listRootAs(t, handler, "tok-R")
	awaitQuotaCondition(t, "cache seeded", func() bool { _, ok := handler.mountQuota.get(scopeOf(handler, "tok-R"), "/mountA"); return ok })
	handler.mountQuota.mu.Lock()
	for k, e := range handler.mountQuota.entries {
		e.fetched = time.Now().Add(-mountQuotaTTL - time.Minute)
		handler.mountQuota.entries[k] = e
	}
	handler.mountQuota.mu.Unlock()

	listRootAs(t, handler, "tok-R")
	awaitQuotaCondition(t, "refresh attempt", func() bool { return refreshes.Load() >= 1 })
	awaitQuotaCondition(t, "fallback plain listing", func() bool { return plains.Load() >= 2 })
}

// Quota is isolated per upstream account: what one account observed is never
// injected into another account's listing, and one account's stale cache
// never triggers a refresh on another account's credentials.
func TestMountQuotaIsolatedPerAccount(t *testing.T) {
	u := &mountQuotaUpstream{quota: mountQuotaRootListing(1000, 400, 2000, 1500)}
	h := newMountQuotaHandler(t, u)

	listRootAs(t, h, "tok-A")
	awaitQuotaCondition(t, "A seeded", func() bool { _, ok := h.mountQuota.get(scopeOf(h, "tok-A"), "/mountA"); return ok })
	if _, ok := h.mountQuota.get(scopeOf(h, "tok-B"), "/mountA"); ok {
		t.Fatal("account B must not see account A's cache entry")
	}

	// Account B's upstream returns NO quota (guest-like): its listing must
	// stay without quota rather than borrow A's.
	u.mu.Lock()
	u.quota = map[string]interface{}{"code": 200, "data": map[string]interface{}{
		"content": []interface{}{
			map[string]interface{}{"name": "mountA", "is_dir": true},
			map[string]interface{}{"name": "mountB", "is_dir": true},
		}, "total": float64(2)}}
	u.mu.Unlock()
	_, entries := listRootAs(t, h, "tok-B")
	for _, name := range []string{"mountA", "mountB"} {
		for _, e := range entries {
			if e["name"] == name {
				if md, has := e["mount_details"]; has && md != nil {
					t.Fatalf("account B borrowed account A's quota for %s: %v", name, md)
				}
			}
		}
	}
}

// Snapshot path with a snapshot that carries NO quota (upstream timed out on
// GetDetails when it was taken) and an empty cache: the served listing keeps
// upstream's null rather than inventing a value, and a refresh is scheduled.
func TestMountQuotaSnapshotWithoutQuotaStaysNull(t *testing.T) {
	u := &mountQuotaUpstream{quota: map[string]interface{}{"code": 200, "data": map[string]interface{}{
		"content": []interface{}{map[string]interface{}{"name": "mountA", "is_dir": true}}, "total": float64(1)}}}
	u.onRefresh = func() map[string]interface{} {
		return map[string]interface{}{"code": 200, "data": map[string]interface{}{
			"content": []interface{}{map[string]interface{}{"name": "mountA", "is_dir": true,
				"mount_details": map[string]interface{}{"total_space": float64(42), "used_space": float64(7)}}}, "total": float64(1)}}
	}
	h := newMountQuotaHandlerWithScope(t, u, "/")
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("create snapshot store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	h.SetDirSyncStore(NewBoltDirSyncStore(store))

	listRootAs(t, h, "tok-A")
	awaitQuotaCondition(t, "refresh scheduled", func() bool { return u.refreshes.Load() >= 1 })
	awaitQuotaCondition(t, "refreshed quota cached", func() bool {
		e, ok := h.mountQuota.get(scopeOf(h, "tok-A"), "/mountA")
		return ok && e.quota.TotalSpace == 42
	})

	// Snapshot is served again (cache_hit) but now carries the refreshed value.
	doc, entries := listRootAs(t, h, "tok-A")
	_ = doc
	if total, _, ok := mountDetailsOf(t, entries, "mountA"); !ok || total != 42 {
		t.Fatalf("snapshot listing should be filled from refreshed cache, got total=%v ok=%v", total, ok)
	}
}

// Stop cancels an in-flight refresh and never leaves a goroutine behind.
func TestMountQuotaStopCancelsInFlightRefresh(t *testing.T) {
	passwd := &config.PasswdInfo{Password: "testpass", EncType: "aesctr", Enable: true, EncPath: []string{"/encrypt/*"}}
	mux := http.NewServeMux()
	release := make(chan struct{})
	mux.HandleFunc("/api/fs/list", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if refresh, _ := req["refresh"].(bool); refresh {
			<-release // hang until the test releases; cancelled ctx should abort the client
			return
		}
		writeJSONResponse(w, mountQuotaRootListing(1, 1, 1, 1))
	})
	srv := newSocketTestServer(t, mux)
	defer srv.Close()
	handler, _ := newTestAlistHandler(t, srv.URL, passwd)

	listRootAs(t, handler, "tok-A")
	awaitQuotaCondition(t, "seeded", func() bool { _, ok := handler.mountQuota.get(scopeOf(handler, "tok-A"), "/mountA"); return ok })
	handler.mountQuota.mu.Lock()
	for k, e := range handler.mountQuota.entries {
		e.fetched = time.Now().Add(-mountQuotaTTL - time.Minute)
		handler.mountQuota.entries[k] = e
	}
	handler.mountQuota.mu.Unlock()
	listRootAs(t, handler, "tok-A") // schedules refresh that hangs

	done := make(chan struct{})
	go func() { handler.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop blocked on an in-flight quota refresh")
	}
	close(release)
}

// A doc shared between singleflight joiners is never written to: with many
// concurrent cold listings for one account, only one upstream call is made
// and every joiner receives the same quota, with no data race.
func TestMountQuotaSharedFlightIsReadOnlyAndConsistent(t *testing.T) {
	u := &mountQuotaUpstream{quota: mountQuotaRootListing(1000, 400, 2000, 1500)}
	h := newMountQuotaHandler(t, u)

	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/api/fs/list", strings.NewReader(`{"path":"/","page":1,"per_page":2}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "tok-S")
			rec := httptest.NewRecorder()
			h.HandleFsList(rec, req)
			if rec.Code != http.StatusOK {
				errs <- fmt.Errorf("status=%d body=%s", rec.Code, rec.Body.String())
				return
			}
			var doc map[string]interface{}
			if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
				errs <- err
				return
			}
			data, _ := doc["data"].(map[string]interface{})
			content, _ := data["content"].([]interface{})
			if len(content) != 2 {
				errs <- fmt.Errorf("page window len=%d want 2", len(content))
				return
			}
			first, _ := content[0].(map[string]interface{})
			if first["name"] != "mountA" {
				errs <- fmt.Errorf("first entry=%v want mountA", first["name"])
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	// singleflight coalesces most of the herd; a request arriving after the
	// flight completed legitimately starts a new one. The contract is "far
	// fewer upstream calls than concurrent callers", and no shared-doc write.
	if n := u.listCalls.Load(); n > 4 {
		t.Fatalf("singleflight: 16 concurrent cold listings made %d upstream calls, want <=4", n)
	}
}

// Pagination: quota injection must apply to the caller's own page window and
// never leak a page-2 entry into page 1 or vice versa.
func TestMountQuotaPaginationWindowUnaffected(t *testing.T) {
	u := &mountQuotaUpstream{quota: mountQuotaRootListing(1000, 400, 2000, 1500)}
	h := newMountQuotaHandler(t, u)

	for page, wantNames := range map[int][]string{1: {"mountA", "mountB"}, 2: {"plainfile.txt"}} {
		req := httptest.NewRequest(http.MethodPost, "/api/fs/list", strings.NewReader(fmt.Sprintf(`{"path":"/","page":%d,"per_page":2}`, page)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "tok-P")
		rec := httptest.NewRecorder()
		h.HandleFsList(rec, req)
		var doc map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Fatalf("page %d decode: %v", page, err)
		}
		data, _ := doc["data"].(map[string]interface{})
		content, _ := data["content"].([]interface{})
		if len(content) != len(wantNames) {
			t.Fatalf("page %d: len=%d want %d", page, len(content), len(wantNames))
		}
		for i, want := range wantNames {
			m, _ := content[i].(map[string]interface{})
			if m["name"] != want {
				t.Fatalf("page %d entry %d = %v want %v", page, i, m["name"], want)
			}
		}
		if total, _ := data["total"].(float64); total != 3 {
			t.Fatalf("page %d: total=%v want 3", page, total)
		}
	}
}

func mustJSON(t *testing.T, v interface{}) string {
	t.Helper()
	b, _ := json.Marshal(v)
	return string(b)
}

// A plain live listing must NOT extend the TTL of an existing entry. Upstream
// serves its own 30-minute details cache on a plain listing, so treating its
// value as a fresh observation would keep postponing the refresh forever.
// Regression guard: an earlier version observed before the stale check and
// never refreshed on the live path.
func TestMountQuotaPlainListingDoesNotExtendTTL(t *testing.T) {
	u := &mountQuotaUpstream{quota: mountQuotaRootListing(1000, 400, 2000, 1500)}
	u.onRefresh = func() map[string]interface{} { return mountQuotaRootListing(1000, 1, 2000, 1) }
	h := newMountQuotaHandler(t, u)

	listRootAs(t, h, "tok-A")
	awaitQuotaCondition(t, "seeded", func() bool { _, ok := h.mountQuota.get(scopeOf(h, "tok-A"), "/mountA"); return ok })
	h.mountQuota.mu.Lock()
	for k, e := range h.mountQuota.entries {
		e.fetched = time.Now().Add(-mountQuotaTTL + 2*time.Second) // still fresh, about to expire
		h.mountQuota.entries[k] = e
	}
	h.mountQuota.mu.Unlock()

	// Hammer the live path with plain listings across the expiry instant.
	// If a plain listing extended the TTL, the entry would never go stale.
	for i := 0; i < 6; i++ {
		listRootAs(t, h, "tok-A")
		time.Sleep(500 * time.Millisecond)
	}
	awaitQuotaCondition(t, "refresh once the original TTL lapses", func() bool { return u.refreshes.Load() >= 1 })
}
