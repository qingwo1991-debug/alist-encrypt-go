package handler

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/shared/encryptcore"
)

func testEncPasswd() *config.PasswdInfo {
	return &config.PasswdInfo{
		Password:  "testpass",
		EncType:   "aesctr",
		Enable:    true,
		EncName:   true,
		EncSuffix: ".bin",
		EncPath:   []string{"/encrypt/*"},
	}
}

func TestHandleFsRemoveClearsSubtreeCache(t *testing.T) {
	passwd := testEncPasswd()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/fs/remove", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, map[string]interface{}{
			"code":    200,
			"message": "success",
			"data":    map[string]interface{}{},
		})
	})

	srv := newSocketTestServer(t, mux)
	defer srv.Close()

	handler, fileDAO := newTestAlistHandler(t, srv.URL, passwd)

	// A directory and one cached child file.
	fileDAO.SetEncPathMappingWithInfo("/encrypt/dir", "/encrypt/dir", "dir", 0, true)
	fileDAO.SetEncPathMappingWithInfo("/encrypt/dir/movie.mp4", "/encrypt/dir/a.bin", "movie.mp4", 100, false)
	fileDAO.SetEncPathMappingWithInfo("/encrypt/keep.txt", "/encrypt/keep.bin", "keep.txt", 5, false)

	req := httptest.NewRequest(http.MethodPost, "/api/fs/remove", strings.NewReader(`{"dir":"/encrypt","names":["dir"]}`))
	rec := httptest.NewRecorder()
	handler.HandleFsRemove(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	for _, gone := range []string{"/encrypt/dir", "/encrypt/dir/movie.mp4", "/encrypt/dir/a.bin"} {
		if _, ok := fileDAO.Get(gone); ok {
			t.Fatalf("subtree entry %q should be invalidated after dir remove", gone)
		}
	}
	if _, ok := fileDAO.Get("/encrypt/keep.txt"); !ok {
		t.Fatal("unrelated entry should be kept")
	}
}

func TestHandleFsSearchKeepsPlaintextDirName(t *testing.T) {
	passwd := testEncPasswd()
	converter := encryption.NewFileNameConverter(passwd.Password, passwd.EncType, passwd.EncSuffix)

	leafDisplay := "sample_video.mp4"
	leafRaw := converter.ToRealName(leafDisplay)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/fs/list", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]interface{}
		_ = json.Unmarshal(body, &req)
		pathValue, _ := req["path"].(string)
		switch pathValue {
		case "/encrypt":
			writeJSONResponse(w, map[string]interface{}{
				"code":    200,
				"message": "success",
				"data": map[string]interface{}{
					"content": []interface{}{
						map[string]interface{}{"name": "season1", "is_dir": true, "size": float64(0), "type": float64(1)},
					},
					"total": float64(1),
				},
			})
		case "/encrypt/season1":
			writeJSONResponse(w, map[string]interface{}{
				"code":    200,
				"message": "success",
				"data": map[string]interface{}{
					"content": []interface{}{
						map[string]interface{}{"name": leafRaw, "is_dir": false, "size": float64(10), "type": float64(2)},
					},
					"total": float64(1),
				},
			})
		default:
			t.Fatalf("unexpected list path: %s", pathValue)
		}
	})
	mux.HandleFunc("/api/fs/search", func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected upstream /api/fs/search fallback")
	})

	srv := newSocketTestServer(t, mux)
	defer srv.Close()

	handler, _ := newTestAlistHandler(t, srv.URL, passwd)
	req := httptest.NewRequest(http.MethodPost, "/api/fs/search", strings.NewReader(`{"path":"/encrypt","keywords":"sample","scope":2,"page":1,"per_page":20}`))
	rec := httptest.NewRecorder()
	handler.HandleFsSearch(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Data struct {
			Content []map[string]interface{} `json:"content"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Data.Content) != 1 {
		t.Fatalf("content len = %d, want 1", len(resp.Data.Content))
	}
	if got := resp.Data.Content[0]["path"].(string); got != "/encrypt/season1/"+leafDisplay {
		t.Fatalf("path = %q, want plaintext dir name preserved", got)
	}
}

func TestResolveUpstreamNamesBatchUsesSingleList(t *testing.T) {
	passwd := testEncPasswd()
	converter := encryption.NewFileNameConverter(passwd.Password, passwd.EncType, passwd.EncSuffix)

	var listCalls, getCalls int
	mux := http.NewServeMux()
	mux.HandleFunc("/api/fs/list", func(w http.ResponseWriter, r *http.Request) {
		listCalls++
		writeJSONResponse(w, map[string]interface{}{
			"code":    200,
			"message": "success",
			"data": map[string]interface{}{
				"content": []interface{}{
					map[string]interface{}{"name": "plain.txt", "is_dir": false},
					map[string]interface{}{"name": "plaindir", "is_dir": true},
				},
				"total": float64(2),
			},
		})
	})
	mux.HandleFunc("/api/fs/get", func(w http.ResponseWriter, r *http.Request) {
		getCalls++
		writeJSONResponse(w, map[string]interface{}{"code": 500, "message": "object not found", "data": nil})
	})

	srv := newSocketTestServer(t, mux)
	defer srv.Close()

	handler, fileDAO := newTestAlistHandler(t, srv.URL, passwd)
	req := httptest.NewRequest(http.MethodPost, "/api/fs/remove", nil)

	resolved := handler.resolveUpstreamNames(req, "/encrypt", []string{"plain.txt", "plaindir", "ghost.bin.mp4"}, passwd)
	if len(resolved) != 3 {
		t.Fatalf("resolved len = %d, want 3", len(resolved))
	}
	if resolved[0] != "plain.txt" {
		t.Fatalf("plaintext file resolved to %q, want plain.txt", resolved[0])
	}
	if resolved[1] != "plaindir" {
		t.Fatalf("plaintext dir resolved to %q, want plaindir", resolved[1])
	}
	if resolved[2] != converter.ToRealName("ghost.bin.mp4") {
		t.Fatalf("absent name resolved to %q, want encrypted %q", resolved[2], converter.ToRealName("ghost.bin.mp4"))
	}
	if listCalls != 1 {
		t.Fatalf("fs/list calls = %d, want 1 (one listing for the whole batch)", listCalls)
	}
	if getCalls != 0 {
		t.Fatalf("fs/get calls = %d, want 0 (no per-name probes)", getCalls)
	}

	// The listing must also warm the name cache: the plaintext dir keeps its
	// spelling and the undecodable plaintext file gets the orig_ display name,
	// exactly like an fs/list pass would record.
	if info, ok := fileDAO.Get("/encrypt/plaindir"); !ok || info == nil || !info.IsDir {
		t.Fatalf("plaindir mapping missing or wrong: %+v ok=%v", info, ok)
	}
	if _, ok := fileDAO.Get("/encrypt/orig_plain.txt"); !ok {
		t.Fatal("orig_plain.txt display mapping should be warmed from the listing")
	}
}

func TestResolveUpstreamNamesBatchFallsBackToProbes(t *testing.T) {
	passwd := testEncPasswd()

	var listCalls, getCalls int
	mux := http.NewServeMux()
	mux.HandleFunc("/api/fs/list", func(w http.ResponseWriter, r *http.Request) {
		listCalls++
		// Simulate upstream list failure: the batch must degrade to per-name probes.
		writeJSONResponse(w, map[string]interface{}{"code": 500, "message": "boom", "data": nil})
	})
	mux.HandleFunc("/api/fs/get", func(w http.ResponseWriter, r *http.Request) {
		getCalls++
		body, _ := io.ReadAll(r.Body)
		var req map[string]string
		_ = json.Unmarshal(body, &req)
		if req["path"] == "/encrypt/real.txt" {
			writeJSONResponse(w, map[string]interface{}{
				"code": 200, "message": "success",
				"data": map[string]interface{}{"is_dir": false},
			})
			return
		}
		writeJSONResponse(w, map[string]interface{}{"code": 500, "message": "object not found", "data": nil})
	})

	srv := newSocketTestServer(t, mux)
	defer srv.Close()

	handler, _ := newTestAlistHandler(t, srv.URL, passwd)
	req := httptest.NewRequest(http.MethodPost, "/api/fs/remove", nil)

	converter := encryption.NewFileNameConverter(passwd.Password, passwd.EncType, passwd.EncSuffix)
	resolved := handler.resolveUpstreamNames(req, "/encrypt", []string{"real.txt", "ghost.txt"}, passwd)
	if resolved[0] != "real.txt" {
		t.Fatalf("probed plaintext resolved to %q, want real.txt", resolved[0])
	}
	if resolved[1] != converter.ToRealName("ghost.txt") {
		t.Fatalf("absent name resolved to %q, want encrypted", resolved[1])
	}
	if getCalls != 2 {
		t.Fatalf("fs/get calls = %d, want 2 fallback probes", getCalls)
	}
	_ = listCalls
}

func TestDirSyncScanBackoff(t *testing.T) {
	handler, _ := newTestAlistHandler(t, "http://127.0.0.1:1", testEncPasswd())
	now := time.Now()

	if handler.dirSyncScanBackoffActive("/broken", now) {
		t.Fatal("no failure recorded yet, backoff should be inactive")
	}
	handler.dirSyncScanNoteResult("/broken", false, now)
	if !handler.dirSyncScanBackoffActive("/broken", now.Add(time.Minute)) {
		t.Fatal("first failure should activate 30m backoff")
	}
	if handler.dirSyncScanBackoffActive("/broken", now.Add(dirSyncScanBackoffBase+time.Minute)) {
		t.Fatal("backoff should expire after base delay")
	}
	// Second failure doubles the window (30m -> 1h from the second failure).
	secondAt := now.Add(dirSyncScanBackoffBase + time.Minute)
	handler.dirSyncScanNoteResult("/broken", false, secondAt)
	if !handler.dirSyncScanBackoffActive("/broken", secondAt.Add(59*time.Minute)) {
		t.Fatal("second failure should extend backoff to ~1h")
	}
	if handler.dirSyncScanBackoffActive("/broken", secondAt.Add(61*time.Minute)) {
		t.Fatal("second backoff should expire after ~1h")
	}
	// Success clears it.
	handler.dirSyncScanNoteResult("/broken", true, now)
	if handler.dirSyncScanBackoffActive("/broken", now) {
		t.Fatal("success should clear backoff")
	}
}

func TestRememberRecentListEvictsOldest(t *testing.T) {
	handler, _ := newTestAlistHandler(t, "http://127.0.0.1:1", testEncPasswd())
	for i := 0; i < recentListMaxEntries+5; i++ {
		handler.rememberRecentList("/dir"+strconv.Itoa(i), "scope-"+strconv.Itoa(i), nil)
	}
	handler.recentListsMu.Lock()
	defer handler.recentListsMu.Unlock()
	if len(handler.recentLists) != recentListMaxEntries {
		t.Fatalf("recentLists len = %d, want %d", len(handler.recentLists), recentListMaxEntries)
	}
	if _, ok := handler.recentLists["scope-0"]; ok {
		t.Fatal("oldest entry should have been evicted")
	}
	if _, ok := handler.recentLists["scope-"+strconv.Itoa(recentListMaxEntries+4)]; !ok {
		t.Fatal("newest entry should be present")
	}
}

func TestReqRefreshBackoff(t *testing.T) {
	handler, _ := newTestAlistHandler(t, "http://127.0.0.1:1", testEncPasswd())
	now := time.Now()

	if handler.reqRefreshBackoffActive("scope", now) {
		t.Fatal("no failure recorded, backoff should be inactive")
	}
	handler.reqRefreshNoteResult("scope", false, now)
	if !handler.reqRefreshBackoffActive("scope", now.Add(time.Minute)) {
		t.Fatal("first failure should activate 10m backoff")
	}
	if handler.reqRefreshBackoffActive("scope", now.Add(dirSyncReqRefreshBackoffBase+time.Minute)) {
		t.Fatal("backoff should expire after base delay")
	}
	handler.reqRefreshNoteResult("scope", true, now)
	if handler.reqRefreshBackoffActive("scope", now) {
		t.Fatal("success should clear backoff")
	}
}

func TestRecentListHotThreshold(t *testing.T) {
	handler, _ := newTestAlistHandler(t, "http://127.0.0.1:1", testEncPasswd())
	if handler.recentListHot("cold") {
		t.Fatal("unknown scope should not be hot")
	}
	for i := 0; i < recentListHotHits; i++ {
		handler.rememberRecentList("/hot", "hot", nil)
	}
	if !handler.recentListHot("hot") {
		t.Fatal("scope at hit threshold should be hot")
	}
}

func TestForgetRecentListOnAuthFailure(t *testing.T) {
	handler, _ := newTestAlistHandler(t, "http://127.0.0.1:1", testEncPasswd())
	now := time.Now()
	handler.rememberRecentList("/a", "expired", nil)
	handler.rememberRecentList("/b", "transient", nil)
	handler.reqRefreshNoteResult("expired", false, now)

	// Non-auth failures keep the entry so the normal backoff applies.
	handler.forgetRecentListOnAuthFailure("transient", http.StatusBadGateway, 500)
	handler.forgetRecentListOnAuthFailure("expired", http.StatusOK, 0)
	// HTTP 200 carrying alist code 401 is the real-world expired-token shape.
	handler.forgetRecentListOnAuthFailure("expired", http.StatusOK, http.StatusUnauthorized)

	handler.recentListsMu.Lock()
	_, expiredKept := handler.recentLists["expired"]
	_, transientKept := handler.recentLists["transient"]
	handler.recentListsMu.Unlock()
	if expiredKept {
		t.Fatal("entry with rejected credentials should be dropped")
	}
	if !transientKept {
		t.Fatal("non-auth failure must not drop the entry")
	}
	if handler.reqRefreshBackoffActive("expired", now) {
		t.Fatal("dropped entry should not leave a stale backoff record")
	}

	// HTTP-level 401 is handled the same way.
	handler.forgetRecentListOnAuthFailure("transient", http.StatusUnauthorized, 0)
	handler.recentListsMu.Lock()
	defer handler.recentListsMu.Unlock()
	if _, ok := handler.recentLists["transient"]; ok {
		t.Fatal("HTTP 401 should drop the entry")
	}
}

func TestHandleFsMkdirForwardsUnderProtection(t *testing.T) {
	passwd := testEncPasswd()

	var gotPath, gotName string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/fs/mkdir", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]string
		_ = json.Unmarshal(body, &req)
		gotPath, gotName = req["path"], req["name"]
		writeJSONResponse(w, map[string]interface{}{
			"code":    200,
			"message": "success",
			"data":    map[string]interface{}{},
		})
	})

	srv := newSocketTestServer(t, mux)
	defer srv.Close()

	handler, _ := newTestAlistHandler(t, srv.URL, passwd)
	cfg := config.Get()
	cfg.AlistServer.FilenameWriteLimits = map[string]int{"/encrypt": 100}

	req := httptest.NewRequest(http.MethodPost, "/api/fs/mkdir", strings.NewReader(`{"path":"/encrypt","name":"newdir"}`))
	rec := httptest.NewRecorder()
	handler.HandleFsMkdir(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if gotPath != "/encrypt" || gotName != "newdir" {
		t.Fatalf("upstream got path=%q name=%q", gotPath, gotName)
	}

	bad := httptest.NewRequest(http.MethodPost, "/api/fs/mkdir", strings.NewReader(`{"path":"/encrypt","name":".."}`))
	badRec := httptest.NewRecorder()
	handler.HandleFsMkdir(badRec, bad)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("invalid name status = %d, want %d", badRec.Code, http.StatusBadRequest)
	}
}
