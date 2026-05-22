package handler

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/encryption"
	"github.com/alist-encrypt-go/internal/proxy"
	"github.com/alist-encrypt-go/internal/storage"
)

func TestHandleFsListSnapshotPreservesItemPaths(t *testing.T) {
	passwd := &config.PasswdInfo{
		Password:  "testpass",
		EncType:   "aesctr",
		Enable:    true,
		EncName:   true,
		EncSuffix: "",
		EncPath:   []string{"/移动云盘156/encrypt/*"},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/fs/list", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, map[string]interface{}{
			"code":    200,
			"message": "success",
			"data": map[string]interface{}{
				"content": []interface{}{
					map[string]interface{}{
						"name":   "season1",
						"path":   "/移动云盘156/encrypt/season1",
						"is_dir": true,
						"size":   float64(0),
						"type":   float64(1),
					},
				},
				"total": float64(1),
			},
		})
	})

	srv := newSocketTestServer(t, mux)
	defer srv.Close()

	handler, _ := newTestAlistHandler(t, srv.URL, passwd)
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("create snapshot store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	handler.SetDirSyncStore(NewBoltDirSyncStore(store))

	reqBody := `{"path":"/移动云盘156/encrypt","page":1,"per_page":1000}`
	req1 := httptest.NewRequest(http.MethodPost, "/api/fs/list", strings.NewReader(reqBody))
	req1.Header.Set("Content-Type", "application/json")
	rec1 := httptest.NewRecorder()
	handler.HandleFsList(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first status=%d body=%s", rec1.Code, rec1.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodPost, "/api/fs/list", strings.NewReader(reqBody))
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	handler.HandleFsList(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("second status=%d body=%s", rec2.Code, rec2.Body.String())
	}

	var resp struct {
		Data struct {
			Content []map[string]interface{} `json:"content"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal snapshot response: %v", err)
	}
	if len(resp.Data.Content) != 1 {
		t.Fatalf("content len=%d, want 1", len(resp.Data.Content))
	}
	if got, _ := resp.Data.Content[0]["path"].(string); got != "/移动云盘156/encrypt/season1" {
		t.Fatalf("path=%q, want preserved path", got)
	}
}

func newTestAlistHandler(t *testing.T, serverURL string, passwd *config.PasswdInfo) (*AlistHandler, *dao.FileDAO) {
	t.Helper()

	cfg := config.Get()
	original := cfg.AlistServer
	t.Cleanup(func() {
		cfg.AlistServer = original
	})

	parsed, err := url.Parse(serverURL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatalf("parse server port: %v", err)
	}

	cfg.AlistServer.ServerHost = parsed.Hostname()
	cfg.AlistServer.ServerPort = port
	cfg.AlistServer.HTTPS = false
	cfg.AlistServer.PasswdList = []config.PasswdInfo{*passwd}

	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})
	fileDAO := dao.NewFileDAO(store)
	passwdDAO := dao.NewPasswdDAO(store)
	streamProxy := proxy.NewStreamProxy(cfg)
	proxyHandler := NewProxyHandler(cfg, streamProxy, fileDAO, passwdDAO, nil, nil)
	alistHandler := NewAlistHandler(cfg, streamProxy, fileDAO, passwdDAO, proxyHandler, nil, nil)

	return alistHandler, fileDAO
}

func writeJSONResponse(w http.ResponseWriter, payload map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

func TestHandleFsSearchRecursiveDecryptsDisplayNames(t *testing.T) {
	passwd := &config.PasswdInfo{
		Password:  "testpass",
		EncType:   "aesctr",
		Enable:    true,
		EncName:   true,
		EncSuffix: "",
		EncPath:   []string{"/156天翼云盘个人/encrypt/*"},
	}
	converter := encryption.NewFileNameConverter(passwd.Password, passwd.EncType, passwd.EncSuffix)

	rootDirRaw := converter.ToRealName("season1")
	leafDisplay := "hhd800.com@420HOI-291.mp4"
	leafRaw := converter.ToRealName(leafDisplay)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/fs/list", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]interface{}
		_ = json.Unmarshal(body, &req)

		pathValue, _ := req["path"].(string)
		switch pathValue {
		case "/156天翼云盘个人/encrypt":
			writeJSONResponse(w, map[string]interface{}{
				"code":    200,
				"message": "success",
				"data": map[string]interface{}{
					"content": []interface{}{
						map[string]interface{}{
							"name":    rootDirRaw,
							"is_dir":  true,
							"size":    float64(0),
							"type":    float64(1),
							"parent":  "/156天翼云盘个人/encrypt",
							"write":   true,
							"thumb":   "",
							"sign":    "",
							"raw_url": "",
						},
						map[string]interface{}{
							"name":   "unrelated.txt",
							"is_dir": false,
							"size":   float64(1),
							"type":   float64(0),
						},
					},
					"total": float64(2),
				},
			})
		case "/156天翼云盘个人/encrypt/" + rootDirRaw:
			writeJSONResponse(w, map[string]interface{}{
				"code":    200,
				"message": "success",
				"data": map[string]interface{}{
					"content": []interface{}{
						map[string]interface{}{
							"name":   leafRaw,
							"is_dir": false,
							"size":   float64(222),
							"type":   float64(2),
							"sign":   "sig",
						},
					},
					"total": float64(1),
				},
			})
		default:
			t.Fatalf("unexpected list path: %s", pathValue)
		}
	})
	mux.HandleFunc("/api/fs/search", func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected upstream /api/fs/search fallback: %s", r.URL.String())
	})

	srv := newSocketTestServer(t, mux)
	defer srv.Close()

	handler, _ := newTestAlistHandler(t, srv.URL, passwd)

	req := httptest.NewRequest(http.MethodPost, "/api/fs/search", strings.NewReader(`{"parent":"/156天翼云盘个人","path":"/156天翼云盘个人/encrypt","keywords":"hhd800","scope":2,"page":1,"per_page":20}`))
	rec := httptest.NewRecorder()
	handler.HandleFsSearch(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var resp struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Content []map[string]interface{} `json:"content"`
			Total   int                      `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	if resp.Code != 200 {
		t.Fatalf("code = %d, want 200", resp.Code)
	}
	if resp.Data.Total != 1 {
		t.Fatalf("total = %d, want 1", resp.Data.Total)
	}
	if len(resp.Data.Content) != 1 {
		t.Fatalf("content len = %d, want 1", len(resp.Data.Content))
	}
	if got := resp.Data.Content[0]["name"].(string); got != leafDisplay {
		t.Fatalf("name = %q, want %q", got, leafDisplay)
	}
	if got := resp.Data.Content[0]["path"].(string); got != "/156天翼云盘个人/encrypt/season1/"+leafDisplay {
		t.Fatalf("path = %q, want display path", got)
	}
}

func TestHandleFsSearchScopeZeroDoesNotRecurse(t *testing.T) {
	passwd := &config.PasswdInfo{
		Password:  "testpass",
		EncType:   "aesctr",
		Enable:    true,
		EncName:   true,
		EncSuffix: "",
		EncPath:   []string{"/156天翼云盘个人/encrypt/*"},
	}
	converter := encryption.NewFileNameConverter(passwd.Password, passwd.EncType, passwd.EncSuffix)
	rootDirRaw := converter.ToRealName("season1")
	leafDisplay := "hhd800.com@420HOI-291.mp4"
	leafRaw := converter.ToRealName(leafDisplay)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/fs/list", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]interface{}
		_ = json.Unmarshal(body, &req)

		pathValue, _ := req["path"].(string)
		switch pathValue {
		case "/156天翼云盘个人/encrypt":
			writeJSONResponse(w, map[string]interface{}{
				"code":    200,
				"message": "success",
				"data": map[string]interface{}{
					"content": []interface{}{
						map[string]interface{}{
							"name":   rootDirRaw,
							"is_dir": true,
							"size":   float64(0),
							"type":   float64(1),
						},
					},
					"total": float64(1),
				},
			})
		case "/156天翼云盘个人/encrypt/" + rootDirRaw:
			writeJSONResponse(w, map[string]interface{}{
				"code":    200,
				"message": "success",
				"data": map[string]interface{}{
					"content": []interface{}{
						map[string]interface{}{
							"name":   leafRaw,
							"is_dir": false,
							"size":   float64(222),
							"type":   float64(2),
						},
					},
					"total": float64(1),
				},
			})
		default:
			t.Fatalf("unexpected list path: %s", pathValue)
		}
	})

	srv := newSocketTestServer(t, mux)
	defer srv.Close()

	handler, _ := newTestAlistHandler(t, srv.URL, passwd)

	req := httptest.NewRequest(http.MethodPost, "/api/fs/search", strings.NewReader(`{"parent":"/156天翼云盘个人/encrypt","keywords":"hhd800","scope":0,"page":1,"per_page":20}`))
	rec := httptest.NewRecorder()
	handler.HandleFsSearch(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var resp struct {
		Data struct {
			Total int `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Data.Total != 0 {
		t.Fatalf("total = %d, want 0 when scope=0", resp.Data.Total)
	}
}

func TestHandleFsSearchRootSearchesEncryptedRoots(t *testing.T) {
	passwd := &config.PasswdInfo{
		Password:  "testpass",
		EncType:   "aesctr",
		Enable:    true,
		EncName:   true,
		EncSuffix: "",
		EncPath:   []string{"/156天翼云盘个人/encrypt/*"},
	}
	converter := encryption.NewFileNameConverter(passwd.Password, passwd.EncType, passwd.EncSuffix)
	leafDisplay := "hhd800.com@420HOI-291.mp4"
	leafRaw := converter.ToRealName(leafDisplay)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/fs/list", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]interface{}
		_ = json.Unmarshal(body, &req)

		pathValue, _ := req["path"].(string)
		if pathValue != "/156天翼云盘个人/encrypt" {
			t.Fatalf("unexpected list path: %s", pathValue)
		}

		writeJSONResponse(w, map[string]interface{}{
			"code":    200,
			"message": "success",
			"data": map[string]interface{}{
				"content": []interface{}{
					map[string]interface{}{
						"name":   leafRaw,
						"is_dir": false,
						"size":   float64(222),
						"type":   float64(2),
					},
				},
				"total": float64(1),
			},
		})
	})

	srv := newSocketTestServer(t, mux)
	defer srv.Close()

	handler, _ := newTestAlistHandler(t, srv.URL, passwd)

	req := httptest.NewRequest(http.MethodPost, "/api/fs/search", strings.NewReader(`{"parent":"/","keywords":"hhd","scope":0,"page":1,"per_page":100,"password":""}`))
	rec := httptest.NewRecorder()
	handler.HandleFsSearch(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var resp struct {
		Data struct {
			Total   int                      `json:"total"`
			Content []map[string]interface{} `json:"content"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Data.Total != 1 {
		t.Fatalf("total = %d, want 1", resp.Data.Total)
	}
	if len(resp.Data.Content) != 1 {
		t.Fatalf("content len = %d, want 1", len(resp.Data.Content))
	}
	if got := resp.Data.Content[0]["name"].(string); got != leafDisplay {
		t.Fatalf("name = %q, want %q", got, leafDisplay)
	}
}

func TestResolveRemoveNameAvoidsDoubleEncryption(t *testing.T) {
	passwd := &config.PasswdInfo{
		Password:  "testpass",
		EncType:   "aesctr",
		Enable:    true,
		EncName:   true,
		EncSuffix: "",
		EncPath:   []string{"/encrypt/*"},
	}
	converter := encryption.NewFileNameConverter(passwd.Password, passwd.EncType, passwd.EncSuffix)
	plain := "hhd800.com@420HOI-291.mp4"
	encoded := converter.ToRealName(plain)

	var capturedRemoveBody []byte
	mux := http.NewServeMux()
	mux.HandleFunc("/api/fs/list", func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected list call")
	})
	mux.HandleFunc("/api/fs/remove", func(w http.ResponseWriter, r *http.Request) {
		var err error
		capturedRemoveBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read remove body: %v", err)
		}
		writeJSONResponse(w, map[string]interface{}{
			"code":    200,
			"message": "success",
			"data":    map[string]interface{}{},
		})
	})

	srv := newSocketTestServer(t, mux)
	defer srv.Close()

	handler, fileDAO := newTestAlistHandler(t, srv.URL, passwd)
	displayPath := "/encrypt/" + plain
	fileDAO.SetEncPathMapping(displayPath, "/encrypt/"+encoded)

	if got := handler.resolveRemoveName("/encrypt", encoded, passwd); got != encoded {
		t.Fatalf("resolveRemoveName double-encoded raw filename: got %q want %q", got, encoded)
	}

	body := `{"dir":"/encrypt","names":["` + plain + `"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/fs/remove", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.HandleFsRemove(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	// Validate the upstream request indirectly by round-tripping the cached mapping.
	resolved := handler.resolveRemoveName("/encrypt", plain, passwd)
	if resolved != encoded {
		t.Fatalf("resolveRemoveName(display) = %q, want %q", resolved, encoded)
	}

	var captured struct {
		Dir   string   `json:"dir"`
		Names []string `json:"names"`
	}
	if err := json.Unmarshal(capturedRemoveBody, &captured); err != nil {
		t.Fatalf("decode captured remove body: %v", err)
	}
	if captured.Dir != "/encrypt" {
		t.Fatalf("captured dir = %q, want /encrypt", captured.Dir)
	}
	if len(captured.Names) != 1 {
		t.Fatalf("captured names len = %d, want 1", len(captured.Names))
	}
	if captured.Names[0] != encoded {
		t.Fatalf("captured name = %q, want %q", captured.Names[0], encoded)
	}
}

func TestResolveRemoveNameStripsOriginalPrefix(t *testing.T) {
	passwd := &config.PasswdInfo{
		Password:  "testpass",
		EncType:   "aesctr",
		Enable:    true,
		EncName:   true,
		EncSuffix: "",
		EncPath:   []string{"/encrypt/*"},
	}
	plain := "orig_cGlHlVLp5VOWIUjGG3H~5GU6cmRIOMtF5CjkaCeYcgcyI9t67(1).mkv"
	want := strings.TrimPrefix(plain, encryption.OrigPrefix)

	var capturedRemoveBody []byte
	mux := http.NewServeMux()
	mux.HandleFunc("/api/fs/remove", func(w http.ResponseWriter, r *http.Request) {
		var err error
		capturedRemoveBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read remove body: %v", err)
		}
		writeJSONResponse(w, map[string]interface{}{
			"code":    200,
			"message": "success",
			"data":    map[string]interface{}{},
		})
	})

	srv := newSocketTestServer(t, mux)
	defer srv.Close()

	handler, _ := newTestAlistHandler(t, srv.URL, passwd)

	req := httptest.NewRequest(http.MethodPost, "/api/fs/remove", strings.NewReader(`{"dir":"/encrypt","names":["`+plain+`"]}`))
	rec := httptest.NewRecorder()
	handler.HandleFsRemove(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var captured struct {
		Dir   string   `json:"dir"`
		Names []string `json:"names"`
	}
	if err := json.Unmarshal(capturedRemoveBody, &captured); err != nil {
		t.Fatalf("decode captured body: %v", err)
	}
	if len(captured.Names) != 1 {
		t.Fatalf("captured names len = %d, want 1", len(captured.Names))
	}
	if captured.Names[0] != want {
		t.Fatalf("captured name = %q, want %q", captured.Names[0], want)
	}
}

func TestHandleFsSearchDoesNotForwardAuthHeaderUpstream(t *testing.T) {
	passwd := &config.PasswdInfo{
		Password:  "testpass",
		EncType:   "aesctr",
		Enable:    true,
		EncName:   true,
		EncSuffix: "",
		EncPath:   []string{"/encrypt/*"},
	}
	converter := encryption.NewFileNameConverter(passwd.Password, passwd.EncType, passwd.EncSuffix)
	leafDisplay := "hhd800.com@420HOI-291.mp4"
	leafRaw := converter.ToRealName(leafDisplay)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/fs/list", func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); auth != "" {
			t.Fatalf("upstream received Authorization header: %s", auth)
		}
		if auth := r.Header.Get("Authorizetoken"); auth != "" {
			t.Fatalf("upstream received Authorizetoken header: %s", auth)
		}
		if auth := r.Header.Get("X-User-Token"); auth != "" {
			t.Fatalf("upstream received X-User-Token header: %s", auth)
		}

		writeJSONResponse(w, map[string]interface{}{
			"code":    200,
			"message": "success",
			"data": map[string]interface{}{
				"content": []interface{}{
					map[string]interface{}{
						"name":   leafRaw,
						"is_dir": false,
						"size":   float64(222),
						"type":   float64(2),
					},
				},
				"total": float64(1),
			},
		})
	})

	srv := newSocketTestServer(t, mux)
	defer srv.Close()

	handler, _ := newTestAlistHandler(t, srv.URL, passwd)
	req := httptest.NewRequest(http.MethodPost, "/api/fs/search", strings.NewReader(`{"parent":"/","keywords":"hhd","scope":0,"page":1,"per_page":100,"password":""}`))
	req.Header.Set("Authorization", "Bearer frontend-token")
	req.Header.Set("Authorizetoken", "frontend-token")
	rec := httptest.NewRecorder()
	handler.HandleFsSearch(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
}
