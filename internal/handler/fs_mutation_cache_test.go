package handler

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
