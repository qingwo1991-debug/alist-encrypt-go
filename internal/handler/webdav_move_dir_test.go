package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/storage"
	"github.com/alist-encrypt-go/shared/encryptcore"
)

func newWebDAVMoveTestHandler(t *testing.T, origin string) (*WebDAVHandler, *dao.FileDAO) {
	t.Helper()
	cfg := config.LoadFromBaseDir(t.TempDir())
	alist := cfg.AlistServerSnapshot()
	u, err := url.Parse(origin)
	if err != nil {
		t.Fatal(err)
	}
	alist.ServerHost = u.Hostname()
	alist.ServerPort, _ = strconv.Atoi(u.Port())
	alist.HTTPS = false
	alist.PasswdList = []config.PasswdInfo{{
		Enable:    true,
		Password:  "testpass",
		EncType:   "aesctr",
		EncName:   true,
		EncSuffix: ".bin",
		EncPath:   []string{"/*"},
	}}
	if err := cfg.UpdateAlistServer(alist); err != nil {
		t.Fatal(err)
	}
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	files := dao.NewFileDAO(store, cfg)
	keys := dao.NewPasswdDAO(store, cfg)
	h := NewWebDAVHandler(cfg, nil, files, keys, nil, nil, nil)
	t.Cleanup(func() {
		h.Stop()
		files.Stop()
		keys.Stop()
		_ = store.Close()
	})
	return h, files
}

func TestWebDAVMoveKeepsDirectoryDestinationName(t *testing.T) {
	var capturedDestination, capturedPath string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/fs/get", func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("cached directory MOVE must not probe fs/get")
	})
	mux.HandleFunc("/dav/encrypt/season1", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "MOVE" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		capturedDestination = r.Header.Get("Destination")
		capturedPath = r.URL.Path
		w.WriteHeader(http.StatusCreated)
	})

	srv := newSocketTestServer(t, mux)
	defer srv.Close()

	h, files := newWebDAVMoveTestHandler(t, srv.URL)
	files.SetEncPathMappingWithInfo("/encrypt/season1", "/encrypt/season1", "season1", 0, true)

	req := httptest.NewRequest("MOVE", "/dav/encrypt/season1", nil)
	req.Header.Set("Destination", "http://example.com/dav/encrypt/season2")
	rec := httptest.NewRecorder()
	h.Handle(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	if capturedPath != "/dav/encrypt/season1" {
		t.Fatalf("upstream path = %q, want /dav/encrypt/season1", capturedPath)
	}
	if !strings.HasSuffix(capturedDestination, "/dav/encrypt/season2") {
		t.Fatalf("destination = %q, want suffix /dav/encrypt/season2", capturedDestination)
	}
}

func TestWebDAVMoveStillEncryptsFileDestinationName(t *testing.T) {
	var capturedDestination string
	converter := encryption.NewFileNameConverter("testpass", "aesctr", ".bin")
	wantName := converter.ToRealName("renamed.mp4")

	mux := http.NewServeMux()
	mux.HandleFunc("/api/fs/get", func(w http.ResponseWriter, r *http.Request) {
		// Source is a file: the is-dir probe may run, answer not-a-directory.
		writeJSONResponse(w, map[string]interface{}{"code": 500, "message": "object not found", "data": nil})
	})
	mux.HandleFunc("/dav/encrypt/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "MOVE" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		capturedDestination = r.Header.Get("Destination")
		w.WriteHeader(http.StatusCreated)
	})

	srv := newSocketTestServer(t, mux)
	defer srv.Close()

	h, files := newWebDAVMoveTestHandler(t, srv.URL)
	encName := converter.ToRealName("movie.mp4")
	files.SetEncPathMappingWithInfo("/encrypt/movie.mp4", "/encrypt/"+encName, "movie.mp4", 100, false)

	req := httptest.NewRequest("MOVE", "/dav/encrypt/movie.mp4", nil)
	req.Header.Set("Destination", "http://example.com/dav/encrypt/renamed.mp4")
	rec := httptest.NewRecorder()
	h.Handle(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	if !strings.HasSuffix(capturedDestination, "/dav/encrypt/"+wantName) {
		t.Fatalf("destination = %q, want suffix /dav/encrypt/%s", capturedDestination, wantName)
	}
}
