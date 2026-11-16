package handler

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
)

// Upstream OpenList's WebDAV DELETE returns 500 for some drivers while
// /api/fs/remove works. handleDelete must fall back to the JSON API so
// clients see a successful delete.
func TestHandleDeleteFallsBackToAPIOnUpstream500(t *testing.T) {
	var removedDir, removedName string
	mux := http.NewServeMux()
	mux.HandleFunc("/dav/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, map[string]interface{}{
			"code": 200, "message": "success",
			"data": map[string]interface{}{"token": "jwt-token"},
		})
	})
	mux.HandleFunc("/api/fs/remove", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload struct {
			Dir   string   `json:"dir"`
			Names []string `json:"names"`
		}
		_ = json.Unmarshal(body, &payload)
		removedDir, removedName = payload.Dir, strings.Join(payload.Names, ",")
		// /api/fs/remove requires the upstream JWT, not Basic auth.
		if r.Header.Get("Authorization") != "jwt-token" {
			writeJSONResponse(w, map[string]interface{}{"code": 401, "message": "unauthorized", "data": nil})
			return
		}
		writeJSONResponse(w, map[string]interface{}{"code": 200, "message": "success", "data": nil})
	})
	mux.HandleFunc("/api/fs/get", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, map[string]interface{}{"code": 404, "message": "not found", "data": nil})
	})
	srv := newSocketTestServer(t, mux)
	defer srv.Close()

	ep := &config.PasswdInfo{
		Password: "pw", EncType: "aesctr", Enable: true, EncName: true,
		EncPath: []string{"/cloud/encrypt/*"},
	}
	ah, d := newTestAlistHandler(t, srv.URL, ep)
	t.Cleanup(ah.Stop)
	h := &WebDAVHandler{cfg: ah.cfg, fileDAO: d, passwdDAO: ah.passwdDAO, stdClient: srv.Client()}

	req := httptest.NewRequest(http.MethodDelete, "http://proxy/dav/cloud/encrypt/movie.mp4", nil)
	req.Header.Set("Authorization", "Basic YWRtaW46c2VjcmV0") // admin:secret
	rec := httptest.NewRecorder()
	h.Handle(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if removedDir != "/cloud/encrypt" || removedName == "" {
		t.Fatalf("fs/remove got dir=%q names=%q", removedDir, removedName)
	}
	if removedName == "movie.mp4" || removedName == "" {
		t.Fatalf("expected resolved upstream name, got %q", removedName)
	}
}
