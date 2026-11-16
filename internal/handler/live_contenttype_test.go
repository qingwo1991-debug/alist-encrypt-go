package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
)

// Synthetic dirsync callers build requests carrying only auth headers; the
// upstream fs/list endpoint must still receive Content-Type: application/json
// or it silently binds an empty body and returns the root listing.
func TestLiveFsListResponseForcesJSONContentType(t *testing.T) {
	var gotCT string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/fs/list", func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		writeJSONResponse(w, map[string]interface{}{
			"code": 200, "message": "success",
			"data": map[string]interface{}{"content": []interface{}{}, "total": float64(0)},
		})
	})
	srv := newSocketTestServer(t, mux)
	defer srv.Close()

	h, _ := newTestAlistHandler(t, srv.URL, &config.PasswdInfo{
		Password: "p", EncType: "aesctr", Enable: true, EncName: true,
		EncPath: []string{"/cloud/encrypt/*"},
	})
	req := httptest.NewRequest(http.MethodPost, "http://dirsync.local/api/fs/list", nil)
	req.Header.Set("Authorization", "Bearer tok")
	if _, _, _, _, err := h.liveFsListResponse(req, []byte(`{"path":"/cloud/encrypt","page":1,"per_page":10}`), "/cloud/encrypt", false); err != nil {
		t.Fatalf("liveFsListResponse: %v", err)
	}
	if gotCT != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", gotCT)
	}
}
