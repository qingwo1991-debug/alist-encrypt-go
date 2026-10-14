package handler

import (
	"net/http/httptest"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
)

func TestProtectedMutationDAVRejectsBeforeResolution(t *testing.T) {
	// No repositories or HTTP clients: unsafe operations must stop before any
	// source lookup, filename conversion, or upstream dispatch.
	h := &WebDAVHandler{cfg: &config.Config{AlistServer: config.AlistServer{FilenameWriteLimits: map[string]int{"/mount/protected": 100}}}}
	defer h.Stop()
	cases := []struct {
		source, destination string
		status              int
	}{
		{"/mount/protected/a", "http://example.com/dav/outside/a", 501},
		{"/outside/a", "/dav/mount/protected/a", 501},
		{"/mount", "/dav/renamed", 501},
		{"/outside", "/dav/mount", 501},
		{"/mount/protected/a", "/dav/outside", 501},
		{"/outside/a", "/dav/%6dount/protected/a", 501},
		{"/mount/protected/a", "", 400},
		{"/mount/protected/a", "http://evil.example/dav/outside/a", 400},
		{"/mount/protected/a", "/other/a", 400},
		{"/mount/protected/a", "/dav/outside?query=1", 400},
		{"/mount/protected/a", "http://user@example.com/dav/outside", 400},
		{"/mount/protected/a", "/dav/outside#fragment", 400},
	}
	for _, method := range []string{"MKCOL", "PROPPATCH", "LOCK", "UNLOCK", "PATCH", "POST"} {
		req := httptest.NewRequest(method, "http://example.com/dav/mount/protected/new", nil)
		rec := httptest.NewRecorder()
		h.Handle(rec, req)
		if rec.Code != 501 {
			t.Fatalf("extension %s bypassed protection: %d", method, rec.Code)
		}
	}
	for _, method := range []string{"MOVE", "COPY"} {
		for _, tc := range cases {
			t.Run(method+tc.source+tc.destination, func(t *testing.T) {
				req := httptest.NewRequest(method, "http://example.com/dav"+tc.source, nil)
				req.Header.Set("Destination", tc.destination)
				rec := httptest.NewRecorder()
				h.handleMoveOrCopy(rec, req, tc.source, method)
				if rec.Code != tc.status {
					t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
				}
			})
		}
	}
}
