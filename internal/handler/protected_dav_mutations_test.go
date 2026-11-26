package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/proxy"
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
	for _, method := range []string{"PROPPATCH", "LOCK", "UNLOCK", "PATCH", "POST"} {
		req := httptest.NewRequest(method, "http://example.com/dav/mount/protected/new", nil)
		rec := httptest.NewRecorder()
		h.Handle(rec, req)
		if rec.Code != 501 {
			t.Fatalf("extension %s bypassed protection: %d", method, rec.Code)
		}
	}
	// MKCOL creates a directory; directory names are never filename-encrypted,
	// so it is refused only on malformed syntax (checked separately below),
	// never by the protected-mutation guard.
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

func TestProtectedMutationDAVMkcolPassesThrough(t *testing.T) {
	// MKCOL is directory creation: no filename is encrypted and no mapping is
	// written, so it must reach upstream even inside a protected scope, exactly
	// like /api/fs/mkdir. Only malformed syntax is refused locally.
	var calls atomic.Int32
	var gotPath, gotMethod string
	upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		gotPath, gotMethod = r.URL.Path, r.Method
		w.WriteHeader(http.StatusCreated)
	}))
	defer upstream.Close()

	cfg := config.DefaultConfig()
	u, _ := url.Parse(upstream.URL)
	cfg.AlistServer.ServerHost, cfg.AlistServer.ServerPort = u.Hostname(), 0
	cfg.AlistServer.ServerPort, _ = strconv.Atoi(u.Port())
	cfg.AlistServer.FilenameWriteLimits = map[string]int{"/mount/protected": 100}
	h := NewWebDAVHandler(cfg, proxy.NewStreamProxy(cfg), nil, nil, nil, nil, nil)
	defer h.Stop()

	req := httptest.NewRequest("MKCOL", "http://example.com/dav/mount/protected/new%20dir", nil)
	rec := httptest.NewRecorder()
	h.Handle(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("MKCOL inside protected scope status=%d body=%s", rec.Code, rec.Body.String())
	}
	if calls.Load() != 1 || gotMethod != "MKCOL" || gotPath != "/dav/mount/protected/new dir" {
		t.Fatalf("upstream calls=%d method=%q path=%q", calls.Load(), gotMethod, gotPath)
	}

	// Malformed target: refused locally with 400, upstream untouched.
	for _, target := range []string{
		"/dav/mount/protected/",   // trailing slash: ambiguous spelling
		"/dav/mount/protected/..", // parent escape
	} {
		req := httptest.NewRequest("MKCOL", "http://example.com"+target, nil)
		body := &mutationUnreadBody{}
		req.Body = body
		rec := httptest.NewRecorder()
		h.Handle(rec, req)
		if rec.Code != http.StatusBadRequest || calls.Load() != 1 {
			t.Fatalf("malformed MKCOL %q status=%d calls=%d body=%s", target, rec.Code, calls.Load(), rec.Body.String())
		}
		if body.reads != 0 {
			t.Fatalf("malformed MKCOL %q body read %d times", target, body.reads)
		}
	}

	// Nested target: a valid single-segment basename under an existing parent;
	// existence of the parent is upstream's decision, the proxy just forwards.
	nested := httptest.NewRequest("MKCOL", "http://example.com/dav/mount/protected/a/b", nil)
	nestedRec := httptest.NewRecorder()
	h.Handle(nestedRec, nested)
	if nestedRec.Code != http.StatusCreated || calls.Load() != 2 {
		t.Fatalf("nested MKCOL status=%d calls=%d body=%s", nestedRec.Code, calls.Load(), nestedRec.Body.String())
	}
}
