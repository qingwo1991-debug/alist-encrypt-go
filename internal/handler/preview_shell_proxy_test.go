package handler

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
)

func TestPreviewShellProxyResponse(t *testing.T) {
	document := `<!doctype html><html><head><script>window.OPENLIST_CONFIG={};window.__dynamic_base__="";</script><script type="module">void 0</script></head><body><div id="root"></div></body></html>`
	t.Run("browser document revalidation", func(t *testing.T) {
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("If-None-Match") != "" || r.Header.Get("If-Modified-Since") != "" {
				t.Error("document retained stale validators")
			}
			if r.Header.Get("Accept-Encoding") != "identity" {
				t.Error("document requested encoded body")
			}
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, document)
		}))
		defer upstream.Close()
		u, err := url.Parse(upstream.URL)
		if err != nil {
			t.Fatal(err)
		}
		cfg := config.DefaultConfig()
		cfg.AlistServer.ServerHost = u.Hostname()
		cfg.AlistServer.ServerPort, _ = strconv.Atoi(u.Port())
		h := newTestProxyHandler(t, cfg)
		r := httptest.NewRequest(http.MethodGet, "http://proxy.test/folder/a.mp4", nil)
		r.Header.Set("Accept", "text/html")
		r.Header.Set("Sec-Fetch-Dest", "document")
		r.Header.Set("Accept-Encoding", "gzip, br")
		r.Header.Set("If-None-Match", `"old"`)
		r.Header.Set("If-Modified-Since", "Tue, 20 Oct 2026 01:00:00 GMT")
		w := httptest.NewRecorder()
		h.HandleProxy(w, r)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), previewShellPrefix+"v1.js") {
			t.Fatal("revalidation did not produce enhanced document")
		}
	})
	var zipped bytes.Buffer
	gz := gzip.NewWriter(&zipped)
	if _, err := io.WriteString(gz, document); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, encoding, cache, disposition string
		compressed, transformed            bool
	}{
		{name: "document", transformed: true},
		{name: "gzip passthrough", encoding: "gzip", compressed: true},
		{name: "no transform", cache: "public, no-transform"},
		{name: "attachment", disposition: `attachment; filename="page.html"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := []byte(document)
			if tc.compressed {
				payload = zipped.Bytes()
			}
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
				w.Header().Set("ETag", `"original"`)
				w.Header().Set("Last-Modified", "Tue, 20 Oct 2026 01:00:00 GMT")
				w.Header().Set("Content-MD5", "original-md5")
				w.Header().Set("Digest", "sha-256=original")
				if tc.encoding != "" {
					w.Header().Set("Content-Encoding", tc.encoding)
				}
				if tc.cache != "" {
					w.Header().Set("Cache-Control", tc.cache)
				}
				if tc.disposition != "" {
					w.Header().Set("Content-Disposition", tc.disposition)
				}
				_, _ = w.Write(payload)
			}))
			defer upstream.Close()
			u, err := url.Parse(upstream.URL)
			if err != nil {
				t.Fatal(err)
			}
			cfg := config.DefaultConfig()
			cfg.AlistServer.ServerHost = u.Hostname()
			cfg.AlistServer.ServerPort, _ = strconv.Atoi(u.Port())
			h := newTestProxyHandler(t, cfg)
			r := httptest.NewRequest(http.MethodGet, "http://proxy.test/", nil)
			r.Header.Set("Accept-Encoding", "gzip")
			w := httptest.NewRecorder()
			h.HandleProxy(w, r)
			if w.Code != http.StatusOK {
				t.Fatalf("status %d", w.Code)
			}
			if tc.transformed {
				if !strings.Contains(w.Body.String(), previewShellPrefix+"v1.js") {
					t.Fatal("missing shell script")
				}
				for _, name := range []string{"Content-Length", "ETag", "Last-Modified", "Content-MD5", "Digest"} {
					if w.Header().Get(name) != "" {
						t.Fatalf("stale integrity header %s", name)
					}
				}
			} else {
				if !bytes.Equal(w.Body.Bytes(), payload) {
					t.Fatal("changed untransformable response")
				}
				if w.Header().Get("ETag") != `"original"` {
					t.Fatal("changed passthrough validators")
				}
			}
		})
	}
}
