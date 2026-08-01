package encrypt

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/OpenListTeam/OpenList/v4/public"
)

func TestHandleEncWebUIIndexRedirectsToPublic(t *testing.T) {
	p := &ProxyServer{}

	req := httptest.NewRequest(http.MethodGet, "/index", nil)
	rr := httptest.NewRecorder()
	p.handleEncWebUIIndex(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d, want %d", rr.Code, http.StatusFound)
	}
	if got := rr.Header().Get("Location"); got != "/public/index.html" {
		t.Fatalf("location=%q, want %q", got, "/public/index.html")
	}
}

// encWebUIPublicHandler mirrors the route registration in proxy_server.go so
// tests exercise the same StripPrefix + FileServer composition.
func encWebUIPublicHandler(t *testing.T) http.Handler {
	t.Helper()
	handler := encWebUIFileServer()
	if handler == nil {
		t.Fatal("expected non-nil handler when dist/enc/index.html is embedded")
	}
	return http.StripPrefix("/public/", handler)
}

func TestEncWebUIFileServerServesIndexHTML(t *testing.T) {
	h := encWebUIPublicHandler(t)

	// Requesting /public/ should serve the enc-webui index.html (the file
	// server resolves the directory to index.html automatically).
	req := httptest.NewRequest(http.MethodGet, "/public/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want %d", rr.Code, http.StatusOK)
	}
	if rr.Body.Len() == 0 {
		t.Fatal("expected non-empty index.html body")
	}
}

func TestEncWebUIFileServerServesStaticAsset(t *testing.T) {
	h := encWebUIPublicHandler(t)

	// Find a real asset path embedded under dist/enc/static.
	sub, err := fs.Sub(public.Public, "dist/enc")
	if err != nil {
		t.Fatalf("fs.Sub dist/enc: %v", err)
	}
	var assetPath string
	_ = fs.WalkDir(sub, "static", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		assetPath = path
		return fs.SkipAll
	})
	if assetPath == "" {
		t.Skip("no static asset found under dist/enc/static")
	}

	req := httptest.NewRequest(http.MethodGet, "/public/"+assetPath, nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d for /public/%s, want %d", rr.Code, assetPath, http.StatusOK)
	}
	if rr.Body.Len() == 0 {
		t.Fatalf("empty body for /public/%s", assetPath)
	}
}
