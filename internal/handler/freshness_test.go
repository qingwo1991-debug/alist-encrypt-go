package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/proxy"
)

func TestStrictOldRuleAdmissionRejectsBeforeAuthorizationOrPlaintext(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer upstream.Close()
	cfg := config.LoadFromBaseDir(t.TempDir())
	current := cfg.AlistServerSnapshot()
	current.StrictFreshness = true
	if err := cfg.UpdateAlistServer(current); err != nil {
		t.Fatal(err)
	}
	r := withPlaybackAdmission(httptest.NewRequest(http.MethodGet, "http://local/d/old", nil), cfg)
	oldRule := &config.PasswdInfo{Enable: true, EncType: "aesctr", Password: "old-rule"}
	next := current
	next.ServerHost = "changed.example"
	if err := cfg.UpdateAlistServer(next); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	executeDecryptPlayback(decryptPlaybackRequest{ResponseWriter: w, Request: r, Config: cfg, StreamProxy: proxy.NewStreamProxy(cfg), PasswdInfo: oldRule, FileItem: FileItem{EncryptedPath: "/old"}, TargetURL: upstream.URL, ConsumerScenario: consumerScenarioHTTP})
	if calls.Load() != 0 || w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "revalidation failed") {
		t.Fatalf("authorizedquery_count=%d status=%d body=%q", calls.Load(), w.Code, w.Body.String())
	}
}

func TestPlaybackCredentialOriginRejectsDowngrade(t *testing.T) {
	if samePlaybackOrigin("https://example.test:443/a", "http://example.test:443/b") {
		t.Fatal("HTTPS downgrade kept caller credentials")
	}
	if !samePlaybackOrigin("https://example.test/a", "https://example.test:443/b") {
		t.Fatal("equivalent origin mismatch")
	}
}

func TestStrictMetadataAlwaysQueriesCallerAuthorization(t *testing.T) {
	var authorizedQueries, geometryQueries atomic.Int32
	var revoked atomic.Bool
	var upstream *httptest.Server
	upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/fs/get" {
			authorizedQueries.Add(1)
			if r.Header.Get("Authorization") != "caller" {
				t.Error("caller credentials missing")
			}
			if revoked.Load() {
				fmt.Fprint(w, `{"code":403,"data":null}`)
				return
			}
			fmt.Fprintf(w, `{"code":200,"data":{"raw_url":%q}}`, upstream.URL+"/object?token=fresh")
			return
		}
		geometryQueries.Add(1)
		w.Header().Set("Content-Range", "bytes 0-31/128")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(make([]byte, 32))
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	port, _ := strconv.Atoi(u.Port())
	cfg := &config.Config{AlistServer: config.AlistServer{ServerHost: u.Hostname(), ServerPort: port, StrictFreshness: true}}
	sp := proxy.NewStreamProxy(cfg)
	r := httptest.NewRequest(http.MethodGet, "http://local/d/enc", nil)
	r.Header.Set("Authorization", "caller")
	r = withPlaybackAdmission(r, cfg)
	req := decryptPlaybackRequest{Config: cfg, Request: r, StreamProxy: sp, PasswdInfo: &config.PasswdInfo{Enable: true, EncType: "aesctr"}, FileItem: FileItem{EncryptedPath: "/enc"}}
	for i := 0; i < 2; i++ {
		_, _, _, err := strictPlaybackMetadata(req, r.Header)
		if err != nil {
			t.Fatal(err)
		}
	}
	if authorizedQueries.Load() != 2 || geometryQueries.Load() != 2 {
		t.Fatalf("authorizedquery_count=%d geometry_count=%d", authorizedQueries.Load(), geometryQueries.Load())
	}
	revoked.Store(true)
	if _, _, _, err := strictPlaybackMetadata(req, r.Header); err == nil {
		t.Fatal("revoked caller accepted still-readable signed URL")
	}
	if authorizedQueries.Load() != 3 || geometryQueries.Load() != 2 {
		t.Fatalf("authorizedquery_count=%d geometry_count=%d", authorizedQueries.Load(), geometryQueries.Load())
	}
}
