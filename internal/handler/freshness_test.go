package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/proxy"
)

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
