package encrypt

import (
	"bytes"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Count only requests which actually serve the representation. Redirect hops
// are recorded separately, so an inspection is never confused with a GET that
// dispatches the plaintext stream (even for the direct cold GET).
type confirmedWebDAVUpstream struct {
	mu       sync.Mutex
	fixture  []byte
	etag     string
	redirect bool
	revoked  bool
	requests []confirmedWebDAVRequest
}

type confirmedWebDAVRequest struct {
	method, rangeHeader, auth string
	redirect                  bool
}

func (u *confirmedWebDAVUpstream) serveHTTP(w http.ResponseWriter, r *http.Request) {
	u.mu.Lock()
	redirect := u.redirect && strings.HasPrefix(r.URL.Path, "/dav/")
	u.requests = append(u.requests, confirmedWebDAVRequest{r.Method, r.Header.Get("Range"), r.Header.Get("Authorization"), redirect})
	fixture, etag, revoked := u.fixture, u.etag, u.revoked
	u.mu.Unlock()
	if revoked {
		http.Error(w, "fixture access revoked", http.StatusForbidden)
		return
	}
	if redirect {
		w.Header().Set("Location", "/cipher")
		w.WriteHeader(http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("ETag", etag)
	http.ServeContent(w, r, "cipher", time.Time{}, bytes.NewReader(fixture))
}

func (u *confirmedWebDAVUpstream) replace(fixture []byte, etag string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.fixture, u.etag = fixture, etag
}

func (u *confirmedWebDAVUpstream) setRevoked(revoked bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.revoked = revoked
}

// Include redirect hops: a forbidden response at the origin must not need to
// reach the representation endpoint to prove that authorization was checked.
func (u *confirmedWebDAVUpstream) methodCount(method string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	count := 0
	for _, r := range u.requests {
		if r.method == method {
			count++
		}
	}
	return count
}

func (u *confirmedWebDAVUpstream) counts() (probes, gets, heads int) {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, r := range u.requests {
		if r.redirect {
			continue
		}
		switch {
		case r.method == http.MethodGet && r.rangeHeader == "bytes=0-47":
			probes++
		case r.method == http.MethodGet:
			gets++
		case r.method == http.MethodHead:
			heads++
		}
	}
	return
}

func confirmedWebDAVProxy(t *testing.T, upstream *httptest.Server) *ProxyServer {
	t.Helper()
	p := legacyV3Proxy(t, upstream)
	client := *upstream.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	p.httpClient, p.streamClient, p.probeClient = &client, &client, &client
	t.Cleanup(func() {
		p.sealLifetime()
		p.lifetime().background.Wait()
	})
	return p
}

func confirmedWebDAVServer(t *testing.T, p *ProxyServer) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(p.handleWebDAV))
	server.Client().Timeout = 5 * time.Second
	server.Client().CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	t.Cleanup(server.Close)
	return server
}

func confirmedWebDAVDo(t *testing.T, server *httptest.Server, method, rangeHeader, auth string) (*http.Response, []byte) {
	t.Helper()
	r, err := http.NewRequest(method, server.URL+"/dav/enc/object", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Range", rangeHeader)
	r.Header.Set("Authorization", auth)
	resp, err := server.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("%s %q response framing: %v", method, rangeHeader, err)
	}
	return resp, body
}

func confirmedWebDAVPlain(t *testing.T, server *httptest.Server, method, rangeHeader, auth string, plain []byte, start, end int) {
	t.Helper()
	resp, body := confirmedWebDAVDo(t, server, method, rangeHeader, auth)
	status := http.StatusOK
	if rangeHeader != "" {
		status = http.StatusPartialContent
	}
	if resp.StatusCode != status || resp.ContentLength != int64(end-start+1) || resp.Header.Get("Location") != "" {
		t.Fatalf("%s %q status=%d length=%d headers=%v body=%q", method, rangeHeader, resp.StatusCode, resp.ContentLength, resp.Header, body)
	}
	if method == http.MethodHead {
		if len(body) != 0 {
			t.Fatal("HEAD returned a body")
		}
	} else if !bytes.Equal(body, plain[start:end+1]) {
		t.Fatalf("%s %q plaintext mismatch: got %q want %q", method, rangeHeader, body, plain[start:end+1])
	}
	if rangeHeader != "" && resp.Header.Get("Content-Range") != fmt.Sprintf("bytes %d-%d/%d", start, end, len(plain)) {
		t.Fatalf("plaintext Content-Range: %v", resp.Header)
	}
}

func confirmedWebDAVFixture(t *testing.T, plain []byte, version int) []byte {
	t.Helper()
	if version == ContentVersionV3 {
		// Fixed-size V3 needs only the 48-byte header inspection; footer-based
		// metadata resolution has a separate trailer request by design.
		return legacyV3Fixture(t, plain, true)
	}
	return mxWebDAVFixture(t, plain, version)
}

func TestConfirmedMetadataWebDAVHTTPReuse(t *testing.T) {
	plain := bytes.Repeat([]byte("confirmed-metadata-video!"), 12)
	for _, version := range []int{ContentVersionV1, ContentVersionV2, ContentVersionV3} {
		for _, redirect := range []bool{false, true} {
			t.Run(fmt.Sprintf("v%d/redirect=%v", version, redirect), func(t *testing.T) {
				u := &confirmedWebDAVUpstream{fixture: confirmedWebDAVFixture(t, plain, version), etag: `"stable-object"`, redirect: redirect}
				upstream := httptest.NewServer(http.HandlerFunc(u.serveHTTP))
				t.Cleanup(upstream.Close)
				p := confirmedWebDAVProxy(t, upstream)
				server := confirmedWebDAVServer(t, p)
				confirmedWebDAVPlain(t, server, "GET", "", "Bearer fixture-one", plain, 0, len(plain)-1)
				probes, gets, _ := u.counts()
				if probes != 1 || gets < 1 {
					t.Fatalf("cold GET: probes=%d actualGETs=%d; want one inspection plus a real stream", probes, gets)
				}
				if version != ContentVersionV3 && !redirect && gets != 1 {
					t.Fatalf("direct cold GET dispatched %d actual GETs; want 1", gets)
				}
				if version != ContentVersionV3 && !redirect {
					u.mu.Lock()
					first := u.requests[0]
					u.mu.Unlock()
					if first.method != "GET" || first.rangeHeader != "bytes=0-47" {
						t.Fatalf("direct stream dispatched before cold inspection: %+v", first)
					}
				}
				for _, tc := range []struct {
					method, rangeHeader string
					start, end          int
				}{
					{"GET", "", 0, len(plain) - 1},
					{"HEAD", "", 0, len(plain) - 1},
					{"GET", "bytes=73-91", 73, 91},
					{"GET", "bytes=-9", len(plain) - 9, len(plain) - 1},
					{"HEAD", "bytes=73-91", 73, 91},
					{"GET", "bytes=73-91", 73, 91},
				} {
					confirmedWebDAVPlain(t, server, tc.method, tc.rangeHeader, "Bearer fixture-one", plain, tc.start, tc.end)
					if probes, _, _ := u.counts(); probes != 1 {
						t.Fatalf("hot %s %q added inspection: total=%d", tc.method, tc.rangeHeader, probes)
					}
				}
			})
		}
	}
}

// Opening the existing schema directly avoids constructor backup/cache workers.
func confirmedWebDAVOpenStore(t *testing.T, p *ProxyServer, filename string) *localStore {
	t.Helper()
	db, err := sql.Open("sqlite3", filename)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if err := initLocalSchema(db); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	store := &localStore{db: db, flushThreshold: 100}
	t.Cleanup(func() {
		p.sealLifetime()
		p.lifetime().background.Wait()
		_ = store.Close()
	})
	return store
}

func TestConfirmedMetadataWebDAVHTTPRestart(t *testing.T) {
	plain := bytes.Repeat([]byte("sqlite-persisted-video!"), 9)
	for _, version := range []int{ContentVersionV1, ContentVersionV2} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			u := &confirmedWebDAVUpstream{fixture: mxWebDAVFixture(t, plain, version), etag: `"persisted-object"`}
			upstream := httptest.NewServer(http.HandlerFunc(u.serveHTTP))
			t.Cleanup(upstream.Close)
			filename := filepath.Join(t.TempDir(), "confirmed.db")
			p := confirmedWebDAVProxy(t, upstream)
			p.localStore = confirmedWebDAVOpenStore(t, p, filename)
			first := confirmedWebDAVServer(t, p)
			confirmedWebDAVPlain(t, first, "GET", "", "Bearer restart", plain, 0, len(plain)-1)
			if probes, _, _ := u.counts(); probes != 1 {
				t.Fatalf("cold inspection count=%d", probes)
			}
			first.Close()
			p.sealLifetime()
			p.lifetime().background.Wait()
			if err := p.localStore.Close(); err != nil {
				t.Fatal(err)
			}
			restarted := confirmedWebDAVProxy(t, upstream)
			// Exactly the same origin/rule configuration, but no in-memory state.
			restarted.config = p.configSnapshot()
			restarted.localStore = confirmedWebDAVOpenStore(t, restarted, filename)
			second := confirmedWebDAVServer(t, restarted)
			confirmedWebDAVPlain(t, second, "HEAD", "", "Bearer restart", plain, 0, len(plain)-1)
			confirmedWebDAVPlain(t, second, "GET", "bytes=71-87", "Bearer restart", plain, 71, 87)
			if probes, _, _ := u.counts(); probes != 1 {
				t.Fatalf("restart HEAD/seek re-inspected persisted metadata: total=%d", probes)
			}
		})
	}
}

func TestConfirmedMetadataWebDAVHTTPChangedRepresentation(t *testing.T) {
	oldPlain := bytes.Repeat([]byte("old-video!"), 24)
	for _, version := range []int{ContentVersionV1, ContentVersionV2} {
		for _, sameSize := range []bool{false, true} {
			t.Run(fmt.Sprintf("v%d/same-size=%v", version, sameSize), func(t *testing.T) {
				newPlain := bytes.Repeat([]byte("new-video!"), 24)
				if !sameSize {
					newPlain = append(newPlain, []byte("different-size")...)
				}
				u := &confirmedWebDAVUpstream{fixture: mxWebDAVFixture(t, oldPlain, version), etag: `"old-object"`}
				upstream := httptest.NewServer(http.HandlerFunc(u.serveHTTP))
				t.Cleanup(upstream.Close)
				server := confirmedWebDAVServer(t, confirmedWebDAVProxy(t, upstream))
				confirmedWebDAVPlain(t, server, "GET", "", "Bearer change", oldPlain, 0, len(oldPlain)-1)
				u.replace(mxWebDAVFixture(t, newPlain, version), `"new-object"`)
				resp, body := confirmedWebDAVDo(t, server, "GET", "bytes=73-91", "Bearer change")
				if resp.StatusCode != http.StatusBadGateway || resp.Header.Get("Content-Range") != "" || bytes.Equal(body, oldPlain[73:92]) || bytes.Equal(body, newPlain[73:92]) {
					t.Fatalf("changed stream not rejected before plaintext headers/body: status=%d headers=%v body=%q", resp.StatusCode, resp.Header, body)
				}
				if probes, _, _ := u.counts(); probes != 1 {
					t.Fatalf("validator should piggyback on actual stream, probes=%d", probes)
				}
				confirmedWebDAVPlain(t, server, "GET", "", "Bearer change", newPlain, 0, len(newPlain)-1)
				confirmedWebDAVPlain(t, server, "GET", "bytes=-7", "Bearer change", newPlain, len(newPlain)-7, len(newPlain)-1)
				if probes, _, _ := u.counts(); probes != 2 {
					t.Fatalf("retry should inspect once, then become hot: total=%d", probes)
				}
			})
		}
	}
}

func TestConfirmedMetadataWebDAVHTTPAuthorizationIsolation(t *testing.T) {
	plain := bytes.Repeat([]byte("credential-scoped-video!"), 9)
	u := &confirmedWebDAVUpstream{fixture: mxWebDAVFixture(t, plain, ContentVersionV2), etag: `"same-object"`}
	upstream := httptest.NewServer(http.HandlerFunc(u.serveHTTP))
	t.Cleanup(upstream.Close)
	server := confirmedWebDAVServer(t, confirmedWebDAVProxy(t, upstream))
	for i, auth := range []string{"Bearer scope-a", "Bearer scope-a", "Bearer scope-b", "Bearer scope-b", "Bearer scope-a"} {
		confirmedWebDAVPlain(t, server, "GET", "bytes=73-91", auth, plain, 73, 91)
		want := 1
		if i >= 2 {
			want = 2
		}
		if probes, _, _ := u.counts(); probes != want {
			t.Fatalf("request %d credential isolation probes=%d want=%d", i, probes, want)
		}
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, r := range u.requests {
		if r.method != http.MethodGet && r.method != http.MethodHead {
			continue
		}
		if r.auth != "Bearer scope-a" && r.auth != "Bearer scope-b" {
			t.Fatalf("same-origin request lost authorization: %+v", r)
		}
	}
}

// A confirmed geometry record proves the object's format, not that the same
// credential is still authorized. In particular, a cached HEAD must not return
// local plaintext headers without making a real upstream authorization check.
func TestConfirmedMetadataWebDAVHTTPCachedHEADChecksAuthorization(t *testing.T) {
	plain := bytes.Repeat([]byte("revocable-video-permission!"), 9)
	for _, version := range []int{ContentVersionV1, ContentVersionV2, ContentVersionV3} {
		for _, redirect := range []bool{false, true} {
			t.Run(fmt.Sprintf("v%d/redirect=%v", version, redirect), func(t *testing.T) {
				u := &confirmedWebDAVUpstream{fixture: confirmedWebDAVFixture(t, plain, version), etag: `"permission-object"`, redirect: redirect}
				upstream := httptest.NewServer(http.HandlerFunc(u.serveHTTP))
				t.Cleanup(upstream.Close)
				server := confirmedWebDAVServer(t, confirmedWebDAVProxy(t, upstream))
				const auth = "Bearer revocable-fixture"
				confirmedWebDAVPlain(t, server, "GET", "", auth, plain, 0, len(plain)-1)
				if probes, _, _ := u.counts(); probes != 1 {
					t.Fatalf("cold confirmation probes=%d", probes)
				}
				u.setRevoked(true)
				for _, rangeHeader := range []string{"", "bytes=73-91"} {
					before := u.methodCount(http.MethodHead)
					resp, body := confirmedWebDAVDo(t, server, "HEAD", rangeHeader, auth)
					if resp.StatusCode != http.StatusForbidden || resp.Header.Get("Content-Range") != "" || resp.Header.Get("Accept-Ranges") != "" || len(body) != 0 {
						t.Fatalf("cached HEAD disclosed plaintext geometry after revocation: range=%q status=%d headers=%v body=%q", rangeHeader, resp.StatusCode, resp.Header, body)
					}
					if u.methodCount(http.MethodHead) <= before {
						t.Fatal("cached HEAD failed to authorize against the actual upstream")
					}
				}
				u.setRevoked(false)
				confirmedWebDAVPlain(t, server, "HEAD", "", auth, plain, 0, len(plain)-1)
				confirmedWebDAVPlain(t, server, "GET", "bytes=73-91", auth, plain, 73, 91)
				if probes, _, _ := u.counts(); probes != 1 {
					t.Fatalf("permission denial discarded unchanged geometry proof: probes=%d", probes)
				}
			})
		}
	}
}

// Empty V3 GET has no chunks to read, but still needs an upstream response:
// possession of a cached authenticated header must not bypass access revocation.
func TestConfirmedMetadataWebDAVHTTPEmptyV3GETChecksAuthorization(t *testing.T) {
	for _, redirect := range []bool{false, true} {
		t.Run(fmt.Sprintf("redirect=%v", redirect), func(t *testing.T) {
			u := &confirmedWebDAVUpstream{fixture: confirmedWebDAVFixture(t, nil, ContentVersionV3), etag: `"empty-permission-object"`, redirect: redirect}
			upstream := httptest.NewServer(http.HandlerFunc(u.serveHTTP))
			t.Cleanup(upstream.Close)
			server := confirmedWebDAVServer(t, confirmedWebDAVProxy(t, upstream))
			const auth = "Bearer empty-revocable-fixture"
			confirmedWebDAVPlain(t, server, "GET", "", auth, nil, 0, -1)
			if probes, _, _ := u.counts(); probes != 1 {
				t.Fatalf("empty cold confirmation probes=%d", probes)
			}
			u.setRevoked(true)
			before := u.methodCount(http.MethodGet)
			resp, body := confirmedWebDAVDo(t, server, "GET", "", auth)
			if resp.StatusCode != http.StatusForbidden || resp.Header.Get("Content-Range") != "" || resp.Header.Get("Accept-Ranges") != "" {
				t.Fatalf("cached empty GET bypassed revoked permission: status=%d headers=%v body=%q", resp.StatusCode, resp.Header, body)
			}
			if u.methodCount(http.MethodGet) <= before {
				t.Fatal("empty cached GET failed to authorize against the actual upstream")
			}
			u.setRevoked(false)
			confirmedWebDAVPlain(t, server, "GET", "", auth, nil, 0, -1)
			if probes, _, _ := u.counts(); probes != 1 {
				t.Fatalf("permission denial discarded unchanged empty geometry proof: probes=%d", probes)
			}
		})
	}
}

func TestConfirmedMetadataWebDAVHTTPLegacyTupleCannotPromote(t *testing.T) {
	plain := bytes.Repeat([]byte("legacy-cache-is-not-proof!"), 8)
	u := &confirmedWebDAVUpstream{fixture: mxWebDAVFixture(t, plain, ContentVersionV2), etag: `"real-object"`}
	upstream := httptest.NewServer(http.HandlerFunc(u.serveHTTP))
	t.Cleanup(upstream.Close)
	p := confirmedWebDAVProxy(t, upstream)
	p.storeFileCache("/enc/object", &FileInfo{
		Size: int64(len(plain)), ContentVersion: ContentVersionV2, HeaderLen: 32,
		CiphertextSize: int64(len(u.fixture)), NonceField: bytes.Repeat([]byte{7}, 16),
	})
	server := confirmedWebDAVServer(t, p)
	confirmedWebDAVPlain(t, server, "GET", "", "Bearer legacy", plain, 0, len(plain)-1)
	if probes, _, _ := u.counts(); probes != 1 {
		t.Fatalf("valid-looking legacy tuple bypassed confirmation: probes=%d", probes)
	}
	confirmedWebDAVPlain(t, server, "HEAD", "", "Bearer legacy", plain, 0, len(plain)-1)
	if probes, _, _ := u.counts(); probes != 1 {
		t.Fatalf("confirmed tuple failed hot reuse: probes=%d", probes)
	}
}
