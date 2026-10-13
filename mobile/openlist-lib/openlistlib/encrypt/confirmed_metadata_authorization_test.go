package encrypt

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
)

// This fixture distinguishes an actual authorization operation from a content
// inspection. HEAD never returns a probe body, unlike the generic probe fixture.
func confirmedAuthorizationFixture(t *testing.T) (*ProxyServer, *EncryptPath, string, *atomic.Bool, *atomic.Int64, *atomic.Int32, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	revoked := &atomic.Bool{}
	total := &atomic.Int64{}
	total.Store(4128)
	heads, operations, probes := &atomic.Int32{}, &atomic.Int32{}, &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dav/mount/video.bin" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer scoped" {
			t.Errorf("authorization lost: %q", r.Header.Get("Authorization"))
		}
		switch {
		case r.Method == http.MethodHead:
			heads.Add(1)
			if r.Header.Get("Range") != "" || r.Header.Get("If-None-Match") != "" {
				t.Error("authorization HEAD retained client condition/range")
			}
		case r.Method == http.MethodGet && r.Header.Get("Range") == "bytes=0-47":
			probes.Add(1)
		case r.Method == http.MethodGet && r.Header.Get("Range") == "bytes=0-0":
			operations.Add(1)
		default:
			t.Errorf("unexpected operation %s range=%q", r.Method, r.Header.Get("Range"))
			http.Error(w, "unexpected", 500)
			return
		}
		if revoked.Load() {
			http.Error(w, "revoked", http.StatusForbidden)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		if r.Method == http.MethodHead {
			w.Header().Set("Content-Length", strconv.FormatInt(total.Load(), 10))
			return
		}
		if r.Header.Get("Range") == "bytes=0-0" {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-0/%d", total.Load()))
			w.Header().Set("Content-Length", "1")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write([]byte{0})
			return
		}
		header, err := BuildV2Header(EncTypeAESCTR, 4096, bytes.Repeat([]byte{7}, 16))
		if err != nil {
			t.Error(err)
			return
		}
		prefix := append(header, bytes.Repeat([]byte{1}, 48-len(header))...)
		w.Header().Set("Content-Range", "bytes 0-47/4128")
		w.Header().Set("Content-Length", "48")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(prefix)
	}))
	t.Cleanup(server.Close)
	u, _ := url.Parse(server.URL)
	port, _ := strconv.Atoi(u.Port())
	p := &ProxyServer{config: &ProxyConfig{AlistHost: u.Hostname(), AlistPort: port}, streamClient: server.Client()}
	t.Cleanup(func() { p.sealLifetime(); p.lifetime().background.Wait() })
	enc := &EncryptPath{Enable: true, EncType: EncTypeAESCTR, Password: "fixture-only"}
	return p, enc, server.URL + "/dav/mount/video.bin", revoked, total, heads, operations, probes
}

func confirmedAuthorizationRequest(t *testing.T, p *ProxyServer, enc *EncryptPath, target, method string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(method, "http://proxy.local/dav/mount/video.bin", nil)
	r.Header.Set("Authorization", "Bearer scoped")
	r = p.withConfirmedMetadataIdentity(r, "/dav/mount/video.bin", enc)
	meta, ok := p.resolveConfirmedMetadata(r.Context(), target, r.Header, enc, 0)
	if !ok || meta.Version != ContentVersionV2 || meta.PlainSize != 4096 || meta.CiphertextSize != 4128 || len(meta.NonceField) != 16 {
		t.Fatalf("confirmed geometry=%+v ok=%v", meta, ok)
	}
	return r
}

func TestConfirmedMetadataAuthorizationCacheHitChecksRevocation(t *testing.T) {
	p, enc, target, revoked, _, heads, operations, probes := confirmedAuthorizationFixture(t)
	r := confirmedAuthorizationRequest(t, p, enc, target, http.MethodGet)
	r.Header.Set("Range", "bytes=100-200")
	r.Header.Set("If-None-Match", `"v1"`)
	for _, denied := range []bool{true, false} {
		revoked.Store(denied)
		w := httptest.NewRecorder()
		ok := p.authorizeConfirmedMetadataCacheHit(w, r, "/d/mount/video.bin")
		if denied {
			if ok || w.Code != http.StatusForbidden || w.Header().Get("Content-Range") != "" || w.Header().Get("Content-Length") != "" {
				t.Fatalf("revoked local hit allowed=%v status=%d headers=%v", ok, w.Code, w.Header())
			}
		} else if !ok || w.Code != http.StatusOK || w.Body.Len() != 0 {
			t.Fatalf("restored local hit allowed=%v status=%d body=%q", ok, w.Code, w.Body.String())
		}
	}
	if heads.Load() != 2 || operations.Load() != 0 || probes.Load() != 1 {
		t.Fatalf("heads=%d operations=%d probes=%d", heads.Load(), operations.Load(), probes.Load())
	}
}

func TestConfirmedMetadataAuthorizationLocalHeadAndEmptyGet(t *testing.T) {
	for _, method := range []string{http.MethodHead, http.MethodGet} {
		t.Run(method, func(t *testing.T) {
			p, enc, target, revoked, _, heads, operations, probes := confirmedAuthorizationFixture(t)
			r := confirmedAuthorizationRequest(t, p, enc, target, method)
			// PlainSize zero exercises the empty-body operation gate; its proof
			// holder remains a separately confirmed, valid V2 representation.
			gateMeta := ContentMeta{PlainSize: 0}
			for _, denied := range []bool{true, false} {
				revoked.Store(denied)
				w := httptest.NewRecorder()
				ok := p.authorizeLocalWebDAVMetadata(w, r, "/dav2/mount/video.bin", gateMeta)
				if denied && (ok || w.Code != http.StatusForbidden) {
					t.Fatalf("revoked %s allowed=%v status=%d", method, ok, w.Code)
				}
				if !denied && (!ok || w.Code != http.StatusOK || w.Body.Len() != 0) {
					t.Fatalf("restored %s allowed=%v status=%d", method, ok, w.Code)
				}
			}
			if probes.Load() != 1 || (method == http.MethodHead && (heads.Load() != 2 || operations.Load() != 0)) || (method == http.MethodGet && (operations.Load() != 2 || heads.Load() != 0)) {
				t.Fatalf("method=%s heads=%d operations=%d probes=%d", method, heads.Load(), operations.Load(), probes.Load())
			}
		})
	}
}

func TestConfirmedMetadataAuthorizationRejectsChangedGeometry(t *testing.T) {
	for _, method := range []string{http.MethodHead, http.MethodGet} {
		t.Run(method, func(t *testing.T) {
			p, enc, target, _, total, heads, operations, probes := confirmedAuthorizationFixture(t)
			r := confirmedAuthorizationRequest(t, p, enc, target, method)
			total.Store(8192)
			w := httptest.NewRecorder()
			if p.authorizeConfirmedMetadataOperation(w, r, "/mount/video.bin") || w.Code != http.StatusBadGateway || w.Header().Get("Content-Range") != "" || w.Header().Get("Content-Length") != "" {
				t.Fatalf("changed geometry status=%d headers=%v", w.Code, w.Header())
			}
			if heads.Load()+operations.Load() != 1 || probes.Load() != 1 {
				t.Fatalf("conflict introduced inspection: heads=%d operations=%d probes=%d", heads.Load(), operations.Load(), probes.Load())
			}
		})
	}
}

func TestConfirmedMetadataCanonicalFallbackRebindsDifferentObject(t *testing.T) {
	var first, second atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var nonce byte
		switch r.URL.Path {
		case "/dav/mount/first.bin":
			first.Add(1)
			nonce = 3
		case "/dav/mount/second.bin":
			second.Add(1)
			nonce = 9
		default:
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet || r.Header.Get("Range") != "bytes=0-47" {
			t.Errorf("unexpected probe %s %q", r.Method, r.Header.Get("Range"))
		}
		header, err := BuildV2Header(EncTypeAESCTR, 4096, bytes.Repeat([]byte{nonce}, 16))
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("ETag", fmt.Sprintf(`"object-%d"`, nonce))
		w.Header().Set("Content-Range", "bytes 0-47/4128")
		w.Header().Set("Content-Length", "48")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(append(header, bytes.Repeat([]byte{1}, 48-len(header))...))
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	port, _ := strconv.Atoi(u.Port())
	p := &ProxyServer{config: &ProxyConfig{AlistHost: u.Hostname(), AlistPort: port}, streamClient: server.Client()}
	t.Cleanup(func() { p.sealLifetime(); p.lifetime().background.Wait() })
	enc := &EncryptPath{Enable: true, EncType: EncTypeAESCTR, Password: "fixture-only"}
	r := httptest.NewRequest(http.MethodGet, "http://proxy.local/dav/mount/first.bin", nil)
	r = p.withConfirmedMetadataIdentity(r, canonicalMetadataDAVPath("/d/mount/first.bin"), enc)
	originalID := confirmedMetadataRequestFromContext(r.Context()).identity
	meta, ok := p.resolveConfirmedMetadata(r.Context(), server.URL+"/dav/mount/first.bin", r.Header, enc, 0)
	if !ok || meta.NonceField[0] != 3 {
		t.Fatalf("first=%+v ok=%v", meta, ok)
	}
	fallback := p.withConfirmedMetadataIdentity(r, canonicalMetadataDAVPath("/p/mount/second.bin"), enc)
	fallbackID := confirmedMetadataRequestFromContext(fallback.Context()).identity
	if originalID == fallbackID || originalID.CredentialScope != fallbackID.CredentialScope || originalID.CryptoFingerprint != fallbackID.CryptoFingerprint {
		t.Fatal("canonical fallback failed to rebind only object identity")
	}
	for i := 0; i < 2; i++ {
		meta, ok = p.resolveConfirmedMetadata(fallback.Context(), server.URL+"/dav/mount/second.bin", fallback.Header, enc, 0)
		if !ok || meta.NonceField[0] != 9 || meta.PlainSize != 4096 {
			t.Fatalf("fallback reused original tuple: %+v ok=%v", meta, ok)
		}
	}
	meta, ok = p.resolveConfirmedMetadata(r.Context(), server.URL+"/dav/mount/first.bin", r.Header, enc, 0)
	if !ok || meta.NonceField[0] != 3 || first.Load() != 1 || second.Load() != 1 {
		t.Fatalf("identity isolation first=%d second=%d meta=%+v ok=%v", first.Load(), second.Load(), meta, ok)
	}
}
