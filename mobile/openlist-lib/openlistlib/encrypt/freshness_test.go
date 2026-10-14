package encrypt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
)

func TestStrictFreshnessRequeriesCallerAuthorizationAndSameSizeNonce(t *testing.T) {
	var controls, probes atomic.Int32
	var nonceByte atomic.Int32
	nonceByte.Store(7)
	var deny atomic.Bool
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/fs/get" {
			controls.Add(1)
			if r.Header.Get("Authorization") != "caller" || deny.Load() {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			var payload struct {
				Path    string `json:"path"`
				Refresh bool   `json:"refresh"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.Path != "/mount/video.bin" || !payload.Refresh {
				t.Errorf("fresh canonical lookup payload=%+v err=%v", payload, err)
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "data": map[string]interface{}{"raw_url": server.URL + "/object?fresh=1", "size": 4130}})
			return
		}
		probes.Add(1)
		header, err := BuildV2Header(EncTypeAESCTR, 4096, bytes.Repeat([]byte{byte(nonceByte.Load())}, 16))
		if err != nil {
			t.Error(err)
			return
		}
		prefix := append(header, bytes.Repeat([]byte{0x61}, int(V3HeaderSize)-len(header))...)
		w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-%d/%d", V3HeaderSize-1, 4096+len(header)))
		w.Header().Set("Content-Length", strconv.Itoa(len(prefix)))
		// Deliberately no validator: TTL/size cannot prove the old nonce.
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(prefix)
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	port, _ := strconv.Atoi(u.Port())
	p := &ProxyServer{config: &ProxyConfig{AlistHost: u.Hostname(), AlistPort: port, StrictFreshness: true}, httpClient: server.Client(), streamClient: server.Client()}
	enc := &EncryptPath{Enable: true, EncType: EncTypeAESCTR, Password: "fixture-only"}
	for i, method := range []string{http.MethodGet, http.MethodHead, http.MethodGet} {
		nonceByte.Store(int32(7 + i))
		r := confirmedMetadataTestRequest(p, enc, "caller")
		r.Method = method
		r.Header.Set("Range", "bytes=-1")
		meta, ok := p.resolveConfirmedMetadata(r.Context(), server.URL+"/old-signed-url", http.Header{"Authorization": {"stored-service"}}, enc, 0)
		if !ok || meta.NonceField[0] != byte(7+i) {
			t.Fatalf("request %d meta=%+v confirmed=%v", i, meta, ok)
		}
		if got := strictConfirmedMetadataTarget(r.Context(), "old"); got != server.URL+"/object?fresh=1" {
			t.Fatalf("fresh transport=%q", got)
		}
	}
	if controls.Load() != 3 || probes.Load() != 3 {
		t.Fatalf("authorizedquery_count=%d probes=%d", controls.Load(), probes.Load())
	}
	deny.Store(true)
	r := confirmedMetadataTestRequest(p, enc, "caller")
	if _, ok := p.resolveConfirmedMetadata(r.Context(), server.URL+"/object", r.Header, enc, 0); ok {
		t.Fatal("revoked caller reused readable signed URL")
	}
	if controls.Load() != 4 || probes.Load() != 3 {
		t.Fatalf("revocation authorizedquery_count=%d probes=%d", controls.Load(), probes.Load())
	}
}

func TestStrictFreshnessAttachedResponseGenerationFence(t *testing.T) {
	p, enc, target, _ := confirmedMetadataTestServer(t, nil, nil)
	r := confirmedMetadataTestRequest(p, enc, "caller")
	if _, ok := p.resolveConfirmedMetadata(r.Context(), target, r.Header, enc, 0); !ok {
		t.Fatal("fixture did not confirm")
	}
	p.config.StrictFreshness = true
	holder := confirmedMetadataRequestFromContext(r.Context())
	holder.strictTarget = target
	actual, _ := http.NewRequest(http.MethodGet, target, nil)
	resp := &http.Response{StatusCode: http.StatusPartialContent, Header: http.Header{}, Request: actual}
	if !p.validateConfirmedMetadataResponse(r.Context(), resp) {
		t.Fatal("current scoped response rejected")
	}
	p.invalidateAllConfirmedMetadata()
	if p.validateConfirmedMetadataResponse(r.Context(), resp) {
		t.Fatal("late response survived generation invalidation")
	}
}

func TestStrictFreshnessOptInConfigAndEvidence(t *testing.T) {
	manager := NewConfigManager(filepath.Join(t.TempDir(), "config.json"))
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	if manager.GetConfig().StrictFreshness {
		t.Fatal("strict must not be default")
	}
	if err := manager.SetAdvancedConfigFromJSON(`{"strictFreshness":true}`); err != nil {
		t.Fatal(err)
	}
	reloaded := NewConfigManager(manager.configPath)
	if err := reloaded.Load(); err != nil {
		t.Fatal(err)
	}
	if !reloaded.GetConfig().StrictFreshness {
		t.Fatal("strict opt-in not persisted")
	}
	p := &ProxyServer{config: reloaded.GetConfig()}
	w := httptest.NewRecorder()
	p.setMetadataFreshnessHeaders(w)
	if w.Header().Get("X-Encrypt-Freshness-Policy") != "strict-freshness" || w.Header().Get("X-Encrypt-Atomic-Snapshot") != "false" || w.Header().Get("X-Encrypt-Stable-Object-Assumption") != "between-requests-no-atomic-snapshot" {
		t.Fatalf("headers=%v", w.Header())
	}
	if _, err := p.v3PlaybackCacheKey(nil, nil, ContentMeta{}); err == nil {
		t.Fatal("strict created a cross-request record key without trusted revision")
	}
}
