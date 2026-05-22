package encrypt

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTryFetchRemoteProviderRoutingCandidates(t *testing.T) {
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/encrypt/provider-routing-candidates" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 200,
			"data": map[string]interface{}{
				"providers": []string{"china_mobile_cloud", "googledrive"},
				"provider_labels": map[string]string{
					"china_mobile_cloud": "移动云盘",
					"googledrive":        "Google Drive",
				},
			},
		})
	}))
	defer remote.Close()

	p := &ProxyServer{
		config: &ProxyConfig{
			DBExportBaseURL:     remote.URL + "/enc-api",
			DBExportAuthEnabled: false,
			ProxyPort:           5344,
		},
	}
	providers, labels, degraded := p.tryFetchRemoteProviderRoutingCandidates(context.Background())
	if degraded {
		t.Fatalf("expected non-degraded remote fetch")
	}
	if len(providers) != 2 {
		t.Fatalf("expected 2 providers, got %d (%v)", len(providers), providers)
	}
	if labels["china_mobile_cloud"] != "移动云盘" {
		t.Fatalf("unexpected label map: %+v", labels)
	}
}

func TestHandleProviderRoutingCandidatesMergesRemoteFallback(t *testing.T) {
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/encrypt/provider-routing-candidates" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 200,
			"data": map[string]interface{}{
				"providers": []string{"china_unicom_cloud", "googledrive"},
				"provider_labels": map[string]string{
					"china_unicom_cloud": "联通云盘",
					"googledrive":        "Google Drive",
				},
			},
		})
	}))
	defer remote.Close()

	p := &ProxyServer{
		config: &ProxyConfig{
			AlistHost:                 "127.0.0.1",
			AlistPort:                 1,
			AlistHttps:                false,
			DBExportBaseURL:           remote.URL,
			DBExportAuthEnabled:       false,
			ProviderCatalogEnabled:    true,
			ProviderCatalogTTLMinutes: 1,
			StorageMapRefreshMinutes:  30,
			ProxyPort:                 5344,
		},
		httpClient: &http.Client{Timeout: time.Second},
		seenProviders: map[string]time.Time{
			"baidunetdisk": time.Now(),
		},
		seenDrivers:      map[string]time.Time{},
		storageDriverMap: map[string]string{},
	}
	p.initProviderCatalog()
	p.refreshProviderCatalog(context.Background(), http.Header{})

	req := httptest.NewRequest(http.MethodGet, "/api/encrypt/provider-routing-candidates", nil)
	w := httptest.NewRecorder()
	p.handleProviderRoutingCandidates(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", w.Code, w.Body.String())
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	data, _ := payload["data"].(map[string]interface{})
	if data == nil {
		t.Fatalf("missing data")
	}
	rawProviders, _ := data["providers"].([]interface{})
	foundRemote := false
	for _, raw := range rawProviders {
		if raw.(string) == "china_unicom_cloud" || raw.(string) == "googledrive" {
			foundRemote = true
			break
		}
	}
	if !foundRemote {
		t.Fatalf("expected remote providers merged, got %v", rawProviders)
	}
	meta, _ := data["meta"].(map[string]interface{})
	if meta == nil {
		t.Fatalf("missing meta")
	}
	if _, ok := meta["catalog_total"]; !ok {
		t.Fatalf("expected catalog_total in meta, got %v", meta)
	}
}

func TestHandleProviderRoutingCandidatesIncludesBuiltinMobileAndUnicom(t *testing.T) {
	p := &ProxyServer{
		config: &ProxyConfig{
			ProviderCatalogEnabled:    true,
			ProviderCatalogTTLMinutes: 60,
		},
		providerCatalog:    map[string]string{},
		providerSourceMask: map[string]int{},
		seenProviders:      map[string]time.Time{},
		seenDrivers:        map[string]time.Time{},
	}
	p.initProviderCatalog()
	req := httptest.NewRequest(http.MethodGet, "/api/encrypt/provider-routing-candidates", nil)
	w := httptest.NewRecorder()
	p.handleProviderRoutingCandidates(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", w.Code, w.Body.String())
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	data, _ := payload["data"].(map[string]interface{})
	if data == nil {
		t.Fatalf("missing data")
	}
	providersRaw, _ := data["providers"].([]interface{})
	foundMobile := false
	foundUnicom := false
	for _, raw := range providersRaw {
		token := raw.(string)
		if token == "china_mobile_cloud" || token == "mobile_cloud" || token == "mopan" {
			foundMobile = true
		}
		if token == "china_unicom_cloud" || token == "unicom_cloud" || token == "wo_cloud" {
			foundUnicom = true
		}
	}
	if !foundMobile || !foundUnicom {
		t.Fatalf("expected mobile/unicom providers in candidates, got %v", providersRaw)
	}
}
