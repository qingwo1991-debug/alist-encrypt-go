package encrypt

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestHandleConfigV2Schema(t *testing.T) {
	p := &ProxyServer{config: DefaultConfig()}
	req := httptest.NewRequest(http.MethodGet, "/api/encrypt/v2/config/schema", nil)
	w := httptest.NewRecorder()
	p.handleConfigV2Schema(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", w.Code)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	data, _ := payload["data"].(map[string]interface{})
	if data == nil {
		t.Fatalf("missing data")
	}
	docs, _ := data["docs"].([]interface{})
	if len(docs) == 0 {
		t.Fatalf("docs should not be empty")
	}
}

func TestHandleConfigV2PostClampsAndPersists(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ConfigPath = filepath.Join(t.TempDir(), "encrypt_config.json")
	p := &ProxyServer{config: cfg}

	body := map[string]interface{}{
		"config": map[string]interface{}{
			"probeTimeoutSeconds":         999,
			"rangeCompatMinFailures":      -1,
			"parallelDecryptConcurrency":  99,
			"dbExportSyncIntervalSeconds": 1,
		},
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/encrypt/v2/config", bytes.NewReader(raw))
	w := httptest.NewRecorder()
	p.handleConfigV2(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", w.Code, w.Body.String())
	}
	if p.config.ProbeTimeoutSeconds != 30 {
		t.Fatalf("probe timeout clamp failed: %d", p.config.ProbeTimeoutSeconds)
	}
	if p.config.RangeCompatMinFailures != 1 {
		t.Fatalf("range failures clamp failed: %d", p.config.RangeCompatMinFailures)
	}
	if p.config.ParallelDecryptConcurrency != 32 {
		t.Fatalf("parallel clamp failed: %d", p.config.ParallelDecryptConcurrency)
	}
	if p.config.DBExportSyncIntervalSeconds != minDBExportSyncIntervalSecs {
		t.Fatalf("sync interval clamp failed: %d", p.config.DBExportSyncIntervalSeconds)
	}
}

func TestHandleConfigV2ProviderRoutingRulesMatchValues(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ConfigPath = filepath.Join(t.TempDir(), "encrypt_config.json")
	p := &ProxyServer{config: cfg}

	body := map[string]interface{}{
		"config": map[string]interface{}{
			"providerRoutingRules": []map[string]interface{}{
				{
					"id":          "r1",
					"matchType":   "provider",
					"matchValues": []string{"baidunetdisk", "weiyun", "mopan"},
					"action":      "direct",
					"enabled":     true,
					"priority":    1,
				},
			},
		},
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/encrypt/v2/config", bytes.NewReader(raw))
	w := httptest.NewRecorder()
	p.handleConfigV2(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", w.Code, w.Body.String())
	}
	if len(p.config.ProviderRoutingRules) != 1 {
		t.Fatalf("expected one routing rule, got %d", len(p.config.ProviderRoutingRules))
	}
	got := p.config.ProviderRoutingRules[0]
	if len(got.MatchValues) != 3 {
		t.Fatalf("expected 3 matchValues, got %d", len(got.MatchValues))
	}
	if got.MatchValue == "" {
		t.Fatalf("expected legacy MatchValue to be populated")
	}
}

func TestHandleConfigV2ProviderRoutingRulesLegacyMatchValueCompat(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ConfigPath = filepath.Join(t.TempDir(), "encrypt_config.json")
	p := &ProxyServer{config: cfg}

	body := map[string]interface{}{
		"config": map[string]interface{}{
			"providerRoutingRules": []map[string]interface{}{
				{
					"id":         "legacy",
					"matchType":  "provider",
					"matchValue": "onedrive",
					"action":     "proxy",
					"enabled":    true,
					"priority":   5,
				},
			},
		},
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/encrypt/v2/config", bytes.NewReader(raw))
	w := httptest.NewRecorder()
	p.handleConfigV2(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", w.Code, w.Body.String())
	}
	if len(p.config.ProviderRoutingRules) != 1 {
		t.Fatalf("expected one routing rule, got %d", len(p.config.ProviderRoutingRules))
	}
	got := p.config.ProviderRoutingRules[0]
	if len(got.MatchValues) != 1 || got.MatchValues[0] != "onedrive" {
		t.Fatalf("legacy matchValue compat failed, got matchValues=%v", got.MatchValues)
	}
}

func TestHandleConfigV2RoutingUnmatchedDefault(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ConfigPath = filepath.Join(t.TempDir(), "encrypt_config.json")
	p := &ProxyServer{config: cfg}

	body := map[string]interface{}{
		"config": map[string]interface{}{
			"routingUnmatchedDefault": "direct",
		},
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/encrypt/v2/config", bytes.NewReader(raw))
	w := httptest.NewRecorder()
	p.handleConfigV2(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", w.Code, w.Body.String())
	}
	if p.config.RoutingUnmatchedDefault != routingActionDirect {
		t.Fatalf("expected direct, got %s", p.config.RoutingUnmatchedDefault)
	}

	body = map[string]interface{}{
		"config": map[string]interface{}{
			"routingUnmatchedDefault": "invalid",
		},
	}
	raw, _ = json.Marshal(body)
	req = httptest.NewRequest(http.MethodPost, "/api/encrypt/v2/config", bytes.NewReader(raw))
	w = httptest.NewRecorder()
	p.handleConfigV2(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", w.Code, w.Body.String())
	}
	if p.config.RoutingUnmatchedDefault != routingActionProxy {
		t.Fatalf("expected invalid value fallback to proxy, got %s", p.config.RoutingUnmatchedDefault)
	}
}

func TestHandleConfigV2ProviderCatalogConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ConfigPath = filepath.Join(t.TempDir(), "encrypt_config.json")
	p := &ProxyServer{config: cfg}

	body := map[string]interface{}{
		"config": map[string]interface{}{
			"providerCatalogEnabled":          true,
			"providerCatalogTtlMinutes":       2,
			"providerCatalogBootstrapOnStart": true,
		},
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/encrypt/v2/config", bytes.NewReader(raw))
	w := httptest.NewRecorder()
	p.handleConfigV2(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", w.Code, w.Body.String())
	}
	// ttl has minimum clamp of 5 minutes
	if p.config.ProviderCatalogTTLMinutes != 5 {
		t.Fatalf("expected ttl clamp=5, got %d", p.config.ProviderCatalogTTLMinutes)
	}
	if !p.config.ProviderCatalogEnabled {
		t.Fatalf("expected provider catalog enabled")
	}
	if !p.config.ProviderCatalogBootstrapOnStart {
		t.Fatalf("expected bootstrap on start enabled")
	}
}
