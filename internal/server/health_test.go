package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alist-encrypt-go/internal/proxy"
	"github.com/gin-gonic/gin"
)

type healthTestCache map[string]interface{}

func (s healthTestCache) DecryptedBlockCacheStats() map[string]interface{} { return s }

func healthRequest(t *testing.T, handler gin.HandlerFunc) map[string]interface{} {
	t.Helper()
	router := gin.New()
	router.GET("/health", handler)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/health", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func TestHealthRuntimeObservationsAndLegacyFields(t *testing.T) {
	response := healthRequest(t, HealthHandler)
	for _, key := range []string{"status", "version", "uptime", "go_version", "num_goroutine", "mem_alloc_mb"} {
		if _, found := response[key]; !found {
			t.Fatalf("legacy field missing: %s", key)
		}
	}
	for _, key := range []string{"observed_at_unix_nano", "mem_alloc_bytes", "mem_sys_bytes", "total_alloc_bytes", "heap_inuse_bytes", "heap_sys_bytes", "heap_idle_bytes", "heap_released_bytes", "heap_objects", "next_gc_bytes", "num_gc", "last_gc_unix_nano", "gc_cpu_fraction"} {
		value, ok := response[key].(float64)
		if !ok || value < 0 {
			t.Fatalf("not a nonnegative numeric observation %s: %v", key, response[key])
		}
	}
	if response["status"] != "ok" || response["num_goroutine"].(float64) < 1 {
		t.Fatal("unexpected process health")
	}
	if response["mem_alloc_mb"].(float64) != float64(uint64(response["mem_alloc_bytes"].(float64))/(1024*1024)) {
		t.Fatal("legacy MiB must use the same snapshot as byte counter")
	}
	if _, found := response["decrypted_block_cache"]; found {
		t.Fatal("unavailable provider must not imply a known disabled cache")
	}
}

func TestHealthCacheProjectionDoesNotExposeProviderFields(t *testing.T) {
	stats := healthTestCache{
		"enabled": true, "entries": 4, "used_bytes": int64(1024), "max_bytes": int64(2048),
		"block_size": int64(256), "hit_count": uint64(3), "miss_count": uint64(2),
		"put_count": uint64(8), "eviction_count": uint64(4),
		"path": "/private-media", "token": "secret-marker", "keys": []string{"private-key"},
	}
	response := healthRequest(t, newHealthHandler(stats))
	cache := response["decrypted_block_cache"].(map[string]interface{})
	if len(cache) != 9 || cache["enabled"] != true || cache["used_bytes"] != float64(1024) || cache["eviction_count"] != float64(4) {
		t.Fatalf("unexpected numeric cache snapshot: %#v", cache)
	}
	b, _ := json.Marshal(response)
	for _, secret := range []string{"private-media", "secret-marker", "private-key", "token"} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("provider field leaked: %s", secret)
		}
	}
	// Observation must not reset counters, evict entries, or change the source map.
	if stats["used_bytes"] != int64(1024) || stats["put_count"] != uint64(8) || len(stats) != 12 {
		t.Fatal("health mutated cache state")
	}
}

func TestHealthCacheUnavailableAndDisabledAreDistinct(t *testing.T) {
	for _, unknown := range []healthTestCache{nil, {}, {"enabled": "false"}, {"enabled": true, "used_bytes": "unknown"}} {
		if got := healthCacheSnapshot(unknown); got != nil {
			t.Fatalf("malformed/unavailable stats must not invent zero usage: %#v", got)
		}
	}
	// The real nil proxy reports a known disabled cache without panicking.
	var disabled *proxy.StreamProxy
	response := healthRequest(t, newHealthHandler(disabled))
	cache, exists := response["decrypted_block_cache"].(map[string]interface{})
	if !exists || cache["enabled"] != false {
		t.Fatal("known disabled cache must be explicit")
	}
}
