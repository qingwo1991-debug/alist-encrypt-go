package server

import (
	"net/http"
	"runtime"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/gin-gonic/gin"
)

var startTime = time.Now()

// HealthResponse exposes numeric process observations, never heap contents.
// MemAlloc includes unreachable allocations not yet collected: it is not a
// retained-live-heap or RSS measurement. Exact byte counters avoid MiB rounding
// when correlating natural GC cycles with a bounded plaintext cache.
type HealthResponse struct {
	Status       string `json:"status"`
	Version      string `json:"version"`
	Uptime       string `json:"uptime"`
	GoVersion    string `json:"go_version"`
	NumGoroutine int    `json:"num_goroutine"`
	MemAlloc     uint64 `json:"mem_alloc_mb"`

	ObservedAtUnixNano int64   `json:"observed_at_unix_nano"`
	MemAllocBytes      uint64  `json:"mem_alloc_bytes"`
	MemSysBytes        uint64  `json:"mem_sys_bytes"`
	TotalAllocBytes    uint64  `json:"total_alloc_bytes"`
	HeapInuseBytes     uint64  `json:"heap_inuse_bytes"`
	HeapSysBytes       uint64  `json:"heap_sys_bytes"`
	HeapIdleBytes      uint64  `json:"heap_idle_bytes"`
	HeapReleasedBytes  uint64  `json:"heap_released_bytes"`
	HeapObjects        uint64  `json:"heap_objects"`
	NextGCBytes        uint64  `json:"next_gc_bytes"`
	NumGC              uint32  `json:"num_gc"`
	LastGCUnixNano     uint64  `json:"last_gc_unix_nano"`
	GCCPUFraction      float64 `json:"gc_cpu_fraction"`

	// Omitted means unavailable, not a disabled cache with zero usage.
	DecryptedBlockCache *healthBlockCache `json:"decrypted_block_cache,omitempty"`
}

type healthBlockCache struct {
	Enabled       bool   `json:"enabled"`
	Entries       int    `json:"entries"`
	UsedBytes     int64  `json:"used_bytes"`
	MaxBytes      int64  `json:"max_bytes"`
	BlockSize     int64  `json:"block_size"`
	HitCount      uint64 `json:"hit_count"`
	MissCount     uint64 `json:"miss_count"`
	PutCount      uint64 `json:"put_count"`
	EvictionCount uint64 `json:"eviction_count"`
}

type healthCacheProvider interface {
	DecryptedBlockCacheStats() map[string]interface{}
}

// healthCacheSnapshot deliberately projects a typed allowlist, rather than
// embedding getStats or an arbitrary provider map into the public response.
func healthCacheSnapshot(provider healthCacheProvider) *healthBlockCache {
	if provider == nil {
		return nil
	}
	stats := provider.DecryptedBlockCacheStats()
	enabled, known := stats["enabled"].(bool)
	if !known {
		return nil
	}
	if !enabled {
		return &healthBlockCache{}
	}
	entries, eOK := stats["entries"].(int)
	used, uOK := stats["used_bytes"].(int64)
	maxBytes, mOK := stats["max_bytes"].(int64)
	blockSize, bOK := stats["block_size"].(int64)
	hits, hOK := stats["hit_count"].(uint64)
	misses, miOK := stats["miss_count"].(uint64)
	puts, pOK := stats["put_count"].(uint64)
	evictions, evOK := stats["eviction_count"].(uint64)
	if !eOK || !uOK || !mOK || !bOK || !hOK || !miOK || !pOK || !evOK {
		return nil
	}
	return &healthBlockCache{enabled, entries, used, maxBytes, blockSize, hits, misses, puts, evictions}
}

// HealthHandler preserves the standalone handler entry point. A server wires
// its own existing stream proxy through newHealthHandler, with no global cache.
func HealthHandler(c *gin.Context) {
	newHealthHandler(nil)(c)
}

func newHealthHandler(provider healthCacheProvider) gin.HandlerFunc {
	return func(c *gin.Context) {
		var m runtime.MemStats
		runtime.ReadMemStats(&m) // Observation only: never force GC or collect a profile.
		resp := HealthResponse{
			Status: "ok", Version: config.Version,
			Uptime: time.Since(startTime).Round(time.Second).String(), GoVersion: runtime.Version(),
			NumGoroutine: runtime.NumGoroutine(), MemAlloc: m.Alloc / 1024 / 1024,
			ObservedAtUnixNano: time.Now().UnixNano(), MemAllocBytes: m.Alloc,
			MemSysBytes: m.Sys, TotalAllocBytes: m.TotalAlloc,
			HeapInuseBytes: m.HeapInuse, HeapSysBytes: m.HeapSys, HeapIdleBytes: m.HeapIdle,
			HeapReleasedBytes: m.HeapReleased, HeapObjects: m.HeapObjects,
			NextGCBytes: m.NextGC, NumGC: m.NumGC, LastGCUnixNano: m.LastGC,
			GCCPUFraction: m.GCCPUFraction, DecryptedBlockCache: healthCacheSnapshot(provider),
		}
		c.JSON(http.StatusOK, resp)
	}
}

// ReadyHandler returns whether the service is ready to accept traffic
func ReadyHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ready"})
}
