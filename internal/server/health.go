package server

import (
	"encoding/json"
	"net/http"
	"runtime"
	"time"

	"github.com/alist-encrypt-go/internal/config"
)

var startTime = time.Now()

// HealthResponse represents the health check response
type HealthResponse struct {
	Status    string `json:"status"`
	Version   string `json:"version"`
	Uptime    string `json:"uptime"`
	GoVersion string `json:"go_version"`
	NumGoroutine int  `json:"num_goroutine"`
	MemAlloc  uint64 `json:"mem_alloc_mb"`
}

// HealthHandler returns server health status
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	resp := HealthResponse{
		Status:       "ok",
		Version:      config.Version,
		Uptime:       time.Since(startTime).Round(time.Second).String(),
		GoVersion:    runtime.Version(),
		NumGoroutine: runtime.NumGoroutine(),
		MemAlloc:     m.Alloc / 1024 / 1024, // MB
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ReadyHandler returns whether the service is ready to accept traffic
func ReadyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ready"}`))
}
