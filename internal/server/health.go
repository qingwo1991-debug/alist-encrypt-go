package server

import (
	"net/http"
	"runtime"
	"time"

	"github.com/gin-gonic/gin"
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
func HealthHandler(c *gin.Context) {
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

	c.JSON(http.StatusOK, resp)
}

// ReadyHandler returns whether the service is ready to accept traffic
func ReadyHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ready"})
}
