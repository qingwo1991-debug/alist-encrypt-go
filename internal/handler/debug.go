package handler

import (
	"context"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/debuglog"
	"github.com/alist-encrypt-go/internal/storage/mysqlstore"
)

// DebugHandler serves the optional /debug endpoints (recent logs + runtime
// status) that let an operator or an AI assistant pull troubleshooting context
// over HTTP. Routes are only registered when cfg.Debug.Enabled is true, and an
// optional bearer token is enforced by the server middleware.
type DebugHandler struct {
	cfg        *config.Config
	mysqlStore *mysqlstore.Store
	startedAt  time.Time
}

// NewDebugHandler builds the debug endpoint handler.
func NewDebugHandler(cfg *config.Config, mysqlStore *mysqlstore.Store) *DebugHandler {
	return &DebugHandler{cfg: cfg, mysqlStore: mysqlStore, startedAt: time.Now()}
}

// maxLogLinesPerRequest bounds a single /debug/logs call so accidental huge
// requests cannot drain the process.
const maxLogLinesPerRequest = 20000

// ServeLogs returns the most recent captured log lines (newest last).
func (h *DebugHandler) ServeLogs(c *gin.Context) {
	if h == nil || h.cfg == nil || !h.cfg.DebugEnabled() {
		c.JSON(http.StatusForbidden, gin.H{"error": "debug mode disabled"})
		return
	}
	lines := 200
	if v := c.Query("lines"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			if n > maxLogLinesPerRequest {
				n = maxLogLinesPerRequest
			}
			lines = n
		}
	}
	logs := debuglog.Tail(lines)
	var b strings.Builder
	if logs == nil {
		b.WriteString("(debug log ring not installed)\n")
	} else {
		for _, ln := range logs {
			b.WriteString(ln)
			b.WriteByte('\n')
		}
	}
	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.Header("X-Debug-Lines", strconv.Itoa(len(logs)))
	c.String(http.StatusOK, b.String())
}

// ServeStatus returns a read-only JSON snapshot of runtime state useful for
// debugging: backend health, snapshot store stats, encryption scopes, and
// process meters. It never exposes secrets (passwords/tokens are omitted).
func (h *DebugHandler) ServeStatus(c *gin.Context) {
	if h == nil || h.cfg == nil || !h.cfg.DebugEnabled() {
		c.JSON(http.StatusForbidden, gin.H{"error": "debug mode disabled"})
		return
	}

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	dbBackend := "boltdb"
	dbOK := false
	var snapshotRows int64
	if h.mysqlStore != nil {
		dbBackend = "mysql"
		ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()
		dbOK = h.mysqlStore.Ping(ctx) == nil
		if total, _, _, _, err := h.mysqlStore.CountDirSnapshots(ctx); err == nil {
			snapshotRows = total
		}
	}

	passwd := h.cfg.PasswdListSnapshot()
	whitelistPaths, encNameEnabled := 0, 0
	for _, p := range passwd {
		whitelistPaths += len(p.EncPath)
		if p.EncName {
			encNameEnabled++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"service": gin.H{
			"version":  config.Version,
			"uptime_s": int64(time.Since(h.startedAt).Seconds()),
			"now":      time.Now().Format(time.RFC3339),
		},
		"debug": gin.H{
			"enabled":   h.cfg.DebugEnabled(),
			"log_lines": h.cfg.DebugMaxLogLines(),
		},
		"db": gin.H{
			"backend":       dbBackend,
			"ok":            dbOK,
			"snapshot_rows": snapshotRows,
		},
		"upstream": gin.H{
			"alist_url": h.cfg.GetAlistURL(),
			"h2c":       h.cfg.AlistServerSnapshot().EnableH2C,
			"https":     h.cfg.IsHTTPSEnabled(),
		},
		"encryption": gin.H{
			"passwords":       len(passwd),
			"whitelist_paths": whitelistPaths,
			"encName_enabled": encNameEnabled,
		},
		"runtime": gin.H{
			"go_version":     runtime.Version(),
			"num_cpu":        runtime.NumCPU(),
			"num_goroutines": runtime.NumGoroutine(),
			"alloc_mb":       mem.Alloc / 1024 / 1024,
			"sys_mb":         mem.Sys / 1024 / 1024,
			"heap_inuse_mb":  mem.HeapInuse / 1024 / 1024,
		},
	})
}
