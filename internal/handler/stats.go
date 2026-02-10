package handler

import (
	"net/http"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/proxy"
)

// StatsHandler provides runtime stats for caches and resolver behavior
type StatsHandler struct {
	cfg           *config.Config
	fileDAO       *dao.FileDAO
	proxyHandler  *ProxyHandler
	webdavHandler *WebDAVHandler
	streamProxy   *proxy.StreamProxy
	startTime     time.Time
}

// NewStatsHandler creates a new StatsHandler
func NewStatsHandler(cfg *config.Config, fileDAO *dao.FileDAO, proxyHandler *ProxyHandler, webdavHandler *WebDAVHandler, streamProxy *proxy.StreamProxy, startTime time.Time) *StatsHandler {
	return &StatsHandler{
		cfg:           cfg,
		fileDAO:       fileDAO,
		proxyHandler:  proxyHandler,
		webdavHandler: webdavHandler,
		streamProxy:   streamProxy,
		startTime:     startTime,
	}
}

// HandleStats returns runtime stats
func (h *StatsHandler) HandleStats(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"version": config.Version,
		"uptime":  time.Since(h.startTime).Round(time.Second).String(),
		"cache": map[string]interface{}{
			"path_cache":      h.fileDAO.PathCacheStats(),
			"file_size_cache": h.fileDAO.FileSizeCacheStats(),
		},
		"proxy":              h.proxyHandler.Stats(),
		"webdav":             h.webdavHandler.Stats(),
		"range_compat_cache": h.streamProxy.RangeCompatStats(),
	}

	RespondSuccess(w, data)
}
