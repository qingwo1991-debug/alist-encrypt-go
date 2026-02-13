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
	proxyStats := h.proxyHandler.Stats()
	webdavStats := h.webdavHandler.Stats()
	proxyStream := getStreamStats(proxyStats)
	webdavStream := getStreamStats(webdavStats)

	data := map[string]interface{}{
		"version": config.Version,
		"uptime":  time.Since(h.startTime).Round(time.Second).String(),
		"meta": map[string]interface{}{
			"cleanup_disabled": h.cfg != nil && h.cfg.Database != nil && h.cfg.Database.DisableCleanup,
		},
		"stream": map[string]interface{}{
			"play_first_fallback":     h.cfg != nil && h.cfg.AlistServer.PlayFirstFallback,
			"final_passthrough_count": proxyStream["final_passthrough_count"] + webdavStream["final_passthrough_count"],
			"size_conflict_count":     proxyStream["size_conflict_count"] + webdavStream["size_conflict_count"],
			"strategy_fallback_count": proxyStream["strategy_fallback_count"] + webdavStream["strategy_fallback_count"],
		},
		"cache": map[string]interface{}{
			"path_cache":      h.fileDAO.PathCacheStats(),
			"file_size_cache": h.fileDAO.FileSizeCacheStats(),
		},
		"proxy":              proxyStats,
		"webdav":             webdavStats,
		"range_compat_cache": h.streamProxy.RangeCompatStats(),
	}

	RespondSuccess(w, data)
}

func getStreamStats(stats map[string]interface{}) map[string]uint64 {
	out := map[string]uint64{
		"final_passthrough_count": 0,
		"size_conflict_count":     0,
		"strategy_fallback_count": 0,
	}

	rawStream, ok := stats["stream"].(map[string]interface{})
	if !ok {
		return out
	}
	for key := range out {
		if value, ok := rawStream[key].(uint64); ok {
			out[key] = value
			continue
		}
		if value, ok := rawStream[key].(int); ok {
			out[key] = uint64(value)
			continue
		}
		if value, ok := rawStream[key].(float64); ok {
			out[key] = uint64(value)
		}
	}
	return out
}
