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
	alistHandler  *AlistHandler
	proxyHandler  *ProxyHandler
	webdavHandler *WebDAVHandler
	streamProxy   *proxy.StreamProxy
	startTime     time.Time
}

// NewStatsHandler creates a new StatsHandler
func NewStatsHandler(cfg *config.Config, fileDAO *dao.FileDAO, alistHandler *AlistHandler, proxyHandler *ProxyHandler, webdavHandler *WebDAVHandler, streamProxy *proxy.StreamProxy, startTime time.Time) *StatsHandler {
	return &StatsHandler{
		cfg:           cfg,
		fileDAO:       fileDAO,
		alistHandler:  alistHandler,
		proxyHandler:  proxyHandler,
		webdavHandler: webdavHandler,
		streamProxy:   streamProxy,
		startTime:     startTime,
	}
}

// HandleStats returns runtime stats
func (h *StatsHandler) HandleStats(w http.ResponseWriter, r *http.Request) {
	proxyStats := h.proxyHandler.Stats()
	alistStats := map[string]interface{}{}
	if h.alistHandler != nil {
		alistStats = h.alistHandler.Stats()
	}
	webdavStats := h.webdavHandler.Stats()
	proxyStream := getStreamStats(proxyStats)
	webdavStream := getStreamStats(webdavStats)
	selectorStats := getSelectorStats(proxyStats, webdavStats)
	streamLimitStats := map[string]interface{}{}
	if h.streamProxy != nil {
		streamLimitStats = h.streamProxy.StreamLimitStats()
	}

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
			"first_frame_count":       proxyStream["first_frame_count"] + webdavStream["first_frame_count"],
			"first_frame_fallbacks":   proxyStream["first_frame_fallbacks"] + webdavStream["first_frame_fallbacks"],
			"warmup_enqueue_count":    proxyStream["warmup_enqueue_count"] + webdavStream["warmup_enqueue_count"],
			"strategy_reason_counts":  selectorStats["reason_counts"],
			"provider_strategy":       selectorStats["provider_strategy"],
			"recent_strategy_events":  selectorStats["recent_events"],
			"limit":                   streamLimitStats,
		},
		"cache": map[string]interface{}{
			"path_cache":            h.fileDAO.PathCacheStats(),
			"file_size_cache":       h.fileDAO.FileSizeCacheStats(),
			"decrypted_block_cache": h.streamProxy.DecryptedBlockCacheStats(),
		},
		"alist":              alistStats,
		"proxy":              proxyStats,
		"webdav":             webdavStats,
		"range_compat_cache": h.streamProxy.RangeCompatStats(),
		"probe_scheduler":    getProbeSchedulerStats(proxyStats, webdavStats),
	}

	RespondSuccess(w, data)
}

func getSelectorStats(stats ...map[string]interface{}) map[string]interface{} {
	for _, item := range stats {
		if selector, ok := item["strategy_selector"].(map[string]interface{}); ok && selector != nil {
			return selector
		}
	}
	return map[string]interface{}{
		"reason_counts":     map[string]uint64{},
		"provider_strategy": map[string]string{},
		"recent_events":     []interface{}{},
	}
}

func getStreamStats(stats map[string]interface{}) map[string]uint64 {
	out := map[string]uint64{
		"final_passthrough_count": 0,
		"size_conflict_count":     0,
		"strategy_fallback_count": 0,
		"first_frame_count":       0,
		"first_frame_fallbacks":   0,
		"warmup_enqueue_count":    0,
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

func getProbeSchedulerStats(stats ...map[string]interface{}) map[string]interface{} {
	for _, item := range stats {
		if probeStats, ok := item["probe_scheduler"].(map[string]interface{}); ok && probeStats != nil {
			return probeStats
		}
	}
	return map[string]interface{}{}
}
