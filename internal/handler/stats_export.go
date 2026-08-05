package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/rs/zerolog/log"

	"github.com/alist-encrypt-go/internal/config"
)

// StatsExportHandler 提供播放/删除统计的导出接口，用独立统计密码保护。
type StatsExportHandler struct {
	cfg   *config.Config
	store *StatsStore
}

func NewStatsExportHandler(cfg *config.Config, store *StatsStore) *StatsExportHandler {
	return &StatsExportHandler{cfg: cfg, store: store}
}

// ExportStats 导出统计事件。需要 `password` 与配置的 StatsPassword 一致才放行。
// 未配置 StatsPassword 时返回 404（功能关闭）。
func (h *StatsExportHandler) ExportStats(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.cfg == nil || h.store == nil {
		RespondHTTPErrorWithStatus(w, "stats disabled", http.StatusNotFound)
		return
	}
	statsPassword := h.cfg.StatsPasswordSnapshot()
	if statsPassword == "" {
		RespondHTTPErrorWithStatus(w, "stats disabled", http.StatusNotFound)
		return
	}
	// 独立统计密码：与登录 JWT 完全隔离。
	query := r.URL.Query()
	given := query.Get("password")
	if given == "" {
		given = r.Header.Get("X-Stats-Password")
	}
	if given != statsPassword {
		http.Error(w, "invalid stats password", http.StatusUnauthorized)
		return
	}

	limit := 0
	if s := query.Get("limit"); s != "" {
		limit, _ = strconv.Atoi(s)
	}

	plays, err := h.store.ListPlayback(r.Context(), limit)
	if err != nil {
		log.Warn().Err(err).Msg("failed to list playback stats")
		RespondHTTPErrorWithStatus(w, "stats read failed", http.StatusInternalServerError)
		return
	}
	dels, err := h.store.ListDeletions(r.Context(), limit)
	if err != nil {
		log.Warn().Err(err).Msg("failed to list deletion stats")
		RespondHTTPErrorWithStatus(w, "stats read failed", http.StatusInternalServerError)
		return
	}
	payload, err := json.Marshal(map[string]interface{}{
		"playbacks": plays,
		"deletions": dels,
	})
	if err != nil {
		RespondHTTPErrorWithStatus(w, "stats marshal failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(payload)
}
