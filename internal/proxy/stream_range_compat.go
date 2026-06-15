package proxy

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/alist-encrypt-go/internal/httputil"
)

const defaultRangeCompatReprobe = 30 * time.Minute

// RangeCompatStats returns range compatibility cache stats
func (s *StreamProxy) RangeCompatStats() map[string]interface{} {
	configStats := map[string]interface{}{
		"enabled": s.cfg != nil && s.cfg.AlistServer.EnableRangeCompatCache,
		"reprobe_minutes": func() int {
			if s.cfg != nil && s.cfg.AlistServer.RangeReprobeMinutes > 0 {
				return s.cfg.AlistServer.RangeReprobeMinutes
			}
			return int(defaultRangeCompatReprobe / time.Minute)
		}(),
		"fail_to_downgrade":  s.rangeFailToDowngrade(),
		"success_to_recover": s.rangeSuccessToRecover(),
		"probe_timeout_seconds": func() int {
			if s != nil && s.cfg != nil && s.cfg.AlistServer.RangeProbeTimeoutSeconds > 0 {
				return s.cfg.AlistServer.RangeProbeTimeoutSeconds
			}
			return 8
		}(),
	}
	runtimeStats := map[string]interface{}{}
	if s.rangeStats != nil {
		for k, v := range s.rangeStats.snapshot() {
			runtimeStats[k] = v
		}
	}
	storeStats := map[string]interface{}{"mode": "unknown"}
	if provider, ok := s.compatStore.(interface{ Stats() map[string]interface{} }); ok && provider != nil {
		for k, v := range provider.Stats() {
			storeStats[k] = v
		}
	}
	flat := map[string]interface{}{
		"config":  configStats,
		"runtime": runtimeStats,
		"store":   storeStats,
	}
	for k, v := range configStats {
		flat[k] = v
	}
	for k, v := range runtimeStats {
		flat[k] = v
	}
	for k, v := range storeStats {
		flat[k] = v
	}
	return flat
}

// SetRangeCompatStore sets a persistent range compatibility store.
func (s *StreamProxy) SetRangeCompatStore(store RangeCompatStore) {
	if s == nil {
		return
	}
	if store == nil {
		s.compatStore = NewMemoryRangeCompatStore()
		return
	}
	s.compatStore = store
}

func (s *StreamProxy) rangeCompatReprobeInterval() time.Duration {
	if s.cfg == nil || !s.cfg.AlistServer.EnableRangeCompatCache {
		return 0
	}
	if s.cfg.AlistServer.RangeReprobeMinutes > 0 {
		return time.Duration(s.cfg.AlistServer.RangeReprobeMinutes) * time.Minute
	}
	return defaultRangeCompatReprobe
}

func (s *StreamProxy) rangeFailToDowngrade() int {
	if s == nil || s.cfg == nil || s.cfg.AlistServer.RangeFailToDowngrade <= 0 {
		return 2
	}
	return s.cfg.AlistServer.RangeFailToDowngrade
}

func (s *StreamProxy) rangeSuccessToRecover() int {
	if s == nil || s.cfg == nil || s.cfg.AlistServer.RangeSuccessToRecover <= 0 {
		return 3
	}
	return s.cfg.AlistServer.RangeSuccessToRecover
}

func (s *StreamProxy) rangeProbeTimeout() time.Duration {
	if s == nil || s.cfg == nil || s.cfg.AlistServer.RangeProbeTimeoutSeconds <= 0 {
		return 8 * time.Second
	}
	return time.Duration(s.cfg.AlistServer.RangeProbeTimeoutSeconds) * time.Second
}

func (s *StreamProxy) chunkedSeekMaxDiscardBytes() int64 {
	if s == nil || s.cfg == nil || s.cfg.AlistServer.ChunkedSeekMaxDiscardBytes <= 0 {
		return 8 * 1024 * 1024
	}
	return s.cfg.AlistServer.ChunkedSeekMaxDiscardBytes
}

func (s *StreamProxy) rangeCompatHost(targetURL string) string {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return ""
	}
	return parsed.Host
}

func normalizeCompatStorageKey(storageKey string) string {
	storageKey = strings.TrimSpace(storageKey)
	if storageKey == "" {
		return "/"
	}
	if !strings.HasPrefix(storageKey, "/") {
		storageKey = "/" + storageKey
	}
	out := strings.TrimRight(storageKey, "/")
	if out == "" {
		return "/"
	}
	return out
}

func (s *StreamProxy) rangeCompatKey(targetURL, storageKey string) string {
	host := s.rangeCompatHost(targetURL)
	if host == "" {
		return ""
	}
	return host + "::" + normalizeCompatStorageKey(storageKey)
}

func (s *StreamProxy) shouldSkipRange(targetURL, storageKey string) bool {
	if s.compatStore == nil || s.cfg == nil || !s.cfg.AlistServer.EnableRangeCompatCache {
		return false
	}
	key := s.rangeCompatKey(targetURL, storageKey)
	if key == "" {
		return false
	}
	state, ok, err := s.compatStore.Get(key)
	if err != nil || !ok {
		return false
	}
	if !state.Incompatible {
		return false
	}
	if state.NextProbeAt.IsZero() {
		if s.rangeStats != nil {
			atomic.AddUint64(&s.rangeStats.skipCount, 1)
		}
		return true
	}
	shouldSkip := time.Now().Before(state.NextProbeAt)
	if shouldSkip && s.rangeStats != nil {
		atomic.AddUint64(&s.rangeStats.skipCount, 1)
	}
	return shouldSkip
}

func (s *StreamProxy) recordRangeFailure(targetURL, storageKey, reason string) {
	if s.compatStore == nil || s.cfg == nil || !s.cfg.AlistServer.EnableRangeCompatCache {
		return
	}
	key := s.rangeCompatKey(targetURL, storageKey)
	if key == "" {
		return
	}
	state, ok, err := s.compatStore.Get(key)
	if err != nil {
		return
	}
	if !ok {
		state = RangeCompatState{}
	}
	now := time.Now()
	state.LastReason = reason
	state.LastCheckedAt = now
	state.LastAccessed = now
	state.UpdatedAt = now
	if reason != "range_unsatisfiable" {
		state.ConsecutiveFailures++
		state.ConsecutiveSuccesses = 0
		if state.ConsecutiveFailures >= s.rangeFailToDowngrade() {
			wasIncompatible := state.Incompatible
			state.Incompatible = true
			reprobe := s.rangeCompatReprobeInterval()
			if reprobe <= 0 {
				reprobe = defaultRangeCompatReprobe
			}
			state.NextProbeAt = now.Add(reprobe)
			if !wasIncompatible && s.rangeStats != nil {
				atomic.AddUint64(&s.rangeStats.downgradeCount, 1)
			}
		}
	} else {
		state.ConsecutiveFailures = 0
		state.ConsecutiveSuccesses = 0
	}
	if s.rangeStats != nil {
		if reason == "range_unsupported" {
			atomic.AddUint64(&s.rangeStats.reasonUnsupported, 1)
		}
		if reason == "range_unsatisfiable" {
			atomic.AddUint64(&s.rangeStats.reasonUnsatisfiable, 1)
		}
	}
	_ = s.compatStore.Upsert(key, state)
}

func (s *StreamProxy) recordRangeSuccess(targetURL, storageKey string) {
	if s.compatStore == nil || s.cfg == nil || !s.cfg.AlistServer.EnableRangeCompatCache {
		return
	}
	key := s.rangeCompatKey(targetURL, storageKey)
	if key == "" {
		return
	}
	state, ok, err := s.compatStore.Get(key)
	if err != nil {
		return
	}
	if !ok {
		state = RangeCompatState{}
	}
	now := time.Now()
	state.ConsecutiveSuccesses++
	state.ConsecutiveFailures = 0
	state.LastReason = ""
	state.LastCheckedAt = now
	state.LastAccessed = now
	state.UpdatedAt = now
	if state.Incompatible && state.ConsecutiveSuccesses >= s.rangeSuccessToRecover() {
		state.Incompatible = false
		state.NextProbeAt = time.Time{}
		if s.rangeStats != nil {
			atomic.AddUint64(&s.rangeStats.recoverCount, 1)
		}
	}
	_ = s.compatStore.Upsert(key, state)
}

// ShouldBackgroundProbeRange returns whether range capability should be probed in background.
func (s *StreamProxy) ShouldBackgroundProbeRange(targetURL, storageKey string) bool {
	if s == nil || s.compatStore == nil || s.cfg == nil || !s.cfg.AlistServer.EnableRangeCompatCache {
		return false
	}
	key := s.rangeCompatKey(targetURL, storageKey)
	if key == "" {
		return false
	}
	state, ok, err := s.compatStore.Get(key)
	if err != nil || !ok {
		return true // cold start
	}
	if state.Incompatible {
		return state.NextProbeAt.IsZero() || !time.Now().Before(state.NextProbeAt)
	}
	return false
}

// ProbeRangeCompatibility sends a lightweight range probe and updates learning state.
func (s *StreamProxy) ProbeRangeCompatibility(ctx context.Context, targetURL string, authHeaders http.Header, storageKey string) {
	if !s.ShouldBackgroundProbeRange(targetURL, storageKey) {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if s.rangeStats != nil {
		atomic.AddUint64(&s.rangeStats.probeTotal, 1)
	}
	probeCtx, cancel := context.WithTimeout(ctx, s.rangeProbeTimeout())
	defer cancel()

	req, err := httputil.NewRequest(http.MethodGet, targetURL).
		WithContext(probeCtx).
		Build()
	if err != nil {
		return
	}
	req.Header.Set("Range", "bytes=0-0")
	req.Header.Set("Accept-Encoding", "identity")
	copyProbeAuthHeaders(req, authHeaders)

	resp, err := s.client.Do(req)
	if err != nil {
		if s.rangeStats != nil {
			atomic.AddUint64(&s.rangeStats.probeFailure, 1)
		}
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
		return
	}
	if resp.StatusCode == http.StatusPartialContent && resp.Header.Get("Content-Range") != "" {
		s.recordRangeSuccess(targetURL, storageKey)
		if s.rangeStats != nil {
			atomic.AddUint64(&s.rangeStats.probeSuccess, 1)
		}
		return
	}
	if resp.StatusCode == http.StatusOK && resp.Header.Get("Content-Range") == "" {
		s.recordRangeFailure(targetURL, storageKey, "range_unsupported")
		if s.rangeStats != nil {
			atomic.AddUint64(&s.rangeStats.probeFailure, 1)
		}
		return
	}
	if resp.StatusCode == http.StatusPartialContent && resp.Header.Get("Content-Range") == "" {
		s.recordRangeFailure(targetURL, storageKey, "range_unsupported")
		if s.rangeStats != nil {
			atomic.AddUint64(&s.rangeStats.pseudoRangeCount, 1)
			atomic.AddUint64(&s.rangeStats.probeFailure, 1)
		}
		return
	}
	if resp.StatusCode == http.StatusRequestedRangeNotSatisfiable {
		s.recordRangeFailure(targetURL, storageKey, "range_unsatisfiable")
		if s.rangeStats != nil {
			atomic.AddUint64(&s.rangeStats.probeFailure, 1)
		}
		return
	}
	if resp.StatusCode >= http.StatusBadRequest {
		if s.rangeStats != nil {
			atomic.AddUint64(&s.rangeStats.probeFailure, 1)
		}
	}
}
