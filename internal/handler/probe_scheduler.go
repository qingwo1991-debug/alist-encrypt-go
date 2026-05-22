package handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/proxy"
)

type ProbeScheduler struct {
	cfg       *config.Config
	resolver  *FileSizeResolver
	fileDAO   *dao.FileDAO
	metaStore FileMetaStore
	stream    *proxy.StreamProxy
	enabled   bool

	queue    chan probeItem
	workers  int
	cooldown time.Duration
	minDelay time.Duration
	maxDelay time.Duration

	seenMu sync.Mutex
	seen   map[string]time.Time

	providerLimit int
	providerMu    sync.Mutex
	providerSem   map[string]chan struct{}
	minSizeBytes  int64
	enqueuedTotal uint64
	droppedTotal  uint64
	cooldownSkips uint64
	runningCount  uint64

	// rawURLFetcher caches signed CDN URLs for pre-warmed files.
	rawURLFetcher RawURLFetcher

	recordMu               sync.Mutex
	recentRecords          []ProbeRecord
	recordCursor           int
	recordCount            int
	successfulWarm         map[string]probeWarmState
	sourceCounts           map[string]uint64
	statusCounts           map[string]uint64
	recentFailureReasons   map[string]uint64
	filesDiscoveredTotal   uint64
	filesQueuedTotal       uint64
	filesSucceededTotal    uint64
	filesFailedTotal       uint64
	filesSkippedTotal      uint64
	filesRawURLFetched     uint64
	filesRangeProbed       uint64
	filesMetaPersisted     uint64
	consumerHitTotal       uint64
	lastSuccessAtUnixNano  int64
	lastFailureAtUnixNano  int64
	lastRecordFinishedNano int64
	consumerHitsBySource   map[string]uint64
	consumerHitsByScenario map[string]uint64
	recentConsumerHits     []ProbeConsumerHit
	consumerCursor         int
	consumerCount          int
	invalidationsTotal     uint64
	recentInvalidations    []ProbeInvalidation
	invalidationCursor     int
	invalidationCount      int
}

// RawURLFetcher fetches the signed raw_url for a display path from alist fs/get.
type RawURLFetcher func(displayPath, realPath string, authHeaders http.Header) string

type probeItem struct {
	file        FileItem
	authHeaders http.Header
	source      string
	queuedAt    time.Time
}

const (
	probeSourceUnspecified   = "unspecified"
	probeSourceFSList        = "fs_list"
	probeSourcePropfind      = "propfind"
	probeSourceStartupScan   = "startup_scan"
	probeSourceFirstFrame    = "first_frame_warmup"
	consumerScenarioHTTP     = "http_download"
	consumerScenarioWebDAV   = "webdav_get"
	consumerScenarioRedirect = "redirect_playback"
	probeStatusQueued        = "queued"
	probeStatusRunning       = "running"
	probeStatusSuccess       = "success"
	probeStatusFailed        = "failed"
	probeStatusSkippedSize   = "skipped_size"
	probeStatusSkippedDup    = "skipped_duplicate"
	probeStatusSkippedCD     = "skipped_cooldown"
	probeStatusDropped       = "dropped_queue_full"
	probeRecordBufferSize    = 256
	warmStateReady           = "warm_ready"
	warmStateStale           = "warm_stale"
	warmStateInvalid         = "warm_invalid"
	consumerHitDedupeWindow  = 30 * time.Second
)

type probeWarmState struct {
	Source            string
	FinishedAt        time.Time
	ConsumerHitCount  uint64
	LastConsumerHitAt time.Time
	State             string
}

type ProbeRecord struct {
	DisplayPath   string `json:"display_path"`
	EncryptedPath string `json:"encrypted_path"`
	TargetHost    string `json:"target_host"`
	ProviderKey   string `json:"provider_key"`
	FileName      string `json:"file_name"`
	Source        string `json:"source"`
	Priority      string `json:"priority"`
	Status        string `json:"status"`
	WarmState     string `json:"warm_state"`
	ReportedSize  int64  `json:"reported_size"`
	ResolvedSize  int64  `json:"resolved_size"`
	SizeSource    string `json:"size_source"`
	UsedAuthMode  string `json:"used_auth_mode"`
	FailureReason string `json:"failure_reason"`
	RawURLFetched bool   `json:"raw_url_fetched"`
	RangeProbed   bool   `json:"range_probed"`
	MetaPersisted bool   `json:"meta_persisted"`
	QueueWaitMs   int64  `json:"queue_wait_ms"`
	Invalidated   bool   `json:"invalidated"`
	ConsumerHitCount  uint64 `json:"consumer_hit_count"`
	LastConsumerHitAt string `json:"last_consumer_hit_at"`
	StartedAt     string `json:"started_at"`
	FinishedAt    string `json:"finished_at"`
	DurationMs    int64  `json:"duration_ms"`
}

type ProbeConsumerHit struct {
	DisplayPath string `json:"display_path"`
	FileName    string `json:"file_name"`
	Source      string `json:"source"`
	Scenario    string `json:"scenario"`
	HitAt       string `json:"hit_at"`
}

type ProbeInvalidation struct {
	DisplayPath string `json:"display_path"`
	Reason      string `json:"reason"`
	At          string `json:"at"`
}

type ProbeWarmSnapshot struct {
	DisplayPath       string `json:"display_path"`
	FileName          string `json:"file_name"`
	Source            string `json:"source"`
	State             string `json:"state"`
	FinishedAt        string `json:"finished_at"`
	ConsumerHitCount  uint64 `json:"consumer_hit_count"`
	LastConsumerHitAt string `json:"last_consumer_hit_at"`
}

type probeExecutionResult struct {
	resolvedSize  int64
	failureReason string
	rawURLFetched bool
	rangeProbed   bool
	metaPersisted bool
	sizeSource    string
	usedAuthMode  string
}

type rawURLFetchResult struct {
	RawURL        string
	StatusCode    int
	FailureReason string
}

type probeSourceContextKey struct{}

// SetRawURLFetcher sets the raw_url pre-fetch callback for probe scheduler.
func (ps *ProbeScheduler) SetRawURLFetcher(f RawURLFetcher) {
	ps.rawURLFetcher = f
}

func NewProbeScheduler(cfg *config.Config, fileDAO *dao.FileDAO, metaStore FileMetaStore, stream *proxy.StreamProxy) *ProbeScheduler {
	ps := &ProbeScheduler{
		cfg:         cfg,
		resolver:    NewFileSizeResolver(cfg, fileDAO, metaStore, 4, getMinMetaSize(cfg), getRedirectMaxHops(cfg)),
		fileDAO:     fileDAO,
		metaStore:   metaStore,
		stream:      stream,
		enabled:     cfg != nil && cfg.AlistServer.EnableBackgroundProbe,
		seen:        make(map[string]time.Time),
		providerSem: make(map[string]chan struct{}),
		recentRecords:        make([]ProbeRecord, probeRecordBufferSize),
		recentConsumerHits:   make([]ProbeConsumerHit, probeRecordBufferSize),
		recentInvalidations:  make([]ProbeInvalidation, probeRecordBufferSize),
		successfulWarm:       make(map[string]probeWarmState),
		sourceCounts:         make(map[string]uint64),
		statusCounts:         make(map[string]uint64),
		recentFailureReasons: make(map[string]uint64),
		consumerHitsBySource:   make(map[string]uint64),
		consumerHitsByScenario: make(map[string]uint64),
	}

	if cfg == nil {
		return ps
	}

	ps.workers = clampInt(cfg.AlistServer.ProbeConcurrency, 1, 20)
	ps.providerLimit = clampInt(cfg.AlistServer.ProbeProviderConcurrency, 1, 5)
	ps.minDelay = time.Duration(clampInt(cfg.AlistServer.ProbeMinDelayMs, 0, 60000)) * time.Millisecond
	ps.maxDelay = time.Duration(clampInt(cfg.AlistServer.ProbeMaxDelayMs, 0, 120000)) * time.Millisecond
	ps.cooldown = time.Duration(clampInt(cfg.AlistServer.ProbeCooldownMinutes, 1, 10080)) * time.Minute
	queueSize := clampInt(cfg.AlistServer.ProbeQueueSize, 100, 10000)
	ps.queue = make(chan probeItem, queueSize)
	ps.minSizeBytes = cfg.AlistServer.ProbeMinSizeBytes

	if ps.enabled {
		for i := 0; i < ps.workers; i++ {
			go ps.worker()
		}
	}
	return ps
}

func (ps *ProbeScheduler) Enqueue(file FileItem, authHeaders http.Header) {
	ps.EnqueueWithSource(file, authHeaders, 0, probeSourceUnspecified)
}

func (ps *ProbeScheduler) EnqueueWithSize(file FileItem, authHeaders http.Header, reportedSize int64) {
	ps.EnqueueWithSource(file, authHeaders, reportedSize, probeSourceUnspecified)
}

func (ps *ProbeScheduler) EnqueueWithSource(file FileItem, authHeaders http.Header, reportedSize int64, source string) {
	if ps == nil || !ps.enabled || ps.queue == nil {
		return
	}
	ps.ensureRecordState()
	source = normalizeProbeSource(source)
	if file.DisplayPath == "" || file.TargetURL == "" {
		return
	}
	atomic.AddUint64(&ps.filesDiscoveredTotal, 1)
	sizeProbeNeeded := ps.shouldProbeSize(reportedSize)
	rangeProbeNeeded := ps.shouldProbeRange(file, reportedSize)

	if size, ok := ps.fileDAO.GetFileSize(file.DisplayPath); ok {
		if !sizeProbeNeeded {
			// no-op
		} else {
			sizeProbeNeeded = ps.shouldProbeSize(size)
		}
		if !rangeProbeNeeded {
			rangeProbeNeeded = ps.shouldProbeRange(file, size)
		}
	}
	if ps.metaStore != nil {
		providerKey := ProviderKey(file.TargetURL, file.DisplayPath)
		if meta, ok, _ := ps.metaStore.Get(context.Background(), providerKey, file.DisplayPath); ok {
			if sizeProbeNeeded {
				sizeProbeNeeded = ps.shouldProbeSize(meta.Size)
			}
			if !rangeProbeNeeded {
				rangeProbeNeeded = ps.shouldProbeRange(file, meta.Size)
			}
		}
	}
	if !sizeProbeNeeded && !rangeProbeNeeded {
		ps.recordTerminal(file, source, probeStatusSkippedSize, reportedSize, probeExecutionResult{})
		atomic.AddUint64(&ps.filesSkippedTotal, 1)
		return
	}

	key := ProviderKey(file.TargetURL, file.DisplayPath)
	if ps.isCoolingDown(key) {
		atomic.AddUint64(&ps.cooldownSkips, 1)
		atomic.AddUint64(&ps.filesSkippedTotal, 1)
		ps.recordTerminal(file, source, probeStatusSkippedCD, reportedSize, probeExecutionResult{})
		return
	}

	select {
	case ps.queue <- probeItem{file: file, authHeaders: authHeaders, source: source, queuedAt: time.Now()}:
		ps.markSeen(key)
		atomic.AddUint64(&ps.enqueuedTotal, 1)
		atomic.AddUint64(&ps.filesQueuedTotal, 1)
		ps.recordTerminal(file, source, probeStatusQueued, reportedSize, probeExecutionResult{})
	default:
		atomic.AddUint64(&ps.droppedTotal, 1)
		atomic.AddUint64(&ps.filesSkippedTotal, 1)
		ps.recordTerminal(file, source, probeStatusDropped, reportedSize, probeExecutionResult{})
		return
	}
}

func (ps *ProbeScheduler) Stats() map[string]interface{} {
	if ps == nil {
		return map[string]interface{}{}
	}
	ps.ensureRecordState()
	queueLen := 0
	queueCap := 0
	if ps.queue != nil {
		queueLen = len(ps.queue)
		queueCap = cap(ps.queue)
	}
	return map[string]interface{}{
		"enabled":        ps.enabled,
		"workers":        ps.workers,
		"provider_limit": ps.providerLimit,
		"queue_len":      queueLen,
		"queue_cap":      queueCap,
		"enqueued_total": atomic.LoadUint64(&ps.enqueuedTotal),
		"dropped_total":  atomic.LoadUint64(&ps.droppedTotal),
		"cooldown_skips": atomic.LoadUint64(&ps.cooldownSkips),
		"running_count":  atomic.LoadUint64(&ps.runningCount),
		"files_discovered_total": atomic.LoadUint64(&ps.filesDiscoveredTotal),
		"files_queued_total":     atomic.LoadUint64(&ps.filesQueuedTotal),
		"files_succeeded_total":  atomic.LoadUint64(&ps.filesSucceededTotal),
		"files_failed_total":     atomic.LoadUint64(&ps.filesFailedTotal),
		"files_skipped_total":    atomic.LoadUint64(&ps.filesSkippedTotal),
		"files_raw_url_fetched":  atomic.LoadUint64(&ps.filesRawURLFetched),
		"files_range_probed":     atomic.LoadUint64(&ps.filesRangeProbed),
		"files_meta_persisted":   atomic.LoadUint64(&ps.filesMetaPersisted),
		"consumer_hit_total":     atomic.LoadUint64(&ps.consumerHitTotal),
		"consumer_hit_rate":      ps.consumerHitRate(),
		"last_success_at":        formatProbeTimestamp(atomic.LoadInt64(&ps.lastSuccessAtUnixNano)),
		"last_failure_at":        formatProbeTimestamp(atomic.LoadInt64(&ps.lastFailureAtUnixNano)),
		"last_record_finished_at": formatProbeTimestamp(atomic.LoadInt64(&ps.lastRecordFinishedNano)),
		"source_counts":          ps.snapshotCounterMap(ps.sourceCounts),
		"status_counts":          ps.snapshotCounterMap(ps.statusCounts),
		"failure_reasons":        ps.snapshotCounterMap(ps.recentFailureReasons),
		"consumer_hits_by_source":   ps.snapshotCounterMap(ps.consumerHitsBySource),
		"consumer_hits_by_scenario": ps.snapshotCounterMap(ps.consumerHitsByScenario),
		"recent_records":         ps.snapshotRecentRecords(),
		"recent_consumer_hits":   ps.snapshotRecentConsumerHits(),
		"invalidations_total":    atomic.LoadUint64(&ps.invalidationsTotal),
		"recent_invalidations":   ps.snapshotRecentInvalidations(),
		"warm_state_counts":      ps.snapshotWarmStateCounts(),
		"current_warm_states":    ps.snapshotWarmStates(),
	}
}

func (ps *ProbeScheduler) shouldProbeSize(size int64) bool {
	if size <= 0 {
		return true
	}
	if ps.minSizeBytes <= 0 {
		return false
	}
	return size < ps.minSizeBytes
}

func (ps *ProbeScheduler) shouldProbeRange(file FileItem, size int64) bool {
	if ps == nil || ps.stream == nil {
		return false
	}
	if file.TargetURL == "" || file.CompatStorageKey == "" {
		return false
	}
	return ps.stream.ShouldBackgroundProbeRange(file.TargetURL, file.CompatStorageKey)
}

func (ps *ProbeScheduler) worker() {
	for item := range ps.queue {
		ps.runItem(item)
	}
}

func (ps *ProbeScheduler) runItem(item probeItem) {
	ps.ensureRecordState()
	atomic.AddUint64(&ps.runningCount, 1)
	startedAt := time.Now()
	ps.recordRunning(item, startedAt)
	defer atomic.AddUint64(&ps.runningCount, ^uint64(0))

	providerKey := ProviderKey(item.file.TargetURL, item.file.DisplayPath)
	providerHost, _ := splitProvider(providerKey)
	sem := ps.getProviderSem(providerHost)
	if sem == nil {
		ps.finishRecord(item, startedAt, probeStatusFailed, probeExecutionResult{failureReason: "provider_semaphore_unavailable"})
		atomic.AddUint64(&ps.filesFailedTotal, 1)
		return
	}

	select {
	case sem <- struct{}{}:
		defer func() { <-sem }()
	default:
		ps.finishRecord(item, startedAt, probeStatusSkippedDup, probeExecutionResult{failureReason: "provider_busy"})
		atomic.AddUint64(&ps.filesSkippedTotal, 1)
		return
	}

	// Only delay re-probes (items that already have cached data).
	// First-time probes execute immediately to warm the cache before user clicks download.
	_, hasCache := ps.fileDAO.GetFileSize(item.file.DisplayPath)
	if hasCache && ps.maxDelay > 0 {
		delay := ps.minDelay
		if ps.maxDelay > ps.minDelay {
			delta := ps.maxDelay - ps.minDelay
			delay += time.Duration(rand.Int63n(int64(delta)))
		}
		time.Sleep(delay)
	}

	// Fallback to configured scan credentials if no user auth available
	authHeaders, authMode := ps.ensureAuth(item.authHeaders)

	resultState := probeExecutionResult{}
	result := ps.resolver.ResolveSingle(context.Background(), item.file, authHeaders)
	if result.Error == nil && result.Size > 0 {
		ps.fileDAO.SetFileSize(item.file.DisplayPath, result.Size, 24*time.Hour)
		resultState.resolvedSize = result.Size
		resultState.metaPersisted = true
		resultState.sizeSource = string(result.Source)
		atomic.AddUint64(&ps.filesMetaPersisted, 1)
	} else if result.Error != nil {
		resultState.failureReason = "size_resolve:" + result.Error.Error()
	}
	resultState.usedAuthMode = authMode
	// Pre-fetch raw_url so WebDAV first-play is zero-latency.
	// Check staleness: don't re-fetch if raw_url is still fresh.
	stalenessThreshold := 30 * time.Minute
	if ps.cfg != nil && ps.cfg.AlistServer.UpstreamStalenessMinutes > 0 {
		stalenessThreshold = time.Duration(ps.cfg.AlistServer.UpstreamStalenessMinutes) * time.Minute
	}
	if ps.rawURLFetcher != nil {
		if rawURL := ps.rawURLFetcher(item.file.DisplayPath, item.file.EncryptedPath, authHeaders); rawURL != "" {
			resultState.rawURLFetched = true
			atomic.AddUint64(&ps.filesRawURLFetched, 1)
		}
	}
	if ps.rawURLFetcher == nil && ps.cfg != nil {
		// Fallback: use built-in raw_url fetcher via alist fs/get
		alistURL := ps.cfg.GetAlistURL()
		rawURLResult := fetchRawURL(context.Background(), alistURL, item.file.DisplayPath, item.file.EncryptedPath, authHeaders, ps.fileDAO, stalenessThreshold)
		if rawURLResult.RawURL != "" {
			resultState.rawURLFetched = true
			atomic.AddUint64(&ps.filesRawURLFetched, 1)
		} else if resultState.failureReason == "" && rawURLResult.FailureReason != "" {
			resultState.failureReason = rawURLResult.FailureReason
		}
		if rawURLResult.StatusCode == http.StatusUnauthorized || rawURLResult.StatusCode == http.StatusForbidden || rawURLResult.StatusCode == http.StatusNotFound {
			ps.InvalidateWarm(item.file.DisplayPath, "raw_url_upstream_4xx")
		}
	}
	if ps.stream != nil {
		ps.stream.ProbeRangeCompatibility(context.Background(), item.file.TargetURL, authHeaders, item.file.CompatStorageKey)
		resultState.rangeProbed = true
		atomic.AddUint64(&ps.filesRangeProbed, 1)
	}
	status := probeStatusSuccess
	if resultState.failureReason != "" && resultState.resolvedSize <= 0 && !resultState.rawURLFetched && !resultState.rangeProbed {
		status = probeStatusFailed
		atomic.AddUint64(&ps.filesFailedTotal, 1)
	} else {
		atomic.AddUint64(&ps.filesSucceededTotal, 1)
	}
	ps.finishRecord(item, startedAt, status, resultState)
}

func (ps *ProbeScheduler) getProviderSem(provider string) chan struct{} {
	ps.providerMu.Lock()
	defer ps.providerMu.Unlock()
	sem, ok := ps.providerSem[provider]
	if ok {
		return sem
	}
	sem = make(chan struct{}, ps.providerLimit)
	ps.providerSem[provider] = sem
	return sem
}

func (ps *ProbeScheduler) isCoolingDown(key string) bool {
	ps.seenMu.Lock()
	defer ps.seenMu.Unlock()
	last, ok := ps.seen[key]
	if !ok {
		return false
	}
	return time.Since(last) < ps.cooldown
}

func (ps *ProbeScheduler) markSeen(key string) {
	ps.seenMu.Lock()
	defer ps.seenMu.Unlock()
	ps.seen[key] = time.Now()
}

func clampInt(value, min, max int) int {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func normalizeProbeSource(source string) string {
	source = strings.TrimSpace(strings.ToLower(source))
	if source == "" {
		return probeSourceUnspecified
	}
	return source
}

func withProbeSource(ctx context.Context, source string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, probeSourceContextKey{}, normalizeProbeSource(source))
}

func probeSourceFromContext(ctx context.Context, fallback string) string {
	if ctx != nil {
		if value, ok := ctx.Value(probeSourceContextKey{}).(string); ok && strings.TrimSpace(value) != "" {
			return normalizeProbeSource(value)
		}
	}
	return normalizeProbeSource(fallback)
}

func formatProbeTimestamp(unixNano int64) string {
	if unixNano <= 0 {
		return ""
	}
	return time.Unix(0, unixNano).Format(time.RFC3339)
}

func (ps *ProbeScheduler) snapshotCounterMap(src map[string]uint64) map[string]uint64 {
	ps.ensureRecordState()
	ps.recordMu.Lock()
	defer ps.recordMu.Unlock()
	out := make(map[string]uint64, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func (ps *ProbeScheduler) snapshotRecentRecords() []ProbeRecord {
	ps.ensureRecordState()
	ps.recordMu.Lock()
	defer ps.recordMu.Unlock()
	if ps.recordCount == 0 {
		return []ProbeRecord{}
	}
	out := make([]ProbeRecord, 0, ps.recordCount)
	start := ps.recordCursor - ps.recordCount
	if start < 0 {
		start += len(ps.recentRecords)
	}
	for i := 0; i < ps.recordCount; i++ {
		idx := (start + i) % len(ps.recentRecords)
		out = append(out, ps.recentRecords[idx])
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].FinishedAt > out[j].FinishedAt
	})
	return out
}

func (ps *ProbeScheduler) snapshotRecentConsumerHits() []ProbeConsumerHit {
	ps.ensureRecordState()
	ps.recordMu.Lock()
	defer ps.recordMu.Unlock()
	if ps.consumerCount == 0 {
		return []ProbeConsumerHit{}
	}
	out := make([]ProbeConsumerHit, 0, ps.consumerCount)
	start := ps.consumerCursor - ps.consumerCount
	if start < 0 {
		start += len(ps.recentConsumerHits)
	}
	for i := 0; i < ps.consumerCount; i++ {
		idx := (start + i) % len(ps.recentConsumerHits)
		out = append(out, ps.recentConsumerHits[idx])
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].HitAt > out[j].HitAt
	})
	return out
}

func (ps *ProbeScheduler) snapshotRecentInvalidations() []ProbeInvalidation {
	ps.ensureRecordState()
	ps.recordMu.Lock()
	defer ps.recordMu.Unlock()
	if ps.invalidationCount == 0 {
		return []ProbeInvalidation{}
	}
	out := make([]ProbeInvalidation, 0, ps.invalidationCount)
	start := ps.invalidationCursor - ps.invalidationCount
	if start < 0 {
		start += len(ps.recentInvalidations)
	}
	for i := 0; i < ps.invalidationCount; i++ {
		idx := (start + i) % len(ps.recentInvalidations)
		out = append(out, ps.recentInvalidations[idx])
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].At > out[j].At
	})
	return out
}

func (ps *ProbeScheduler) snapshotWarmStateCounts() map[string]uint64 {
	ps.ensureRecordState()
	ps.recordMu.Lock()
	defer ps.recordMu.Unlock()
	out := map[string]uint64{
		warmStateReady:   0,
		warmStateStale:   0,
		warmStateInvalid: 0,
	}
	threshold := ps.stalenessThreshold()
	now := time.Now()
	for _, warm := range ps.successfulWarm {
		switch probeWarmStateStatus(warm, threshold, now) {
		case warmStateInvalid:
			out[warmStateInvalid]++
		case warmStateStale:
			out[warmStateStale]++
		default:
			out[warmStateReady]++
		}
	}
	return out
}

func (ps *ProbeScheduler) snapshotWarmStates() []ProbeWarmSnapshot {
	ps.ensureRecordState()
	ps.recordMu.Lock()
	defer ps.recordMu.Unlock()
	out := make([]ProbeWarmSnapshot, 0, len(ps.successfulWarm))
	threshold := ps.stalenessThreshold()
	now := time.Now()
	for displayPath, warm := range ps.successfulWarm {
		state := probeWarmStateStatus(warm, threshold, now)
		fileName := path.Base(displayPath)
		if ps.fileDAO != nil {
			if entry, ok := ps.fileDAO.Get(displayPath); ok && entry != nil && strings.TrimSpace(entry.Name) != "" {
				fileName = entry.Name
			}
		}
		out = append(out, ProbeWarmSnapshot{
			DisplayPath:       displayPath,
			FileName:          fileName,
			Source:            warm.Source,
			State:             state,
			FinishedAt:        formatTimeValue(warm.FinishedAt),
			ConsumerHitCount:  warm.ConsumerHitCount,
			LastConsumerHitAt: formatTimeValue(warm.LastConsumerHitAt),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].FinishedAt > out[j].FinishedAt
	})
	return out
}

func (ps *ProbeScheduler) recordRunning(item probeItem, startedAt time.Time) {
	ps.ensureRecordState()
	ps.recordMu.Lock()
	defer ps.recordMu.Unlock()
	ps.statusCounts[probeStatusRunning]++
	_ = startedAt
}

func (ps *ProbeScheduler) finishRecord(item probeItem, startedAt time.Time, status string, result probeExecutionResult) {
	ps.ensureRecordState()
	now := time.Now()
	record := ProbeRecord{
		DisplayPath:   item.file.DisplayPath,
		EncryptedPath: item.file.EncryptedPath,
		TargetHost:    providerHostForRecord(item.file.TargetURL),
		ProviderKey:   ProviderKey(item.file.TargetURL, item.file.DisplayPath),
		FileName:      item.file.FileName,
		Source:        item.source,
		Priority:      probePriority(item.source),
		Status:        status,
		ResolvedSize:  result.resolvedSize,
		SizeSource:    result.sizeSource,
		UsedAuthMode:  result.usedAuthMode,
		FailureReason: result.failureReason,
		RawURLFetched: result.rawURLFetched,
		RangeProbed:   result.rangeProbed,
		MetaPersisted: result.metaPersisted,
		QueueWaitMs:   startedAt.Sub(item.queuedAt).Milliseconds(),
		StartedAt:     startedAt.Format(time.RFC3339),
		FinishedAt:    now.Format(time.RFC3339),
		DurationMs:    now.Sub(startedAt).Milliseconds(),
	}
	ps.recordMu.Lock()
	defer ps.recordMu.Unlock()
	ps.statusCounts[status]++
	ps.sourceCounts[item.source]++
	if result.failureReason != "" {
		ps.recentFailureReasons[result.failureReason]++
	}
	if warm, ok := ps.successfulWarm[item.file.DisplayPath]; ok {
		applyWarmStateToRecord(&record, warm, now, ps.stalenessThreshold())
	}
	ps.recentRecords[ps.recordCursor] = record
	ps.recordCursor = (ps.recordCursor + 1) % len(ps.recentRecords)
	if ps.recordCount < len(ps.recentRecords) {
		ps.recordCount++
	}
	atomic.StoreInt64(&ps.lastRecordFinishedNano, now.UnixNano())
	if status == probeStatusSuccess {
		warm := ps.successfulWarm[item.file.DisplayPath]
		warm.Source = item.source
		warm.FinishedAt = now
		warm.State = warmStateReady
		ps.successfulWarm[item.file.DisplayPath] = warm
		applyWarmStateToRecord(&ps.recentRecords[(ps.recordCursor-1+len(ps.recentRecords))%len(ps.recentRecords)], warm, now, ps.stalenessThreshold())
		atomic.StoreInt64(&ps.lastSuccessAtUnixNano, now.UnixNano())
	}
	if status == probeStatusFailed {
		atomic.StoreInt64(&ps.lastFailureAtUnixNano, now.UnixNano())
	}
}

func (ps *ProbeScheduler) recordTerminal(file FileItem, source, status string, reportedSize int64, result probeExecutionResult) {
	ps.ensureRecordState()
	now := time.Now()
	record := ProbeRecord{
		DisplayPath:   file.DisplayPath,
		EncryptedPath: file.EncryptedPath,
		TargetHost:    providerHostForRecord(file.TargetURL),
		ProviderKey:   ProviderKey(file.TargetURL, file.DisplayPath),
		FileName:      file.FileName,
		Source:        source,
		Priority:      probePriority(source),
		Status:        status,
		ReportedSize:  reportedSize,
		ResolvedSize:  result.resolvedSize,
		SizeSource:    result.sizeSource,
		UsedAuthMode:  result.usedAuthMode,
		FailureReason: result.failureReason,
		RawURLFetched: result.rawURLFetched,
		RangeProbed:   result.rangeProbed,
		MetaPersisted: result.metaPersisted,
		StartedAt:     now.Format(time.RFC3339),
		FinishedAt:    now.Format(time.RFC3339),
	}
	ps.recordMu.Lock()
	defer ps.recordMu.Unlock()
	ps.statusCounts[status]++
	ps.sourceCounts[source]++
	if result.failureReason != "" {
		ps.recentFailureReasons[result.failureReason]++
	}
	if warm, ok := ps.successfulWarm[file.DisplayPath]; ok {
		applyWarmStateToRecord(&record, warm, now, ps.stalenessThreshold())
	}
	ps.recentRecords[ps.recordCursor] = record
	ps.recordCursor = (ps.recordCursor + 1) % len(ps.recentRecords)
	if ps.recordCount < len(ps.recentRecords) {
		ps.recordCount++
	}
	atomic.StoreInt64(&ps.lastRecordFinishedNano, now.UnixNano())
	if status == probeStatusSuccess {
		warm := ps.successfulWarm[file.DisplayPath]
		warm.Source = source
		warm.FinishedAt = now
		warm.State = warmStateReady
		ps.successfulWarm[file.DisplayPath] = warm
		applyWarmStateToRecord(&ps.recentRecords[(ps.recordCursor-1+len(ps.recentRecords))%len(ps.recentRecords)], warm, now, ps.stalenessThreshold())
		atomic.StoreInt64(&ps.lastSuccessAtUnixNano, now.UnixNano())
	}
	if status == probeStatusFailed {
		atomic.StoreInt64(&ps.lastFailureAtUnixNano, now.UnixNano())
	}
}

func providerHostForRecord(targetURL string) string {
	parsed, err := url.Parse(targetURL)
	if err != nil || parsed == nil {
		return ""
	}
	return parsed.Host
}

func (ps *ProbeScheduler) ensureRecordState() {
	if ps == nil {
		return
	}
	ps.recordMu.Lock()
	defer ps.recordMu.Unlock()
	if ps.recentRecords == nil {
		ps.recentRecords = make([]ProbeRecord, probeRecordBufferSize)
	}
	if ps.sourceCounts == nil {
		ps.sourceCounts = make(map[string]uint64)
	}
	if ps.statusCounts == nil {
		ps.statusCounts = make(map[string]uint64)
	}
	if ps.recentFailureReasons == nil {
		ps.recentFailureReasons = make(map[string]uint64)
	}
	if ps.successfulWarm == nil {
		ps.successfulWarm = make(map[string]probeWarmState)
	}
	if ps.consumerHitsBySource == nil {
		ps.consumerHitsBySource = make(map[string]uint64)
	}
	if ps.consumerHitsByScenario == nil {
		ps.consumerHitsByScenario = make(map[string]uint64)
	}
	if ps.recentConsumerHits == nil {
		ps.recentConsumerHits = make([]ProbeConsumerHit, probeRecordBufferSize)
	}
	if ps.recentInvalidations == nil {
		ps.recentInvalidations = make([]ProbeInvalidation, probeRecordBufferSize)
	}
}

func (ps *ProbeScheduler) RecordConsumerHit(file FileItem, scenario string) {
	if ps == nil {
		return
	}
	ps.ensureRecordState()
	scenario = normalizeProbeSource(scenario)
	ps.recordMu.Lock()
	defer ps.recordMu.Unlock()
	warm, ok := ps.successfulWarm[file.DisplayPath]
	if !ok {
		return
	}
	now := time.Now()
	if !warm.LastConsumerHitAt.IsZero() && now.Sub(warm.LastConsumerHitAt) < consumerHitDedupeWindow {
		return
	}
	warm.LastConsumerHitAt = now
	warm.ConsumerHitCount++
	ps.successfulWarm[file.DisplayPath] = warm
	ps.applyWarmStateToRecordsLocked(file.DisplayPath, warm, now)
	atomic.AddUint64(&ps.consumerHitTotal, 1)
	ps.consumerHitsBySource[warm.Source]++
	ps.consumerHitsByScenario[scenario]++
	hit := ProbeConsumerHit{
		DisplayPath: file.DisplayPath,
		FileName:    file.FileName,
		Source:      warm.Source,
		Scenario:    scenario,
		HitAt:       now.Format(time.RFC3339),
	}
	ps.recentConsumerHits[ps.consumerCursor] = hit
	ps.consumerCursor = (ps.consumerCursor + 1) % len(ps.recentConsumerHits)
	if ps.consumerCount < len(ps.recentConsumerHits) {
		ps.consumerCount++
	}
}

func (ps *ProbeScheduler) InvalidateWarm(displayPath, reason string) {
	if ps == nil {
		return
	}
	displayPath = strings.TrimSpace(displayPath)
	if displayPath == "" {
		return
	}
	ps.ensureRecordState()
	ps.recordMu.Lock()
	defer ps.recordMu.Unlock()
	now := time.Now()
	if warm, ok := ps.successfulWarm[displayPath]; ok {
		warm.State = warmStateInvalid
		ps.successfulWarm[displayPath] = warm
		ps.applyWarmStateToRecordsLocked(displayPath, warm, now)
	}
	atomic.AddUint64(&ps.invalidationsTotal, 1)
	event := ProbeInvalidation{
		DisplayPath: displayPath,
		Reason:      strings.TrimSpace(reason),
		At:          now.Format(time.RFC3339),
	}
	ps.recentInvalidations[ps.invalidationCursor] = event
	ps.invalidationCursor = (ps.invalidationCursor + 1) % len(ps.recentInvalidations)
	if ps.invalidationCount < len(ps.recentInvalidations) {
		ps.invalidationCount++
	}
}

func (ps *ProbeScheduler) consumerHitRate() float64 {
	successes := atomic.LoadUint64(&ps.filesSucceededTotal)
	if successes == 0 {
		return 0
	}
	hits := atomic.LoadUint64(&ps.consumerHitTotal)
	return float64(hits) / float64(successes)
}

func (ps *ProbeScheduler) stalenessThreshold() time.Duration {
	if ps != nil && ps.cfg != nil && ps.cfg.AlistServer.UpstreamStalenessMinutes > 0 {
		return time.Duration(ps.cfg.AlistServer.UpstreamStalenessMinutes) * time.Minute
	}
	return 30 * time.Minute
}

func formatTimeValue(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.Format(time.RFC3339)
}

func probePriority(source string) string {
	switch normalizeProbeSource(source) {
	case probeSourceFirstFrame:
		return "high"
	case probeSourceStartupScan:
		return "low"
	default:
		return "normal"
	}
}

func probeWarmStateStatus(warm probeWarmState, threshold time.Duration, now time.Time) string {
	if warm.State == warmStateInvalid {
		return warmStateInvalid
	}
	if !warm.FinishedAt.IsZero() && now.Sub(warm.FinishedAt) > threshold {
		return warmStateStale
	}
	return warmStateReady
}

func applyWarmStateToRecord(record *ProbeRecord, warm probeWarmState, now time.Time, threshold time.Duration) {
	if record == nil {
		return
	}
	record.WarmState = probeWarmStateStatus(warm, threshold, now)
	record.Invalidated = record.WarmState == warmStateInvalid
	record.ConsumerHitCount = warm.ConsumerHitCount
	record.LastConsumerHitAt = formatTimeValue(warm.LastConsumerHitAt)
}

func (ps *ProbeScheduler) applyWarmStateToRecordsLocked(displayPath string, warm probeWarmState, now time.Time) {
	if ps == nil || ps.recordCount == 0 {
		return
	}
	threshold := ps.stalenessThreshold()
	start := ps.recordCursor - ps.recordCount
	if start < 0 {
		start += len(ps.recentRecords)
	}
	for i := 0; i < ps.recordCount; i++ {
		idx := (start + i) % len(ps.recentRecords)
		if ps.recentRecords[idx].DisplayPath != displayPath {
			continue
		}
		applyWarmStateToRecord(&ps.recentRecords[idx], warm, now, threshold)
	}
}

func splitProvider(providerKey string) (string, string) {
	parts := strings.SplitN(providerKey, "::", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return providerKey, ""
}

// ensureAuth returns auth headers, falling back to configured scan credentials
// if the provided headers have no Authorization or Cookie.
func (ps *ProbeScheduler) ensureAuth(headers http.Header) (http.Header, string) {
	if headers == nil {
		headers = make(http.Header)
	}
	// User-provided auth takes priority
	if headers.Get("Authorization") != "" || headers.Get("Cookie") != "" {
		return headers, "request"
	}
	if ps.cfg == nil {
		return headers, "none"
	}
	// Try scan auth header first
	if raw := strings.TrimSpace(ps.cfg.AlistServer.ScanAuthHeader); raw != "" {
		headers.Set("Authorization", raw)
		return headers, "scan_header"
	}
	// Try JWT login with scan credentials (alist /api/fs/list needs token, not Basic auth)
	username := ps.cfg.AlistServer.ScanUsername
	password := ps.cfg.AlistServer.ScanPassword
	if username != "" && password != "" {
		if token := fetchAlistJWT(ps.cfg.GetAlistURL(), username, password); token != "" {
			headers.Set("Authorization", token)
			return headers, "scan_jwt"
		}
		// Fallback to Basic auth
		token := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		headers.Set("Authorization", "Basic "+token)
		return headers, "scan_basic"
	}
	return headers, "none"
}

func fetchAlistJWT(alistURL, username, password string) string {
	loginURL := alistURL + "/api/auth/login"
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	req, err := http.NewRequest(http.MethodPost, loginURL, bytes.NewReader(body))
	if err != nil {
		return ""
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var result struct {
		Code int `json:"code"`
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if json.Unmarshal(respBody, &result) != nil || result.Code != 200 || result.Data.Token == "" {
		return ""
	}
	return result.Data.Token
}

// fetchRawURL calls alist /api/fs/get to get the signed raw_url and caches it.
// Used by ProbeScheduler to pre-warm raw_url for WebDAV zero-latency playback.
// staleThreshold: if cached raw_url is fresher than this, skip the fetch.
func fetchRawURL(ctx context.Context, alistURL, displayPath, realPath string, authHeaders http.Header, fileDAO *dao.FileDAO, staleThreshold time.Duration) rawURLFetchResult {
	if alistURL == "" || fileDAO == nil {
		return rawURLFetchResult{}
	}
	// Check if cached raw_url is still fresh.
	if cached, ok := fileDAO.Get(displayPath); ok && cached != nil &&
		strings.TrimSpace(cached.RawURL) != "" &&
		cached.UpstreamStaleness() < staleThreshold {
		return rawURLFetchResult{RawURL: cached.RawURL}
	}

	body, _ := json.Marshal(map[string]string{"path": realPath})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, alistURL+"/api/fs/get", bytes.NewReader(body))
	if err != nil {
		return rawURLFetchResult{}
	}
	req.Header.Set("Content-Type", "application/json")
	copyAuthHeaders(req, authHeaders)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return rawURLFetchResult{FailureReason: "raw_url_fetch:" + err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
		fileDAO.InvalidateDisplayPath(displayPath)
		fileDAO.DeleteEncPathMapping(displayPath)
		return rawURLFetchResult{
			StatusCode:    resp.StatusCode,
			FailureReason: "raw_url_http_" + http.StatusText(resp.StatusCode),
		}
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	var result struct {
		Code int `json:"code"`
		Data struct {
			RawURL string `json:"raw_url"`
			Size   int64  `json:"size"`
		} `json:"data"`
	}
	if json.Unmarshal(respBody, &result) != nil {
		return rawURLFetchResult{StatusCode: resp.StatusCode, FailureReason: "raw_url_invalid_json"}
	}
	if result.Code != 200 || result.Data.RawURL == "" {
		return rawURLFetchResult{StatusCode: resp.StatusCode, FailureReason: "raw_url_empty"}
	}
	fileDAO.Set(&dao.FileInfo{
		Path:              displayPath,
		Size:              result.Data.Size,
		RawURL:            result.Data.RawURL,
		UpstreamFetchedAt: time.Now(),
	})
	return rawURLFetchResult{RawURL: result.Data.RawURL, StatusCode: resp.StatusCode}
}
