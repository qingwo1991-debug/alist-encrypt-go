package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	ctx       context.Context
	cancel    context.CancelFunc
	workerWG  sync.WaitGroup
	stopOnce  sync.Once

	queue    chan probeItem
	workers  int
	cooldown time.Duration
	minDelay time.Duration
	maxDelay time.Duration

	seenMu  sync.Mutex
	seen    map[string]time.Time
	pending map[string]struct{}

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

	// JWT caching to avoid repeated login requests
	cachedJWT       string
	cachedJWTExpiry time.Time
	cachedJWTScope  [sha256.Size]byte
	jwtMu           sync.Mutex
	jwtFetcher      func(alistURL, username, password string) string
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
	probeSourceDirSync       = "dir_sync"
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
	DisplayPath       string `json:"display_path"`
	EncryptedPath     string `json:"encrypted_path"`
	TargetHost        string `json:"target_host"`
	ProviderKey       string `json:"provider_key"`
	FileName          string `json:"file_name"`
	Source            string `json:"source"`
	Priority          string `json:"priority"`
	Status            string `json:"status"`
	WarmState         string `json:"warm_state"`
	ReportedSize      int64  `json:"reported_size"`
	ResolvedSize      int64  `json:"resolved_size"`
	SizeSource        string `json:"size_source"`
	UsedAuthMode      string `json:"used_auth_mode"`
	FailureReason     string `json:"failure_reason"`
	RawURLFetched     bool   `json:"raw_url_fetched"`
	RangeProbed       bool   `json:"range_probed"`
	MetaPersisted     bool   `json:"meta_persisted"`
	QueueWaitMs       int64  `json:"queue_wait_ms"`
	Invalidated       bool   `json:"invalidated"`
	ConsumerHitCount  uint64 `json:"consumer_hit_count"`
	LastConsumerHitAt string `json:"last_consumer_hit_at"`
	StartedAt         string `json:"started_at"`
	FinishedAt        string `json:"finished_at"`
	DurationMs        int64  `json:"duration_ms"`
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
	Size          int64
	Source        string
	StatusCode    int
	FailureReason string
}

type probeSourceContextKey struct{}

// SetRawURLFetcher sets the raw_url pre-fetch callback for probe scheduler.
func (ps *ProbeScheduler) SetRawURLFetcher(f RawURLFetcher) {
	ps.rawURLFetcher = f
}

func NewProbeScheduler(cfg *config.Config, fileDAO *dao.FileDAO, metaStore FileMetaStore, stream *proxy.StreamProxy) *ProbeScheduler {
	workerCtx, cancelWorkers := context.WithCancel(context.Background())
	alist := config.AlistServer{}
	if cfg != nil {
		alist = cfg.AlistServerSnapshot()
	}
	ps := &ProbeScheduler{
		cfg:                    cfg,
		resolver:               NewFileSizeResolver(cfg, fileDAO, metaStore, 4, getMinMetaSize(cfg), getRedirectMaxHops(cfg)),
		fileDAO:                fileDAO,
		metaStore:              metaStore,
		stream:                 stream,
		enabled:                cfg != nil && alist.EnableBackgroundProbe,
		ctx:                    workerCtx,
		cancel:                 cancelWorkers,
		seen:                   make(map[string]time.Time),
		pending:                make(map[string]struct{}),
		providerSem:            make(map[string]chan struct{}),
		recentRecords:          make([]ProbeRecord, probeRecordBufferSize),
		recentConsumerHits:     make([]ProbeConsumerHit, probeRecordBufferSize),
		recentInvalidations:    make([]ProbeInvalidation, probeRecordBufferSize),
		successfulWarm:         make(map[string]probeWarmState),
		sourceCounts:           make(map[string]uint64),
		statusCounts:           make(map[string]uint64),
		recentFailureReasons:   make(map[string]uint64),
		consumerHitsBySource:   make(map[string]uint64),
		consumerHitsByScenario: make(map[string]uint64),
	}

	if cfg == nil {
		return ps
	}

	ps.workers = clampInt(alist.ProbeConcurrency, 1, 20)
	ps.providerLimit = clampInt(alist.ProbeProviderConcurrency, 1, 5)
	ps.minDelay = time.Duration(clampInt(alist.ProbeMinDelayMs, 0, 60000)) * time.Millisecond
	ps.maxDelay = time.Duration(clampInt(alist.ProbeMaxDelayMs, 0, 120000)) * time.Millisecond
	ps.cooldown = time.Duration(clampInt(alist.ProbeCooldownMinutes, 1, 10080)) * time.Minute
	queueSize := clampInt(alist.ProbeQueueSize, 100, 10000)
	ps.queue = make(chan probeItem, queueSize)
	ps.minSizeBytes = alist.ProbeMinSizeBytes

	if ps.enabled {
		for i := 0; i < ps.workers; i++ {
			ps.workerWG.Add(1)
			go func() {
				defer ps.workerWG.Done()
				ps.worker()
			}()
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
	select {
	case <-ps.done():
		return
	default:
	}
	ps.ensureRecordState()
	source = normalizeProbeSource(source)
	if file.DisplayPath == "" || file.TargetURL == "" {
		return
	}
	atomic.AddUint64(&ps.filesDiscoveredTotal, 1)
	forcePlaybackWarmup := source == probeSourceFirstFrame
	if !forcePlaybackWarmup && ps.cfg != nil && ps.cfg.AlistServerSnapshot().ScanVideoOnly && !isVideoFile(file.FileName) {
		ps.recordTerminal(file, source, probeStatusSkippedSize, reportedSize, probeExecutionResult{})
		atomic.AddUint64(&ps.filesSkippedTotal, 1)
		return
	}

	effectiveSize := reportedSize
	rangeProbeNeeded := ps.shouldProbeRange(file, reportedSize)

	if ps.fileDAO != nil {
		if size, ok := ps.fileDAO.GetFileSize(file.DisplayPath); ok && size > 0 {
			effectiveSize = size
			if !rangeProbeNeeded {
				rangeProbeNeeded = ps.shouldProbeRange(file, size)
			}
		}
	}
	if ps.metaStore != nil {
		providerKey := ProviderKey(file.TargetURL, file.DisplayPath)
		if meta, ok, _ := ps.metaStore.Get(context.Background(), providerKey, file.DisplayPath); ok {
			if meta.Size > 0 {
				effectiveSize = meta.Size
			}
			if !rangeProbeNeeded {
				rangeProbeNeeded = ps.shouldProbeRange(file, meta.Size)
			}
		}
	}
	sizeProbeNeeded := forcePlaybackWarmup || ps.shouldProbeSize(effectiveSize)
	if !sizeProbeNeeded && !rangeProbeNeeded {
		ps.recordTerminal(file, source, probeStatusSkippedSize, reportedSize, probeExecutionResult{})
		atomic.AddUint64(&ps.filesSkippedTotal, 1)
		return
	}
	if effectiveSize > 0 {
		// The listing/PROPFIND size is already useful input. Without carrying it
		// into FileItem the resolver performs redundant HEAD/Range requests and
		// can report a false size_resolve failure for an otherwise known file.
		file.PropfindSize = effectiveSize
	}

	key := probeCooldownKey(file)
	reservedAt, skipStatus := ps.reserveProbe(key, ps.warmNeedsRefresh(file.DisplayPath))
	if skipStatus != "" {
		if skipStatus == probeStatusSkippedCD {
			atomic.AddUint64(&ps.cooldownSkips, 1)
		}
		atomic.AddUint64(&ps.filesSkippedTotal, 1)
		ps.recordTerminal(file, source, skipStatus, reportedSize, probeExecutionResult{})
		return
	}

	select {
	case <-ps.done():
		ps.releaseProbeReservation(key, reservedAt, true)
		return
	case ps.queue <- probeItem{file: file, authHeaders: authHeaders.Clone(), source: source, queuedAt: time.Now()}:
		atomic.AddUint64(&ps.enqueuedTotal, 1)
		atomic.AddUint64(&ps.filesQueuedTotal, 1)
		ps.recordTerminal(file, source, probeStatusQueued, reportedSize, probeExecutionResult{})
	default:
		ps.releaseProbeReservation(key, reservedAt, true)
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
		"enabled":                   ps.enabled,
		"workers":                   ps.workers,
		"provider_limit":            ps.providerLimit,
		"queue_len":                 queueLen,
		"queue_cap":                 queueCap,
		"enqueued_total":            atomic.LoadUint64(&ps.enqueuedTotal),
		"dropped_total":             atomic.LoadUint64(&ps.droppedTotal),
		"cooldown_skips":            atomic.LoadUint64(&ps.cooldownSkips),
		"running_count":             atomic.LoadUint64(&ps.runningCount),
		"files_discovered_total":    atomic.LoadUint64(&ps.filesDiscoveredTotal),
		"files_queued_total":        atomic.LoadUint64(&ps.filesQueuedTotal),
		"files_succeeded_total":     atomic.LoadUint64(&ps.filesSucceededTotal),
		"files_failed_total":        atomic.LoadUint64(&ps.filesFailedTotal),
		"files_skipped_total":       atomic.LoadUint64(&ps.filesSkippedTotal),
		"files_raw_url_fetched":     atomic.LoadUint64(&ps.filesRawURLFetched),
		"files_range_probed":        atomic.LoadUint64(&ps.filesRangeProbed),
		"files_meta_persisted":      atomic.LoadUint64(&ps.filesMetaPersisted),
		"consumer_hit_total":        atomic.LoadUint64(&ps.consumerHitTotal),
		"consumer_hit_rate":         ps.consumerHitRate(),
		"last_success_at":           formatProbeTimestamp(atomic.LoadInt64(&ps.lastSuccessAtUnixNano)),
		"last_failure_at":           formatProbeTimestamp(atomic.LoadInt64(&ps.lastFailureAtUnixNano)),
		"last_record_finished_at":   formatProbeTimestamp(atomic.LoadInt64(&ps.lastRecordFinishedNano)),
		"source_counts":             ps.snapshotCounterMap(ps.sourceCounts),
		"status_counts":             ps.snapshotCounterMap(ps.statusCounts),
		"failure_reasons":           ps.snapshotCounterMap(ps.recentFailureReasons),
		"consumer_hits_by_source":   ps.snapshotCounterMap(ps.consumerHitsBySource),
		"consumer_hits_by_scenario": ps.snapshotCounterMap(ps.consumerHitsByScenario),
		"recent_records":            ps.snapshotRecentRecords(),
		"recent_consumer_hits":      ps.snapshotRecentConsumerHits(),
		"invalidations_total":       atomic.LoadUint64(&ps.invalidationsTotal),
		"recent_invalidations":      ps.snapshotRecentInvalidations(),
		"warm_state_counts":         ps.snapshotWarmStateCounts(),
		"current_warm_states":       ps.snapshotWarmStates(),
	}
}

func (ps *ProbeScheduler) shouldProbeSize(size int64) bool {
	if size <= 0 {
		return true
	}
	if ps.minSizeBytes <= 0 {
		return true
	}
	return size >= ps.minSizeBytes
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
	for {
		select {
		case <-ps.done():
			return
		case item := <-ps.queue:
			ps.runItem(item)
		}
	}
}

// Stop cancels queued and active background probes and waits for workers to
// release references to stores and HTTP clients before server shutdown.
func (ps *ProbeScheduler) Stop() {
	if ps == nil {
		return
	}
	ps.stopOnce.Do(func() {
		if ps.cancel != nil {
			ps.cancel()
		}
		ps.workerWG.Wait()
	})
}

func (ps *ProbeScheduler) probeContext() context.Context {
	if ps != nil && ps.ctx != nil {
		return ps.ctx
	}
	return context.Background()
}

func (ps *ProbeScheduler) done() <-chan struct{} {
	if ps != nil && ps.ctx != nil {
		return ps.ctx.Done()
	}
	return nil
}

func (ps *ProbeScheduler) runItem(item probeItem) {
	ps.ensureRecordState()
	defer ps.releaseProbeReservation(probeCooldownKey(item.file), time.Time{}, false)
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

	// Workers wait for their provider slot. Dropping here permanently loses an
	// item that was already marked as seen for the full cooldown window.
	select {
	case <-ps.done():
		ps.finishRecord(item, startedAt, probeStatusFailed, probeExecutionResult{failureReason: "scheduler_stopped"})
		return
	case sem <- struct{}{}:
	}
	defer func() { <-sem }()

	// Only delay files that were already successfully warmed. A directory
	// listing populates the size cache before the first warmup, so using size
	// presence here incorrectly delays every first-time file.
	// First-time probes execute immediately to warm the cache before user clicks download.
	if ps.hasSuccessfulWarm(item.file.DisplayPath) && ps.maxDelay > 0 {
		delay := ps.minDelay
		if ps.maxDelay > ps.minDelay {
			delta := ps.maxDelay - ps.minDelay
			delay += time.Duration(rand.Int63n(int64(delta)))
		}
		timer := time.NewTimer(delay)
		select {
		case <-ps.done():
			if !timer.Stop() {
				<-timer.C
			}
			ps.finishRecord(item, startedAt, probeStatusFailed, probeExecutionResult{failureReason: "scheduler_stopped"})
			return
		case <-timer.C:
		}
	}

	// Fallback to configured scan credentials if no user auth available
	authHeaders, authMode := ps.ensureAuth(item.authHeaders)

	resultState := probeExecutionResult{}
	probeCtx := ps.probeContext()
	result := ps.resolver.ResolveSingle(probeCtx, item.file, authHeaders)
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
	if ps.cfg != nil {
		if minutes := ps.cfg.AlistServerSnapshot().UpstreamStalenessMinutes; minutes > 0 {
			stalenessThreshold = time.Duration(minutes) * time.Minute
		}
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
		rawURLResult := fetchRawURL(probeCtx, alistURL, item.file.DisplayPath, item.file.EncryptedPath, authHeaders, ps.fileDAO, stalenessThreshold)
		if rawURLResult.RawURL != "" {
			resultState.rawURLFetched = true
			atomic.AddUint64(&ps.filesRawURLFetched, 1)
			if item.file.PasswdInfo != nil && ps.stream != nil {
				meta := ps.stream.InspectEncryptedContent(probeCtx, rawURLResult.RawURL, authHeaders, item.file.PasswdInfo, rawURLResult.Size)
				if meta.IsV2() && meta.PlainSize > 0 {
					cached := &dao.FileInfo{
						Path:              item.file.DisplayPath,
						EncryptedPath:     item.file.EncryptedPath,
						Name:              item.file.FileName,
						Size:              meta.PlainSize,
						CiphertextSize:    meta.TotalCiphertextSize(),
						ContentVersion:    meta.Version,
						HeaderLen:         meta.HeaderLen,
						NonceField:        append([]byte(nil), meta.NonceField...),
						RawURL:            rawURLResult.RawURL,
						RawURLAuthScope:   rawURLAuthScope(authHeaders),
						UpstreamFetchedAt: time.Now(),
					}
					if existing, ok := ps.fileDAO.Get(item.file.DisplayPath); ok && existing != nil {
						if strings.TrimSpace(existing.Name) != "" {
							cached.Name = existing.Name
						}
						cached.Sign = existing.Sign
						cached.IsDir = existing.IsDir
					}
					_ = ps.fileDAO.Set(cached)
				}
			}
		} else if resultState.failureReason == "" && rawURLResult.FailureReason != "" {
			resultState.failureReason = rawURLResult.FailureReason
		}
		if rawURLResult.StatusCode == http.StatusUnauthorized || rawURLResult.StatusCode == http.StatusForbidden || rawURLResult.StatusCode == http.StatusNotFound {
			ps.InvalidateWarm(item.file.DisplayPath, "raw_url_upstream_4xx")
		}
		// Invalidate JWT cache on 401 to force re-authentication on next probe
		if rawURLResult.StatusCode == http.StatusUnauthorized {
			ps.invalidateJWTCache()
		}
	}
	// Probe Range capability against the URL a real player will hit. The alist
	// /d/ or /dav/ front-end responds 401/302 and does not itself serve Range, so
	// probing it teaches nothing and leaves files_range_probed at zero. Prefer
	// the cached raw_url (the actual CDN/object URL) that was fetched above;
	// fall back to the internal target and let ProbeRangeCompatibility follow
	// redirects to the real storage.
	probeTargetURL := item.file.TargetURL
	if ps.fileDAO != nil {
		if info, ok := ps.fileDAO.Get(item.file.DisplayPath); ok && info != nil && strings.TrimSpace(info.RawURL) != "" {
			probeTargetURL = info.RawURL
		}
	}
	if ps.stream != nil && ps.stream.ProbeRangeCompatibility(probeCtx, probeTargetURL, authHeaders, item.file.CompatStorageKey) {
		resultState.rangeProbed = true
		atomic.AddUint64(&ps.filesRangeProbed, 1)
	}
	usefulWarmArtifact := resultState.rawURLFetched || resultState.rangeProbed || (resultState.resolvedSize > 0 && item.file.PropfindSize <= 0)
	status := probeStatusSuccess
	if !usefulWarmArtifact || (resultState.failureReason != "" && !resultState.rawURLFetched) {
		status = probeStatusFailed
		if resultState.failureReason == "" {
			resultState.failureReason = "no_warm_artifact"
		}
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

// reserveProbe atomically de-duplicates queued/running work and starts the
// cooldown. Stale or invalid state may bypass cooldown, but never an already
// pending refresh for the same file.
func (ps *ProbeScheduler) reserveProbe(key string, bypassCooldown bool) (time.Time, string) {
	ps.seenMu.Lock()
	defer ps.seenMu.Unlock()
	if ps.pending == nil {
		ps.pending = make(map[string]struct{})
	}
	if _, ok := ps.pending[key]; ok {
		return time.Time{}, probeStatusSkippedDup
	}
	if last, ok := ps.seen[key]; ok && time.Since(last) < ps.cooldown && !bypassCooldown {
		return time.Time{}, probeStatusSkippedCD
	}
	now := time.Now()
	ps.pending[key] = struct{}{}
	ps.seen[key] = now
	return now, ""
}

func (ps *ProbeScheduler) releaseProbeReservation(key string, reservedAt time.Time, rollbackCooldown bool) {
	if ps == nil {
		return
	}
	ps.seenMu.Lock()
	defer ps.seenMu.Unlock()
	delete(ps.pending, key)
	if rollbackCooldown {
		if seenAt, ok := ps.seen[key]; ok && seenAt.Equal(reservedAt) {
			delete(ps.seen, key)
		}
	}
}

func (ps *ProbeScheduler) clearCooldownForFile(file FileItem) {
	if ps == nil {
		return
	}
	key := probeCooldownKey(file)
	ps.seenMu.Lock()
	delete(ps.seen, key)
	ps.seenMu.Unlock()
}

func (ps *ProbeScheduler) clearCooldownForDisplayPath(displayPath string) {
	if ps == nil || strings.TrimSpace(displayPath) == "" {
		return
	}
	suffix := "::" + strings.TrimSpace(displayPath)
	ps.seenMu.Lock()
	for key := range ps.seen {
		if strings.HasSuffix(key, suffix) {
			delete(ps.seen, key)
		}
	}
	ps.seenMu.Unlock()
}

func probeCooldownKey(file FileItem) string {
	provider := ProviderKey(file.TargetURL, file.DisplayPath)
	displayPath := strings.TrimSpace(file.DisplayPath)
	if displayPath == "" {
		displayPath = strings.TrimSpace(file.EncryptedPath)
	}
	return provider + "::" + displayPath
}

func (ps *ProbeScheduler) hasSuccessfulWarm(displayPath string) bool {
	if ps == nil || strings.TrimSpace(displayPath) == "" {
		return false
	}
	ps.ensureRecordState()
	ps.recordMu.Lock()
	defer ps.recordMu.Unlock()
	warm, ok := ps.successfulWarm[displayPath]
	return ok && warm.State != warmStateInvalid
}

func (ps *ProbeScheduler) warmNeedsRefresh(displayPath string) bool {
	if ps == nil || strings.TrimSpace(displayPath) == "" {
		return false
	}
	ps.ensureRecordState()
	ps.recordMu.Lock()
	defer ps.recordMu.Unlock()
	warm, ok := ps.successfulWarm[displayPath]
	return ok && probeWarmStateStatus(warm, ps.stalenessThreshold(), time.Now()) != warmStateReady
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
	if status == probeStatusFailed {
		// A failed attempt must not suppress this file for the full configured
		// cooldown. The next scan or real playback can retry after credentials or
		// a signed URL have recovered.
		ps.clearCooldownForFile(item.file)
	}
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
	// Routine scan skips can outnumber useful events by millions and otherwise
	// evict every success/failure from the small recent-record ring. Keep their
	// aggregate counters without flooding the diagnostic sample.
	if status == probeStatusSkippedSize || status == probeStatusSkippedCD {
		atomic.StoreInt64(&ps.lastRecordFinishedNano, now.UnixNano())
		return
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
	if probeWarmStateStatus(warm, ps.stalenessThreshold(), now) != warmStateReady {
		return
	}
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
	// Invalidation is an explicit signal that a cached raw URL/meta result can
	// no longer help playback, so it must also release the per-file cooldown.
	ps.clearCooldownForDisplayPath(displayPath)
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
	if ps != nil && ps.cfg != nil {
		if minutes := ps.cfg.AlistServerSnapshot().UpstreamStalenessMinutes; minutes > 0 {
			return time.Duration(minutes) * time.Minute
		}
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
	case probeSourceDirSync:
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
	if idx := strings.Index(providerKey, "::/"); idx >= 0 {
		return providerKey[:idx], providerKey[idx+2:]
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
	alist := ps.cfg.AlistServerSnapshot()
	if raw := strings.TrimSpace(alist.ScanAuthHeader); raw != "" {
		headers.Set("Authorization", raw)
		return headers, "scan_header"
	}
	// Try JWT login with scan credentials (alist /api/fs/list needs token, not Basic auth)
	username := alist.ScanUsername
	password := alist.ScanPassword
	if username != "" && password != "" {
		alistURL := ps.cfg.GetAlistURL()
		scope := sha256.Sum256([]byte(alistURL + "\x00" + username + "\x00" + password))
		// Check cached JWT first (2-hour TTL)
		ps.jwtMu.Lock()
		if ps.cachedJWT != "" && ps.cachedJWTScope == scope && time.Now().Before(ps.cachedJWTExpiry) {
			token := ps.cachedJWT
			ps.jwtMu.Unlock()
			headers.Set("Authorization", token)
			return headers, "scan_jwt_cached"
		}
		ps.cachedJWT = ""
		ps.cachedJWTExpiry = time.Time{}
		ps.cachedJWTScope = [sha256.Size]byte{}
		ps.jwtMu.Unlock()

		fetcher := ps.jwtFetcher
		if fetcher == nil {
			fetcher = fetchAlistJWT
		}
		if token := fetcher(alistURL, username, password); token != "" {
			// Cache the token with 2-hour expiry
			ps.jwtMu.Lock()
			ps.cachedJWT = token
			ps.cachedJWTExpiry = time.Now().Add(2 * time.Hour)
			ps.cachedJWTScope = scope
			ps.jwtMu.Unlock()
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

// invalidateJWTCache clears the cached JWT token, forcing a fresh login on next ensureAuth call.
// Call this when receiving 401 Unauthorized responses to trigger re-authentication.
func (ps *ProbeScheduler) invalidateJWTCache() {
	ps.jwtMu.Lock()
	ps.cachedJWT = ""
	ps.cachedJWTExpiry = time.Time{}
	ps.cachedJWTScope = [sha256.Size]byte{}
	ps.jwtMu.Unlock()
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

// fetchRawURL calls alist metadata APIs to get the signed raw_url and caches it.
// Used by ProbeScheduler to pre-warm raw_url for WebDAV zero-latency playback.
// staleThreshold: if positive and the cached raw_url is fresher than this,
// skip the fetch. A zero/negative value explicitly forces an upstream refresh.
func fetchRawURL(ctx context.Context, alistURL, displayPath, realPath string, authHeaders http.Header, fileDAO *dao.FileDAO, staleThreshold time.Duration) rawURLFetchResult {
	if alistURL == "" || fileDAO == nil {
		return rawURLFetchResult{}
	}
	// Check if cached raw_url is still fresh.
	authScope := rawURLAuthScope(authHeaders)
	if staleThreshold > 0 {
		if cached, ok := fileDAO.Get(displayPath); ok && cached != nil &&
			cachedRawURLFresh(cached, staleThreshold, authScope) {
			return rawURLFetchResult{RawURL: cached.RawURL, Size: cached.Size, Source: "cache"}
		}
	}

	result := fetchRawURLViaAPI(ctx, alistURL, displayPath, realPath, authHeaders, fileDAO, "/api/fs/get")
	if strings.TrimSpace(result.RawURL) != "" || result.FailureReason != "raw_url_empty" {
		return result
	}

	linkResult := fetchRawURLViaAPI(ctx, alistURL, displayPath, realPath, authHeaders, fileDAO, "/api/fs/link")
	if strings.TrimSpace(linkResult.RawURL) != "" {
		return linkResult
	}
	resolverCfg := fileDAO.Config()
	if resolverCfg == nil {
		resolverCfg = config.Get()
	}
	redirectResult := resolveFinalRawURL(ctx, resolverCfg, alistURL, displayPath, realPath, authHeaders, fileDAO)
	if strings.TrimSpace(redirectResult.RawURL) != "" {
		return redirectResult
	}
	if linkResult.StatusCode != 0 || linkResult.FailureReason != "" {
		return linkResult
	}
	if redirectResult.FailureReason != "" {
		return redirectResult
	}
	return result
}

func fetchRawURLViaAPI(ctx context.Context, alistURL, displayPath, realPath string, authHeaders http.Header, fileDAO *dao.FileDAO, apiPath string) rawURLFetchResult {
	body, _ := json.Marshal(map[string]string{"path": realPath})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, alistURL+apiPath, bytes.NewReader(body))
	if err != nil {
		return rawURLFetchResult{}
	}
	req.Header.Set("Content-Type", "application/json")
	copyAuthHeaders(req, authHeaders)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return rawURLFetchResult{FailureReason: "raw_url_fetch:" + err.Error(), Source: rawURLSourceFromAPIPath(apiPath)}
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
		fileDAO.InvalidateRawURLForScope(displayPath, rawURLAuthScope(authHeaders))
		return rawURLFetchResult{
			StatusCode:    resp.StatusCode,
			Source:        rawURLSourceFromAPIPath(apiPath),
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
		return rawURLFetchResult{StatusCode: resp.StatusCode, FailureReason: "raw_url_invalid_json", Source: rawURLSourceFromAPIPath(apiPath)}
	}
	if result.Code != 200 || result.Data.RawURL == "" {
		return rawURLFetchResult{StatusCode: resp.StatusCode, FailureReason: "raw_url_empty", Source: rawURLSourceFromAPIPath(apiPath)}
	}
	fileDAO.Set(&dao.FileInfo{
		Path:              displayPath,
		Size:              result.Data.Size,
		RawURL:            result.Data.RawURL,
		RawURLAuthScope:   rawURLAuthScope(authHeaders),
		UpstreamFetchedAt: time.Now(),
	})
	return rawURLFetchResult{
		RawURL:     result.Data.RawURL,
		Size:       result.Data.Size,
		Source:     rawURLSourceFromAPIPath(apiPath),
		StatusCode: resp.StatusCode,
	}
}

func rawURLSourceFromAPIPath(apiPath string) string {
	switch apiPath {
	case "/api/fs/get":
		return "fs_get"
	case "/api/fs/link":
		return "fs_link"
	default:
		return strings.TrimPrefix(apiPath, "/")
	}
}
