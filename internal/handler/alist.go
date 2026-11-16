package handler

import (
	"context"
	"net/http"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/httputil"
	"github.com/alist-encrypt-go/internal/metrics"
	"github.com/alist-encrypt-go/internal/ports"
	"github.com/alist-encrypt-go/internal/proxy"
	"github.com/alist-encrypt-go/shared/encryptcore"
)

// AlistHandler handles Alist API interception
type AlistHandler struct {
	cfg            *config.Config
	streamProxy    ports.Streamer
	httpClient     *http.Client
	fileDAO        ports.FileRepository
	passwdDAO      ports.KeyRepository
	proxyHandler   *ProxyHandler
	metaStore      FileMetaStore
	foreground     *ForegroundTracker
	probe          *ProbeScheduler
	dirSyncStore   DirSyncStore
	dirSyncStart   sync.Once
	dirSyncRunning atomic.Bool
	dirSyncGroup   singleflight.Group
	// liveListGroup coalesces concurrent cold fs/list misses for the SAME
	// directory (keyed by the dir path, auth-agnostic) into one shared full
	// upstream listing, so an N-way thundering herd costs one upstream call.
	liveListGroup singleflight.Group
	// dirSyncRefreshSem bounds the number of concurrently-running request-driven
	// async snapshot refreshes. A full listing is expensive (one full upstream
	// fs/list + persist); without this cap, sustained cold/miss load spawns
	// unbounded goroutines and DB writes. Refreshes are pure optimization, so
	// when the cap is reached new ones are simply dropped.
	dirSyncRefreshPending map[string]bool // guarded by dirSyncMu; coalesce before spawning
	dirSyncRefreshSem     chan struct{}
	dirSyncCtx            context.Context
	dirSyncCancel         context.CancelFunc
	dirSyncMu             sync.Mutex
	dirSyncStopped        bool
	dirSyncWG             sync.WaitGroup
	dirSyncStop           sync.Once
	filenameTaskMu        sync.Mutex
	filenameTaskSem       chan struct{}
	filenameTaskPending   map[string]bool
	// listMaintenanceSem bounds concurrent post-response listing maintenance
	// (persist + meta upsert + probe enqueue). These are cache-warming writes
	// that used to run inline and could add seconds of MySQL/Bolt latency to
	// every fs/list; they now run in a bounded background pass instead.
	listMaintenanceSem chan struct{}
	fsMetaGroup        singleflight.Group
	fsMetaMu           sync.Mutex
	statsRecorder      StatsRecorder
	fsMetaCache        map[string]fsMetaCacheEntry

	// dirSyncScanFails backs off paths whose upstream listing keeps failing
	// (e.g. an unmounted "storage not found" root) so they stop consuming an
	// upstream fetch on every 15-minute scan cycle. Guarded by dirSyncMu.
	dirSyncScanFails map[string]dirSyncScanFail
	// reqRefreshFails backs off request_fill snapshot refreshes (keyed by
	// scope key) whose upstream fetch keeps failing. Guarded by dirSyncMu.
	reqRefreshFails map[string]reqRefreshFail
	// recentLists is a small LRU of recently served fs/list directories whose
	// request_fill snapshots are refreshed before their short TTL expires, so
	// repeat visits stay on the warm snapshot path. Guarded by recentListsMu.
	recentListsMu sync.Mutex
	recentLists   map[string]recentListEntry

	fsMetaRequests         uint64
	fsMetaCacheHits        uint64
	fsMetaSingleflightHits uint64
	fsMetaUpstreamFetches  uint64
	fsMetaRefreshBypass    uint64
	fsMetaFailureFastHits  uint64
	fsMetaFailureStores    uint64

	rootMountsMu   sync.RWMutex
	rootMountsSet  map[string]struct{}
	rootMountsOnce sync.Once
}

type fsMetaCacheEntry struct {
	StatusCode  int
	Header      http.Header
	Body        []byte
	ExpiresAt   time.Time
	FailureFast bool
}

// liveListFlight is the shared result of a coalesced full-dir upstream listing.
type liveListFlight struct {
	StatusCode int
	Payload    []byte
	ItemCount  int
	// Doc is the parsed response document from liveFsListResponse, reused by
	// joiners for in-memory pagination instead of re-parsing PayloadJSON.
	Doc map[string]interface{}
}

type fsMetaUpstreamResponse struct {
	StatusCode  int
	Header      http.Header
	Body        []byte
	FailureFast bool
}

type fsMetaFetchResult struct {
	Response *fsMetaUpstreamResponse
	CacheHit bool
}

// NewAlistHandler creates a new Alist handler
// proxyHandler must be the same instance used for /redirect routes
func NewAlistHandler(cfg *config.Config, streamProxy ports.Streamer, fileDAO ports.FileRepository, passwdDAO ports.KeyRepository, proxyHandler *ProxyHandler, metaStore FileMetaStore, probe *ProbeScheduler) *AlistHandler {
	dirSyncCtx, dirSyncCancel := context.WithCancel(context.Background())
	return &AlistHandler{
		cfg:                cfg,
		streamProxy:        streamProxy,
		httpClient:         proxy.NewHTTPClient(cfg, getAlistRequestTimeout(cfg)),
		fileDAO:            fileDAO,
		passwdDAO:          passwdDAO,
		proxyHandler:       proxyHandler,
		metaStore:          metaStore,
		probe:              probe,
		dirSyncCtx:         dirSyncCtx,
		dirSyncCancel:      dirSyncCancel,
		dirSyncRefreshSem:  make(chan struct{}, dirSyncRefreshMaxConcurrent),
		listMaintenanceSem: make(chan struct{}, 4),
	}
}

// Stop cancels and joins directory synchronization work before its stores close.
func (h *AlistHandler) Stop() {
	if h == nil {
		return
	}
	h.dirSyncStop.Do(func() {
		h.dirSyncMu.Lock()
		h.dirSyncStopped = true
		if h.dirSyncCancel != nil {
			h.dirSyncCancel()
		}
		h.dirSyncMu.Unlock()
		h.dirSyncWG.Wait()
	})
}

func (h *AlistHandler) startDirSyncWork(work func(context.Context)) bool {
	if h == nil || work == nil {
		return false
	}
	h.dirSyncMu.Lock()
	if h.dirSyncStopped {
		h.dirSyncMu.Unlock()
		return false
	}
	if h.dirSyncCtx == nil {
		h.dirSyncCtx, h.dirSyncCancel = context.WithCancel(context.Background())
	}
	ctx := h.dirSyncCtx
	h.dirSyncWG.Add(1)
	h.dirSyncMu.Unlock()
	go func() {
		defer h.dirSyncWG.Done()
		work(ctx)
	}()
	return true
}

func (h *AlistHandler) SetDirSyncStore(store DirSyncStore) {
	h.dirSyncStore = store
}

func (h *AlistHandler) SetStatsRecorder(recorder StatsRecorder) {
	h.statsRecorder = recorder
}

func (h *AlistHandler) Stats() map[string]interface{} {
	if h == nil {
		return map[string]interface{}{}
	}
	h.fsMetaMu.Lock()
	fsMetaEntries := len(h.fsMetaCache)
	h.fsMetaMu.Unlock()
	return map[string]interface{}{
		"fs_metadata": map[string]interface{}{
			"requests":          atomic.LoadUint64(&h.fsMetaRequests),
			"cache_hits":        atomic.LoadUint64(&h.fsMetaCacheHits),
			"singleflight_hits": atomic.LoadUint64(&h.fsMetaSingleflightHits),
			"upstream_fetches":  atomic.LoadUint64(&h.fsMetaUpstreamFetches),
			"refresh_bypass":    atomic.LoadUint64(&h.fsMetaRefreshBypass),
			"failure_fast_hits": atomic.LoadUint64(&h.fsMetaFailureFastHits),
			"failure_stores":    atomic.LoadUint64(&h.fsMetaFailureStores),
			"entries":           fsMetaEntries,
			"hot_ttl_seconds":   int(fsMetaHotCacheTTL.Seconds()),
			"fail_ttl_seconds":  int(fsMetaFailureCacheTTL.Seconds()),
			"max_entries":       maxFSMetaCacheEntries,
		},
	}
}

// decryptResult holds the result of parallel filename decryption
type decryptResult struct {
	index    int
	showName string
}

const (
	parallelDecryptThreshold = 5
	maxParallelDecryptLimit  = 32
	// fsMeta hot-cache TTL. fs/link + fs/get responses are content metadata
	// (name/size/link) that does not change on a per-second basis; a 10s TTL
	// forced a fresh upstream read on almost every back-navigate or repeated
	// click. 60s dramatically cuts upstream round trips and first-frame
	// latency for revisited items, while refresh=true (client-forced) still
	// bypasses the cache entirely. Since fs/get must reflect edits quickly, we
	// keep a moderate TTL rather than minutes.
	fsMetaHotCacheTTL     = 60 * time.Second
	fsMetaFailureCacheTTL = 2 * time.Second
	maxFSMetaCacheEntries = 512
)

var mediaTypeByExt = map[string]float64{
	// video
	".mp4": 2, ".mkv": 2, ".avi": 2, ".mov": 2,
	".wmv": 2, ".flv": 2, ".webm": 2, ".m4v": 2,
	".ts": 2, ".rmvb": 2, ".rm": 2, ".3gp": 2,
	// image
	".jpg": 5, ".jpeg": 5, ".png": 5, ".gif": 5,
	".bmp": 5, ".webp": 5, ".svg": 5, ".avif": 5,
}

func (h *AlistHandler) parallelDecryptEnabled() bool {
	return h.cfg != nil && h.cfg.AlistServerSnapshot().EnableParallelDecrypt
}

func (h *AlistHandler) parallelDecryptLimit() int {
	limit := 4
	if h.cfg != nil {
		if configured := h.cfg.AlistServerSnapshot().ParallelDecryptConcurrency; configured > 0 {
			limit = configured
		}
	}
	if limit < 1 {
		limit = 1
	}
	if limit > maxParallelDecryptLimit {
		limit = maxParallelDecryptLimit
	}
	return limit
}

func (h *AlistHandler) convertShowName(passwdInfo *config.PasswdInfo, name string) string {
	allowLoose := h.cfg != nil && h.cfg.AlistServerSnapshot().AllowLooseDecode
	return encryption.ConvertShowNameWithSuffixOptions(passwdInfo.Password, passwdInfo.EncType, name, passwdInfo.EncSuffix, allowLoose)
}

// convertEntryShowName decrypts listing/search entry names. Files keep the
// orig_ fallback for undecodable names; directories may legitimately be
// plaintext upstream, so undecodable directory names keep their spelling
// instead of being mangled into orig_ display names.
func (h *AlistHandler) convertEntryShowName(passwdInfo *config.PasswdInfo, name string, isDir bool) string {
	if !isDir {
		return h.convertShowName(passwdInfo, name)
	}
	allowLoose := h.cfg != nil && h.cfg.AlistServerSnapshot().AllowLooseDecode
	if show, ok := encryption.TryConvertShowNameWithSuffixOptions(passwdInfo.Password, passwdInfo.EncType, name, passwdInfo.EncSuffix, allowLoose); ok {
		return show
	}
	return name
}

// normalizeDecryptedListItem keeps display fields aligned with decrypted filename,
// so frontend preview strategy won't be stuck on encrypted suffix/type (e.g. ".bin").
func normalizeDecryptedListItem(fileData map[string]interface{}, showName string) {
	if fileData == nil || showName == "" {
		return
	}

	if pathText, ok := fileData["path"].(string); ok && pathText != "" {
		fileData["path"] = path.Join(path.Dir(pathText), showName)
	}

	ext := strings.ToLower(path.Ext(showName))
	if fileType, ok := mediaTypeByExt[ext]; ok {
		fileData["type"] = fileType
	}
}

// proxyToAlist creates and executes a proxy request to Alist backend
func (h *AlistHandler) proxyToAlist(ctx interface{}, method, endpoint string, body []byte, srcReq *http.Request) (*http.Response, error) {
	targetURL := httputil.BuildTargetURL(h.cfg.GetAlistURL(), endpoint, nil)

	// Authorization belongs to the upstream file-browser session. Strip only
	// local management credentials; dropping it silently turns searches into
	// guest requests, even when the same caller can list files successfully.
	req, err := httputil.NewRequest(method, targetURL).
		WithContext(srcReq.Context()).
		WithBody(body).
		CopyHeadersExcept(srcReq, "Content-Length", "Authorizetoken", "X-User-Token").
		WithForwardedHeaders(srcReq).
		WithHeader("Content-Type", "application/json").
		Build()
	if err != nil {
		return nil, err
	}

	resp, err := h.httpClient.Do(req)
	switch {
	case err != nil:
		metrics.Inc("alist_upstream_requests_total", map[string]string{"result": "transport_error"}, 1)
	case resp.StatusCode >= 500:
		metrics.Inc("alist_upstream_requests_total", map[string]string{"result": "upstream_5xx"}, 1)
	case resp.StatusCode >= 400:
		metrics.Inc("alist_upstream_requests_total", map[string]string{"result": "upstream_4xx"}, 1)
	default:
		metrics.Inc("alist_upstream_requests_total", map[string]string{"result": "ok"}, 1)
	}
	return resp, err
}
