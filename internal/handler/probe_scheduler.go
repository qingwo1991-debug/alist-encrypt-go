package handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/rand"
	"net/http"
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

	// rawURLFetcher caches signed CDN URLs for pre-warmed files.
	rawURLFetcher RawURLFetcher
}

// RawURLFetcher fetches the signed raw_url for a display path from alist fs/get.
type RawURLFetcher func(displayPath, realPath string) string

type probeItem struct {
	file        FileItem
	authHeaders http.Header
}

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
	ps.EnqueueWithSize(file, authHeaders, 0)
}

func (ps *ProbeScheduler) EnqueueWithSize(file FileItem, authHeaders http.Header, reportedSize int64) {
	if ps == nil || !ps.enabled || ps.queue == nil {
		return
	}
	if file.DisplayPath == "" || file.TargetURL == "" {
		return
	}
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
		return
	}

	key := ProviderKey(file.TargetURL, file.DisplayPath)
	if ps.isCoolingDown(key) {
		atomic.AddUint64(&ps.cooldownSkips, 1)
		return
	}

	select {
	case ps.queue <- probeItem{file: file, authHeaders: authHeaders}:
		ps.markSeen(key)
		atomic.AddUint64(&ps.enqueuedTotal, 1)
	default:
		atomic.AddUint64(&ps.droppedTotal, 1)
		return
	}
}

func (ps *ProbeScheduler) Stats() map[string]interface{} {
	if ps == nil {
		return map[string]interface{}{}
	}
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
	providerKey := ProviderKey(item.file.TargetURL, item.file.DisplayPath)
	providerHost, _ := splitProvider(providerKey)
	sem := ps.getProviderSem(providerHost)
	if sem == nil {
		return
	}

	select {
	case sem <- struct{}{}:
		defer func() { <-sem }()
	default:
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
	authHeaders := ps.ensureAuth(item.authHeaders)

	result := ps.resolver.ResolveSingle(context.Background(), item.file, authHeaders)
	if result.Error == nil && result.Size > 0 {
		ps.fileDAO.SetFileSize(item.file.DisplayPath, result.Size, 24*time.Hour)
	}
	// Pre-fetch raw_url so WebDAV first-play is zero-latency.
	// Check staleness: don't re-fetch if raw_url is still fresh.
	stalenessThreshold := 30 * time.Minute
	if ps.cfg != nil && ps.cfg.AlistServer.UpstreamStalenessMinutes > 0 {
		stalenessThreshold = time.Duration(ps.cfg.AlistServer.UpstreamStalenessMinutes) * time.Minute
	}
	if ps.rawURLFetcher != nil {
		_ = ps.rawURLFetcher(item.file.DisplayPath, item.file.EncryptedPath)
	}
	if ps.rawURLFetcher == nil && ps.cfg != nil {
		// Fallback: use built-in raw_url fetcher via alist fs/get
		alistURL := ps.cfg.GetAlistURL()
		_ = fetchRawURL(context.Background(), alistURL, item.file.DisplayPath, item.file.EncryptedPath, ps.fileDAO, stalenessThreshold)
	}
	if ps.stream != nil {
		ps.stream.ProbeRangeCompatibility(context.Background(), item.file.TargetURL, item.authHeaders, item.file.CompatStorageKey)
	}
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

func splitProvider(providerKey string) (string, string) {
	parts := strings.SplitN(providerKey, "::", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return providerKey, ""
}

// ensureAuth returns auth headers, falling back to configured scan credentials
// if the provided headers have no Authorization or Cookie.
func (ps *ProbeScheduler) ensureAuth(headers http.Header) http.Header {
	if headers == nil {
		headers = make(http.Header)
	}
	// User-provided auth takes priority
	if headers.Get("Authorization") != "" || headers.Get("Cookie") != "" {
		return headers
	}
	if ps.cfg == nil {
		return headers
	}
	// Try scan auth header first
	if raw := strings.TrimSpace(ps.cfg.AlistServer.ScanAuthHeader); raw != "" {
		headers.Set("Authorization", raw)
		return headers
	}
	// Try JWT login with scan credentials (alist /api/fs/list needs token, not Basic auth)
	username := ps.cfg.AlistServer.ScanUsername
	password := ps.cfg.AlistServer.ScanPassword
	if username != "" && password != "" {
		if token := fetchAlistJWT(ps.cfg.GetAlistURL(), username, password); token != "" {
			headers.Set("Authorization", token)
			return headers
		}
		// Fallback to Basic auth
		token := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		headers.Set("Authorization", "Basic "+token)
		return headers
	}
	return headers
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
func fetchRawURL(ctx context.Context, alistURL, displayPath, realPath string, fileDAO *dao.FileDAO, staleThreshold time.Duration) string {
	if alistURL == "" || fileDAO == nil {
		return ""
	}
	// Check if cached raw_url is still fresh.
	if cached, ok := fileDAO.Get(displayPath); ok && cached != nil &&
		strings.TrimSpace(cached.RawURL) != "" &&
		cached.UpstreamStaleness() < staleThreshold {
		return cached.RawURL
	}

	body, _ := json.Marshal(map[string]string{"path": realPath})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, alistURL+"/api/fs/get", bytes.NewReader(body))
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
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	var result struct {
		Code int `json:"code"`
		Data struct {
			RawURL string `json:"raw_url"`
			Size   int64  `json:"size"`
		} `json:"data"`
	}
	if json.Unmarshal(respBody, &result) != nil || result.Code != 200 || result.Data.RawURL == "" {
		return ""
	}
	fileDAO.Set(&dao.FileInfo{
		Path:              displayPath,
		Size:              result.Data.Size,
		RawURL:            result.Data.RawURL,
		UpstreamFetchedAt: time.Now(),
	})
	return result.Data.RawURL
}
