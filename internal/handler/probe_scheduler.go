package handler

import (
	"context"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
)

type ProbeScheduler struct {
	cfg       *config.Config
	resolver  *FileSizeResolver
	fileDAO   *dao.FileDAO
	metaStore FileMetaStore
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
}

type probeItem struct {
	file        FileItem
	authHeaders http.Header
}

func NewProbeScheduler(cfg *config.Config, fileDAO *dao.FileDAO, metaStore FileMetaStore) *ProbeScheduler {
	ps := &ProbeScheduler{
		cfg:         cfg,
		resolver:    NewFileSizeResolver(fileDAO, metaStore, 4, getMinMetaSize(cfg), getRedirectMaxHops(cfg)),
		fileDAO:     fileDAO,
		metaStore:   metaStore,
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
	if !ps.shouldProbeSize(reportedSize) {
		return
	}

	if size, ok := ps.fileDAO.GetFileSize(file.DisplayPath); ok && !ps.shouldProbeSize(size) {
		return
	}
	if ps.metaStore != nil {
		providerKey := ProviderKey(file.TargetURL, file.DisplayPath)
		if meta, ok, _ := ps.metaStore.Get(context.Background(), providerKey, file.DisplayPath); ok && !ps.shouldProbeSize(meta.Size) {
			return
		}
	}

	key := ProviderKey(file.TargetURL, file.DisplayPath)
	if ps.isCoolingDown(key) {
		return
	}

	select {
	case ps.queue <- probeItem{file: file, authHeaders: authHeaders}:
		ps.markSeen(key)
	default:
		return
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

	if ps.maxDelay > ps.minDelay {
		delta := ps.maxDelay - ps.minDelay
		sleep := ps.minDelay + time.Duration(rand.Int63n(int64(delta)))
		time.Sleep(sleep)
	} else if ps.minDelay > 0 {
		time.Sleep(ps.minDelay)
	}

	result := ps.resolver.ResolveSingle(context.Background(), item.file, item.authHeaders)
	if result.Error == nil && result.Size > 0 {
		ps.fileDAO.SetFileSize(item.file.DisplayPath, result.Size, 24*time.Hour)
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
