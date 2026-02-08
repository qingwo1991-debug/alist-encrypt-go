package handler

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/httputil"
	"github.com/rs/zerolog/log"
)

// PrefetchManager handles background prefetching of file metadata
type PrefetchManager struct {
	fileDAO      *dao.FileDAO
	cfg          *config.Config
	semaphore    chan struct{} // Limit concurrent prefetch requests
	activeJobs   sync.Map      // Track active prefetch jobs to avoid duplicates
	maxWorkers   int
	shutdownChan chan struct{}
}

// NewPrefetchManager creates a new prefetch manager
func NewPrefetchManager(cfg *config.Config, fileDAO *dao.FileDAO, maxWorkers int) *PrefetchManager {
	if maxWorkers <= 0 {
		maxWorkers = 10 // Default: 10 concurrent prefetch workers
	}

	pm := &PrefetchManager{
		fileDAO:      fileDAO,
		cfg:          cfg,
		semaphore:    make(chan struct{}, maxWorkers),
		maxWorkers:   maxWorkers,
		shutdownChan: make(chan struct{}),
	}

	return pm
}

// PrefetchFileSize fetches file size in background and caches it
func (pm *PrefetchManager) PrefetchFileSize(displayPath, encryptedPath string, passwdInfo *config.PasswdInfo, authHeader, cookieHeader string) {
	// Check if already cached
	if _, ok := pm.fileDAO.GetFileSize(encryptedPath); ok {
		return // Already cached, skip
	}

	// Check if prefetch job already running for this path
	if _, loaded := pm.activeJobs.LoadOrStore(encryptedPath, true); loaded {
		return // Already prefetching
	}

	// Launch background prefetch
	go func() {
		defer pm.activeJobs.Delete(encryptedPath)

		// Acquire semaphore (limit concurrent requests)
		select {
		case pm.semaphore <- struct{}{}:
			defer func() { <-pm.semaphore }()
		case <-pm.shutdownChan:
			return
		}

		// Add small delay to avoid thundering herd
		time.Sleep(50 * time.Millisecond)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Build HEAD request URL
		targetURL := pm.cfg.GetAlistURL() + "/dav" + encryptedPath

		// Log authentication status
		hasAuth := authHeader != ""
		hasCookie := cookieHeader != ""
		log.Debug().
			Str("path", displayPath).
			Bool("auth", hasAuth).
			Bool("cookie", hasCookie).
			Msg("Building prefetch HEAD request")

		// Build request with authentication headers
		reqBuilder := httputil.NewRequest("HEAD", targetURL).
			WithContext(ctx)

		// Add authentication headers if present
		if authHeader != "" {
			reqBuilder = reqBuilder.WithHeader("Authorization", authHeader)
		}
		if cookieHeader != "" {
			reqBuilder = reqBuilder.WithHeader("Cookie", cookieHeader)
		}

		headReq, err := reqBuilder.Build()
		if err != nil {
			log.Debug().Err(err).Str("path", displayPath).Msg("Failed to create prefetch HEAD request")
			return
		}

		// Execute HEAD request
		client := &http.Client{Timeout: 10 * time.Second}
		headResp, err := client.Do(headReq)
		if err != nil {
			log.Debug().Err(err).Str("path", displayPath).Msg("Prefetch HEAD request failed")
			return
		}
		defer headResp.Body.Close()

		// Check status code
		if headResp.StatusCode != http.StatusOK {
			log.Debug().
				Str("path", displayPath).
				Int("status", headResp.StatusCode).
				Msg("Prefetch HEAD request failed with non-200 status")
			return
		}

		// Extract file size
		if contentLen := headResp.Header.Get("Content-Length"); contentLen != "" {
			if size, err := httputil.ParseInt64(contentLen); err == nil && size > 0 {
				// Cache for 24 hours
				pm.fileDAO.SetFileSize(encryptedPath, size, 24*time.Hour)
				log.Debug().
					Str("path", displayPath).
					Int64("size", size).
					Msg("Prefetched file size successfully")
			}
		}
	}()
}

// PrefetchBatch prefetches multiple file sizes in parallel
func (pm *PrefetchManager) PrefetchBatch(items []PrefetchItem, authHeader, cookieHeader string) {
	for _, item := range items {
		pm.PrefetchFileSize(item.DisplayPath, item.EncryptedPath, item.PasswdInfo, authHeader, cookieHeader)
	}
}

// PrefetchItem represents a file to prefetch
type PrefetchItem struct {
	DisplayPath   string
	EncryptedPath string
	PasswdInfo    *config.PasswdInfo
}

// PrefetchWithAuth is a convenience wrapper that extracts auth headers from request
func (pm *PrefetchManager) PrefetchWithAuth(displayPath, encryptedPath string, passwdInfo *config.PasswdInfo, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	cookieHeader := r.Header.Get("Cookie")
	pm.PrefetchFileSize(displayPath, encryptedPath, passwdInfo, authHeader, cookieHeader)
}

// PrefetchBatchWithAuth is a convenience wrapper for batch prefetch with auth from request
func (pm *PrefetchManager) PrefetchBatchWithAuth(items []PrefetchItem, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	cookieHeader := r.Header.Get("Cookie")
	pm.PrefetchBatch(items, authHeader, cookieHeader)
}

// Shutdown gracefully stops the prefetch manager
func (pm *PrefetchManager) Shutdown() {
	close(pm.shutdownChan)
}

// Stats returns prefetch manager statistics
func (pm *PrefetchManager) Stats() map[string]interface{} {
	activeCount := 0
	pm.activeJobs.Range(func(key, value interface{}) bool {
		activeCount++
		return true
	})

	return map[string]interface{}{
		"max_workers":  pm.maxWorkers,
		"active_jobs":  activeCount,
		"file_size_cache": pm.fileDAO.FileSizeCacheStats(),
	}
}
