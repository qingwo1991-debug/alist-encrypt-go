package handler

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/proxy"
)

// ProxyHandler handles proxy requests
type ProxyHandler struct {
	cfg          *config.Config
	streamProxy  *proxy.StreamProxy
	fileDAO      *dao.FileDAO
	passwdDAO    *dao.PasswdDAO
	redirectMap  sync.Map // key -> redirect info
	client       *proxy.Client // Reuse connection pool
	redirectKeys []string // Track keys for LRU eviction
	keysMu       sync.Mutex
}

const maxRedirectEntries = 10000 // Maximum redirect entries to prevent memory bloat

type redirectInfo struct {
	URL       string
	FileSize  int64
	Password  string
	EncType   string
	ExpiresAt time.Time
}

// NewProxyHandler creates a new proxy handler
func NewProxyHandler(cfg *config.Config, streamProxy *proxy.StreamProxy, fileDAO *dao.FileDAO, passwdDAO *dao.PasswdDAO) *ProxyHandler {
	h := &ProxyHandler{
		cfg:         cfg,
		streamProxy: streamProxy,
		fileDAO:     fileDAO,
		passwdDAO:   passwdDAO,
		client:      proxy.NewClient(cfg), // Reuse connection pool
	}
	// Cleanup expired redirects periodically
	go h.cleanupRedirects()
	return h
}

func (h *ProxyHandler) cleanupRedirects() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		now := time.Now()
		h.redirectMap.Range(func(key, value interface{}) bool {
			info := value.(*redirectInfo)
			if now.After(info.ExpiresAt) {
				h.redirectMap.Delete(key)
			}
			return true
		})
	}
}

// HandleRedirect handles /redirect/:key for 302 redirect decryption
func (h *ProxyHandler) HandleRedirect(w http.ResponseWriter, r *http.Request) {
	key := chi.URLParam(r, "key")
	if key == "" {
		http.Error(w, "Missing key", http.StatusBadRequest)
		return
	}

	value, ok := h.redirectMap.Load(key)
	if !ok {
		http.Error(w, "Redirect key not found or expired", http.StatusNotFound)
		return
	}

	info := value.(*redirectInfo)
	passwdInfo := &config.PasswdInfo{
		Password: info.Password,
		EncType:  info.EncType,
	}

	if err := h.streamProxy.ProxyDownloadDecrypt(w, r, info.URL, passwdInfo, info.FileSize); err != nil {
		log.Error().Err(err).Str("key", key).Msg("Failed to proxy redirect")
		http.Error(w, "Proxy error", http.StatusBadGateway)
	}
}

// RegisterRedirect registers a URL for redirect decryption and returns the key
func (h *ProxyHandler) RegisterRedirect(url string, fileSize int64, password, encType string) string {
	// Generate a unique key
	hash := md5.Sum([]byte(fmt.Sprintf("%s:%d:%d", url, fileSize, time.Now().UnixNano())))
	key := hex.EncodeToString(hash[:])

	h.redirectMap.Store(key, &redirectInfo{
		URL:       url,
		FileSize:  fileSize,
		Password:  password,
		EncType:   encType,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})

	// LRU eviction: remove oldest entries if over limit
	h.keysMu.Lock()
	h.redirectKeys = append(h.redirectKeys, key)
	for len(h.redirectKeys) > maxRedirectEntries {
		oldKey := h.redirectKeys[0]
		h.redirectKeys = h.redirectKeys[1:]
		h.redirectMap.Delete(oldKey)
	}
	h.keysMu.Unlock()

	return key
}

// HandleDownload handles /d/* and /p/* download requests with decryption
func (h *ProxyHandler) HandleDownload(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/d")
	path = strings.TrimPrefix(path, "/p")

	// Find password config for this path
	passwdInfo, found := h.passwdDAO.FindByPath(path)
	if !found {
		// No encryption configured, proxy directly
		targetURL := h.cfg.GetAlistURL() + r.URL.Path
		if r.URL.RawQuery != "" {
			targetURL += "?" + r.URL.RawQuery
		}
		if err := h.streamProxy.ProxyRequest(w, r, targetURL); err != nil {
			log.Error().Err(err).Str("path", path).Msg("Failed to proxy download")
			http.Error(w, "Proxy error", http.StatusBadGateway)
		}
		return
	}

	// Get file info for size
	fileInfo, found := h.fileDAO.Get(path)
	if !found {
		log.Warn().Str("path", path).Msg("File info not found, fetching from Alist")
		// Fetch file size from Alist
		fileInfo = &dao.FileInfo{
			Path: path,
			Size: 0, // Will need to get from response headers
		}
	}

	targetURL := h.cfg.GetAlistURL() + r.URL.Path
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	if err := h.streamProxy.ProxyDownloadDecrypt(w, r, targetURL, passwdInfo, fileInfo.Size); err != nil {
		log.Error().Err(err).Str("path", path).Msg("Failed to decrypt download")
		http.Error(w, "Decryption error", http.StatusBadGateway)
	}
}

// HandleProxy handles catch-all proxy to Alist
func (h *ProxyHandler) HandleProxy(w http.ResponseWriter, r *http.Request) {
	log.Debug().Str("path", r.URL.Path).Str("method", r.Method).Msg("Proxying request")
	targetURL := h.cfg.GetAlistURL() + r.URL.Path
	log.Debug().Str("target", targetURL).Msg("Target URL")
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	// Create proxy request
	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, r.Body)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create proxy request")
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Copy headers
	for key, values := range r.Header {
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}

	// Execute request using shared client (connection pool)
	resp, err := h.client.Do(proxyReq)
	if err != nil {
		log.Error().Err(err).Str("target", targetURL).Msg("Failed to proxy request")
		http.Error(w, "Proxy error", http.StatusBadGateway)
		return
	}
	log.Debug().Str("target", targetURL).Int("status", resp.StatusCode).Msg("Proxy response")
	defer resp.Body.Close()

	// Inject version identifier for HTML responses
	contentType := resp.Header.Get("Content-Type")

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Handle redirects - convert 302 to local redirect for encrypted files
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
		location := resp.Header.Get("Location")
		if location != "" {
			// Check if the path needs encryption
			parsedLoc, err := url.Parse(location)
			if err == nil {
				path := parsedLoc.Path
				if passwdInfo, found := h.passwdDAO.FindByPath(path); found {
					// Get file info
					if fileInfo, found := h.fileDAO.Get(path); found {
						key := h.RegisterRedirect(location, fileInfo.Size, passwdInfo.Password, passwdInfo.EncType)
						w.Header().Set("Location", "/redirect/"+key)
						w.WriteHeader(resp.StatusCode)
						return
					}
				}
			}
		}
	}

	w.WriteHeader(resp.StatusCode)

	// Inject version for HTML (with size limit to prevent OOM)
	if strings.Contains(contentType, "text/html") {
		// Limit HTML read to 10MB max to prevent memory issues
		const maxHTMLSize = 10 * 1024 * 1024
		limitedReader := io.LimitReader(resp.Body, maxHTMLSize)
		body, err := io.ReadAll(limitedReader)
		if err != nil {
			log.Error().Err(err).Msg("Failed to read response body")
			return
		}
		// Inject version comment
		modified := strings.Replace(string(body), "</head>", "<!-- alist-encrypt-go --></head>", 1)
		w.Write([]byte(modified))
		return
	}

	// Use buffer pool for non-HTML content
	buf := proxy.GetBuffer()
	defer proxy.PutBuffer(buf)
	io.CopyBuffer(w, resp.Body, *buf)
}
