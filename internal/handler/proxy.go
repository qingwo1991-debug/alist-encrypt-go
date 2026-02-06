package handler

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/encryption"
	"github.com/alist-encrypt-go/internal/httputil"
	"github.com/alist-encrypt-go/internal/proxy"
	"github.com/alist-encrypt-go/internal/trace"
)

// ProxyHandler handles proxy requests
type ProxyHandler struct {
	cfg          *config.Config
	streamProxy  *proxy.StreamProxy
	fileDAO      *dao.FileDAO
	passwdDAO    *dao.PasswdDAO
	redirectMap  sync.Map // key -> redirect info
	client       *proxy.Client
	redirectKeys []string
	keysMu       sync.Mutex
}

const maxRedirectEntries = 10000

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
		client:      proxy.NewClient(cfg),
	}
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
	key := strings.TrimPrefix(r.URL.Path, "/redirect/")
	if key == "" {
		RespondHTTPErrorWithStatus(w, "Missing key", http.StatusBadRequest)
		return
	}

	value, ok := h.redirectMap.Load(key)
	if !ok {
		RespondHTTPErrorWithStatus(w, "Redirect key not found or expired", http.StatusNotFound)
		return
	}

	info := value.(*redirectInfo)
	passwdInfo := &config.PasswdInfo{
		Password: info.Password,
		EncType:  info.EncType,
	}

	if err := h.streamProxy.ProxyDownloadDecrypt(w, r, info.URL, passwdInfo, info.FileSize); err != nil {
		log.Error().Err(err).Str("key", key).Msg("Failed to proxy redirect")
		RespondHTTPErrorWithStatus(w, "Proxy error", http.StatusBadGateway)
	}
}

// RegisterRedirect registers a URL for redirect decryption and returns the key
func (h *ProxyHandler) RegisterRedirect(url string, fileSize int64, password, encType string) string {
	hash := md5.Sum([]byte(fmt.Sprintf("%s:%d:%d", url, fileSize, time.Now().UnixNano())))
	key := hex.EncodeToString(hash[:])

	h.redirectMap.Store(key, &redirectInfo{
		URL:       url,
		FileSize:  fileSize,
		Password:  password,
		EncType:   encType,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})

	// LRU eviction
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

// convertDisplayToRealPath converts a display path to encrypted path for downloads
func (h *ProxyHandler) convertDisplayToRealPath(displayPath string, passwdInfo *config.PasswdInfo) string {
	if passwdInfo == nil || !passwdInfo.EncName {
		return displayPath
	}

	fileName := path.Base(displayPath)
	if encryption.IsOriginalFile(fileName) {
		realName := encryption.StripOriginalPrefix(fileName)
		return path.Dir(displayPath) + "/" + realName
	}

	converter := encryption.NewFileNameConverter(passwdInfo.Password, passwdInfo.EncType, passwdInfo.EncSuffix)
	realName := converter.ToRealName(fileName)
	return path.Dir(displayPath) + "/" + realName
}

// HandleDownload handles /d/* and /p/* download requests with decryption
func (h *ProxyHandler) HandleDownload(w http.ResponseWriter, r *http.Request) {
	displayPath := strings.TrimPrefix(r.URL.Path, "/d")
	displayPath = strings.TrimPrefix(displayPath, "/p")

	reqID := trace.GetRequestID(r.Context())
	pathTag := trace.GetPathTag(r.Context())

	passwdInfo, found := h.passwdDAO.FindByPath(displayPath)
	if !found {
		// No encryption - proxy original path
		log.Debug().
			Str("req_id", reqID).
			Str("path_tag", pathTag).
			Str("display", displayPath).
			Msg("[download] No encryption, proxying directly")

		targetURL := httputil.BuildTargetURL(h.cfg.GetAlistURL(), r.URL.Path, r)
		if err := h.streamProxy.ProxyRequest(w, r, targetURL); err != nil {
			log.Error().Err(err).Str("req_id", reqID).Str("path", displayPath).Msg("Failed to proxy download")
			RespondHTTPErrorWithStatus(w, "Proxy error", http.StatusBadGateway)
		}
		return
	}

	// Convert display path to encrypted path if filename encryption is enabled
	realPath := displayPath
	if passwdInfo.EncName {
		realPath = h.convertDisplayToRealPath(displayPath, passwdInfo)
	}

	log.Debug().
		Str("req_id", reqID).
		Str("path_tag", pathTag).
		Str("display", displayPath).
		Str("real", realPath).
		Msg("[download] Path converted")

	// Look up file info by DISPLAY path (how PROPFIND/fs/list cached it)
	fileInfo, found := h.fileDAO.Get(displayPath)
	if !found {
		log.Warn().
			Str("req_id", reqID).
			Str("path", displayPath).
			Msg("[download] File info not found, using size 0")
		fileInfo = &dao.FileInfo{Path: displayPath, Size: 0}
	}

	// Build target URL with ENCRYPTED path
	urlPrefix := "/d"
	if strings.HasPrefix(r.URL.Path, "/p") {
		urlPrefix = "/p"
	}
	targetURL := httputil.BuildTargetURL(h.cfg.GetAlistURL(), urlPrefix+realPath, r)

	log.Debug().
		Str("req_id", reqID).
		Str("target", targetURL).
		Int64("size", fileInfo.Size).
		Msg("[download] Proxying with decryption")

	if err := h.streamProxy.ProxyDownloadDecrypt(w, r, targetURL, passwdInfo, fileInfo.Size); err != nil {
		log.Error().Err(err).Str("req_id", reqID).Str("path", displayPath).Msg("Failed to decrypt download")
		RespondHTTPErrorWithStatus(w, "Decryption error", http.StatusBadGateway)
	}
}

// HandleProxy handles catch-all proxy to Alist
func (h *ProxyHandler) HandleProxy(w http.ResponseWriter, r *http.Request) {
	log.Debug().Str("path", r.URL.Path).Str("method", r.Method).Msg("Proxying request")
	targetURL := httputil.BuildTargetURL(h.cfg.GetAlistURL(), r.URL.Path, r)
	log.Debug().Str("target", targetURL).Msg("Target URL")

	proxyReq, err := httputil.NewRequest(r.Method, targetURL).
		WithContext(r.Context()).
		WithBodyReader(r.Body).
		CopyHeaders(r).
		Build()
	if err != nil {
		log.Error().Err(err).Msg("Failed to create proxy request")
		RespondHTTPErrorWithStatus(w, "Internal error", http.StatusInternalServerError)
		return
	}

	resp, err := h.client.Do(proxyReq)
	if err != nil {
		log.Error().Err(err).Str("target", targetURL).Msg("Failed to proxy request")
		RespondHTTPErrorWithStatus(w, "Proxy error", http.StatusBadGateway)
		return
	}
	log.Debug().Str("target", targetURL).Int("status", resp.StatusCode).Msg("Proxy response")
	defer resp.Body.Close()

	contentType := resp.Header.Get("Content-Type")
	httputil.CopyResponseHeaders(w, resp)

	// Handle redirects
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
		location := resp.Header.Get("Location")
		if location != "" {
			parsedLoc, err := url.Parse(location)
			if err == nil {
				path := parsedLoc.Path
				if passwdInfo, found := h.passwdDAO.FindByPath(path); found {
					var fileSize int64
					if fileInfo, found := h.fileDAO.Get(path); found {
						fileSize = fileInfo.Size
					}
					key := h.RegisterRedirect(location, fileSize, passwdInfo.Password, passwdInfo.EncType)
					w.Header().Set("Location", "/redirect/"+key)
					w.WriteHeader(resp.StatusCode)
					return
				}
			}
		}
	}

	w.WriteHeader(resp.StatusCode)

	// Inject version for HTML
	if strings.Contains(contentType, "text/html") {
		const maxHTMLSize = 10 * 1024 * 1024
		limitedReader := io.LimitReader(resp.Body, maxHTMLSize)
		body, err := io.ReadAll(limitedReader)
		if err != nil {
			log.Error().Err(err).Msg("Failed to read response body")
			return
		}
		modified := strings.Replace(string(body), "</head>", "<!-- alist-encrypt-go --></head>", 1)
		w.Write([]byte(modified))
		return
	}

	buf := proxy.GetBuffer()
	defer proxy.PutBuffer(buf)
	io.CopyBuffer(w, resp.Body, *buf)
}
