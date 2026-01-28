package handler

import (
	"bytes"
	"encoding/xml"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/proxy"
)

// WebDAVHandler handles WebDAV requests
type WebDAVHandler struct {
	cfg          *config.Config
	streamProxy  *proxy.StreamProxy
	fileDAO      *dao.FileDAO
	passwdDAO    *dao.PasswdDAO
	proxyHandler *ProxyHandler
}

// NewWebDAVHandler creates a new WebDAV handler
func NewWebDAVHandler(cfg *config.Config, streamProxy *proxy.StreamProxy, fileDAO *dao.FileDAO, passwdDAO *dao.PasswdDAO) *WebDAVHandler {
	return &WebDAVHandler{
		cfg:          cfg,
		streamProxy:  streamProxy,
		fileDAO:      fileDAO,
		passwdDAO:    passwdDAO,
		proxyHandler: NewProxyHandler(cfg, streamProxy, fileDAO, passwdDAO),
	}
}

// Handle routes WebDAV requests
func (h *WebDAVHandler) Handle(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/dav")
	if path == "" {
		path = "/"
	}

	switch r.Method {
	case "GET", "HEAD":
		h.handleGet(w, r, path)
	case "PUT":
		h.handlePut(w, r, path)
	case "PROPFIND":
		h.handlePropfind(w, r, path)
	case "MKCOL", "DELETE", "MOVE", "COPY", "PROPPATCH", "LOCK", "UNLOCK", "OPTIONS":
		h.handlePassthrough(w, r)
	default:
		h.handlePassthrough(w, r)
	}
}

// handleGet handles GET requests with decryption
func (h *WebDAVHandler) handleGet(w http.ResponseWriter, r *http.Request, path string) {
	passwdInfo, found := h.passwdDAO.FindByPath(path)
	if !found {
		h.handlePassthrough(w, r)
		return
	}

	// Get file info
	fileInfo, found := h.fileDAO.Get(path)
	var fileSize int64
	if found {
		fileSize = fileInfo.Size
	}

	targetURL := h.cfg.GetAlistURL() + r.URL.Path
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	if err := h.streamProxy.ProxyDownloadDecrypt(w, r, targetURL, passwdInfo, fileSize); err != nil {
		log.Error().Err(err).Str("path", path).Msg("WebDAV GET decryption failed")
		http.Error(w, "Decryption error", http.StatusBadGateway)
	}
}

// handlePut handles PUT requests with encryption
func (h *WebDAVHandler) handlePut(w http.ResponseWriter, r *http.Request, path string) {
	passwdInfo, found := h.passwdDAO.FindByPath(path)
	if !found {
		h.handlePassthrough(w, r)
		return
	}

	fileSize, _ := strconv.ParseInt(r.Header.Get("Content-Length"), 10, 64)
	targetURL := h.cfg.GetAlistURL() + r.URL.Path
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	if err := h.streamProxy.ProxyUploadEncrypt(w, r, targetURL, passwdInfo, fileSize); err != nil {
		log.Error().Err(err).Str("path", path).Msg("WebDAV PUT encryption failed")
		http.Error(w, "Encryption error", http.StatusBadGateway)
	}
}

// handlePropfind handles PROPFIND requests and caches file info
func (h *WebDAVHandler) handlePropfind(w http.ResponseWriter, r *http.Request, path string) {
	targetURL := h.cfg.GetAlistURL() + r.URL.Path
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	// Read request body
	body, _ := io.ReadAll(r.Body)

	proxyReq, err := http.NewRequestWithContext(r.Context(), "PROPFIND", targetURL, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	for key, values := range r.Header {
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}

	client := &http.Client{}
	resp, err := client.Do(proxyReq)
	if err != nil {
		log.Error().Err(err).Msg("WebDAV PROPFIND failed")
		http.Error(w, "Proxy error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	// Parse and cache file info from PROPFIND response
	h.parsePropfindResponse(respBody, path)

	// Copy response
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

// handlePassthrough passes requests directly to Alist
func (h *WebDAVHandler) handlePassthrough(w http.ResponseWriter, r *http.Request) {
	targetURL := h.cfg.GetAlistURL() + r.URL.Path
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	if err := h.streamProxy.ProxyRequest(w, r, targetURL); err != nil {
		log.Error().Err(err).Str("method", r.Method).Msg("WebDAV passthrough failed")
		http.Error(w, "Proxy error", http.StatusBadGateway)
	}
}

// parsePropfindResponse parses WebDAV PROPFIND XML response
func (h *WebDAVHandler) parsePropfindResponse(body []byte, basePath string) {
	type PropfindResponse struct {
		XMLName  xml.Name `xml:"multistatus"`
		Response []struct {
			Href string `xml:"href"`
			Prop struct {
				DisplayName     string `xml:"propstat>prop>displayname"`
				ContentLength   int64  `xml:"propstat>prop>getcontentlength"`
				ResourceType    string `xml:"propstat>prop>resourcetype"`
				LastModified    string `xml:"propstat>prop>getlastmodified"`
				IsCollection    bool   `xml:"-"`
			} `xml:"propstat>prop"`
		} `xml:"response"`
	}

	var propfind PropfindResponse
	if err := xml.Unmarshal(body, &propfind); err != nil {
		log.Debug().Err(err).Msg("Failed to parse PROPFIND response")
		return
	}

	for _, resp := range propfind.Response {
		// Extract path from href
		path := strings.TrimPrefix(resp.Href, "/dav")
		if path == "" {
			path = "/"
		}

		info := &dao.FileInfo{
			Path:  path,
			Name:  resp.Prop.DisplayName,
			Size:  resp.Prop.ContentLength,
			IsDir: strings.Contains(resp.Prop.ResourceType, "collection"),
		}

		h.fileDAO.Set(info)
	}
}
