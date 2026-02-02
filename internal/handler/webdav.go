package handler

import (
	"bytes"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/encryption"
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
	davPath := strings.TrimPrefix(r.URL.Path, "/dav")
	if davPath == "" {
		davPath = "/"
	}

	switch r.Method {
	case "GET", "HEAD":
		h.handleGet(w, r, davPath)
	case "PUT":
		h.handlePut(w, r, davPath)
	case "PROPFIND":
		h.handlePropfind(w, r, davPath)
	case "DELETE":
		h.handleDelete(w, r, davPath)
	case "MOVE":
		h.handleMove(w, r, davPath)
	case "COPY":
		h.handleCopy(w, r, davPath)
	case "MKCOL", "PROPPATCH", "LOCK", "UNLOCK", "OPTIONS":
		h.handlePassthrough(w, r)
	default:
		h.handlePassthrough(w, r)
	}
}

// convertToRealPath converts display path to encrypted path for WebDAV
func (h *WebDAVHandler) convertToRealPath(davPath string) string {
	passwdInfo, found := h.passwdDAO.FindByPath(davPath)
	if !found || !passwdInfo.EncName {
		return davPath
	}

	// Convert filename to encrypted name
	fileName := path.Base(davPath)
	if strings.HasPrefix(fileName, encryption.OrigPrefix) {
		// Original file, remove prefix
		realName := strings.TrimPrefix(fileName, encryption.OrigPrefix)
		return path.Dir(davPath) + "/" + realName
	}

	realName := encryption.ConvertRealNameWithSuffix(
		passwdInfo.Password,
		passwdInfo.EncType,
		fileName,
		passwdInfo.EncSuffix,
	)
	return path.Dir(davPath) + "/" + realName
}

// handleGet handles GET requests with decryption
func (h *WebDAVHandler) handleGet(w http.ResponseWriter, r *http.Request, davPath string) {
	passwdInfo, found := h.passwdDAO.FindByPath(davPath)
	if !found {
		h.handlePassthrough(w, r)
		return
	}

	// Convert display path to real encrypted path
	realPath := h.convertToRealPath(davPath)
	targetURL := h.cfg.GetAlistURL() + "/dav" + realPath
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	// Get file info
	fileInfo, infoFound := h.fileDAO.Get(realPath)
	var fileSize int64
	if infoFound {
		fileSize = fileInfo.Size
	}

	// Create new request with modified path
	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, r.Body)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	for key, values := range r.Header {
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}

	if err := h.streamProxy.ProxyDownloadDecryptReq(w, proxyReq, targetURL, passwdInfo, fileSize); err != nil {
		log.Error().Err(err).Str("path", davPath).Msg("WebDAV GET decryption failed")
		http.Error(w, "Decryption error", http.StatusBadGateway)
	}
}

// handlePut handles PUT requests with encryption and filename encryption
func (h *WebDAVHandler) handlePut(w http.ResponseWriter, r *http.Request, davPath string) {
	passwdInfo, found := h.passwdDAO.FindByPath(davPath)
	if !found {
		h.handlePassthrough(w, r)
		return
	}

	fileSize, _ := strconv.ParseInt(r.Header.Get("Content-Length"), 10, 64)

	// Convert display path to real encrypted path
	realPath := davPath
	if passwdInfo.EncName {
		fileName := path.Base(davPath)
		ext := passwdInfo.EncSuffix
		if ext == "" {
			ext = path.Ext(fileName)
		}
		encName := encryption.EncodeName(passwdInfo.Password, passwdInfo.EncType, strings.TrimSuffix(fileName, path.Ext(fileName)))
		realPath = path.Dir(davPath) + "/" + encName + ext
		log.Debug().Str("original", davPath).Str("encrypted", realPath).Msg("WebDAV PUT filename encrypted")
	}

	targetURL := h.cfg.GetAlistURL() + "/dav" + realPath
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	if err := h.streamProxy.ProxyUploadEncrypt(w, r, targetURL, passwdInfo, fileSize); err != nil {
		log.Error().Err(err).Str("path", davPath).Msg("WebDAV PUT encryption failed")
		http.Error(w, "Encryption error", http.StatusBadGateway)
	}
}

// handleDelete handles DELETE requests with filename encryption
func (h *WebDAVHandler) handleDelete(w http.ResponseWriter, r *http.Request, davPath string) {
	passwdInfo, found := h.passwdDAO.FindByPath(davPath)
	if !found || !passwdInfo.EncName {
		h.handlePassthrough(w, r)
		return
	}

	// Convert display path to real encrypted path
	realPath := h.convertToRealPath(davPath)
	targetURL := h.cfg.GetAlistURL() + "/dav" + realPath
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	proxyReq, err := http.NewRequestWithContext(r.Context(), "DELETE", targetURL, r.Body)
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
		log.Error().Err(err).Msg("WebDAV DELETE failed")
		http.Error(w, "Proxy error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

// handleMove handles MOVE requests with filename encryption
func (h *WebDAVHandler) handleMove(w http.ResponseWriter, r *http.Request, davPath string) {
	h.handleMoveOrCopy(w, r, davPath, "MOVE")
}

// handleCopy handles COPY requests with filename encryption
func (h *WebDAVHandler) handleCopy(w http.ResponseWriter, r *http.Request, davPath string) {
	h.handleMoveOrCopy(w, r, davPath, "COPY")
}

// handleMoveOrCopy handles MOVE/COPY requests with filename encryption
func (h *WebDAVHandler) handleMoveOrCopy(w http.ResponseWriter, r *http.Request, davPath string, method string) {
	passwdInfo, found := h.passwdDAO.FindByPath(davPath)

	// Convert source path
	realSrcPath := davPath
	if found && passwdInfo.EncName {
		realSrcPath = h.convertToRealPath(davPath)
	}

	// Convert destination path from header
	destination := r.Header.Get("Destination")
	if destination != "" {
		destURL, err := url.Parse(destination)
		if err == nil {
			destPath := strings.TrimPrefix(destURL.Path, "/dav")
			destPasswd, destFound := h.passwdDAO.FindByPath(destPath)
			if destFound && destPasswd.EncName {
				// Encrypt destination filename
				fileName := path.Base(destPath)
				ext := destPasswd.EncSuffix
				if ext == "" {
					ext = path.Ext(fileName)
				}
				encName := encryption.EncodeName(destPasswd.Password, destPasswd.EncType, strings.TrimSuffix(fileName, path.Ext(fileName)))
				realDestPath := path.Dir(destPath) + "/" + encName + ext

				// Rebuild destination URL
				destURL.Path = "/dav" + realDestPath
				destination = destURL.String()
			}
		}
	}

	targetURL := h.cfg.GetAlistURL() + "/dav" + realSrcPath
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	body, _ := io.ReadAll(r.Body)
	proxyReq, err := http.NewRequestWithContext(r.Context(), method, targetURL, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	for key, values := range r.Header {
		if key == "Destination" {
			continue // Will set modified destination
		}
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}
	if destination != "" {
		proxyReq.Header.Set("Destination", destination)
	}

	client := &http.Client{}
	resp, err := client.Do(proxyReq)
	if err != nil {
		log.Error().Err(err).Msgf("WebDAV %s failed", method)
		http.Error(w, "Proxy error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
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
