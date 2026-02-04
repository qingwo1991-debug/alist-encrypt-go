package handler

import (
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
	"github.com/alist-encrypt-go/internal/httputil"
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
	if encryption.IsOriginalFile(fileName) {
		realName := encryption.StripOriginalPrefix(fileName)
		return path.Dir(davPath) + "/" + realName
	}

	converter := encryption.NewFileNameConverter(passwdInfo.Password, passwdInfo.EncType, passwdInfo.EncSuffix)
	realName := converter.ToRealName(fileName)
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
	targetURL := httputil.BuildTargetURL(h.cfg.GetAlistURL(), "/dav"+realPath, r)

	// Get file info for size
	fileInfo, infoFound := h.fileDAO.Get(realPath)
	var fileSize int64
	if infoFound {
		fileSize = fileInfo.Size
	}

	// Create new request with modified path
	proxyReq, err := httputil.NewRequest(r.Method, targetURL).
		WithContext(r.Context()).
		WithBodyReader(r.Body).
		CopyHeaders(r).
		Build()
	if err != nil {
		RespondHTTPErrorWithStatus(w, "Internal error", http.StatusInternalServerError)
		return
	}

	if err := h.streamProxy.ProxyDownloadDecryptReq(w, proxyReq, targetURL, passwdInfo, fileSize); err != nil {
		log.Error().Err(err).Str("path", davPath).Msg("WebDAV GET decryption failed")
		RespondHTTPErrorWithStatus(w, "Decryption error", http.StatusBadGateway)
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
		converter := encryption.NewFileNameConverter(passwdInfo.Password, passwdInfo.EncType, passwdInfo.EncSuffix)
		fileName := path.Base(davPath)
		ext := passwdInfo.EncSuffix
		if ext == "" {
			ext = path.Ext(fileName)
		}
		encName := converter.EncryptFileName(strings.TrimSuffix(fileName, path.Ext(fileName)))
		realPath = path.Dir(davPath) + "/" + encName + ext
		log.Debug().Str("original", davPath).Str("encrypted", realPath).Msg("WebDAV PUT filename encrypted")
	}

	targetURL := httputil.BuildTargetURL(h.cfg.GetAlistURL(), "/dav"+realPath, r)

	if err := h.streamProxy.ProxyUploadEncrypt(w, r, targetURL, passwdInfo, fileSize); err != nil {
		log.Error().Err(err).Str("path", davPath).Msg("WebDAV PUT encryption failed")
		RespondHTTPErrorWithStatus(w, "Encryption error", http.StatusBadGateway)
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
	targetURL := httputil.BuildTargetURL(h.cfg.GetAlistURL(), "/dav"+realPath, r)

	proxyReq, err := httputil.NewRequest("DELETE", targetURL).
		WithContext(r.Context()).
		WithBodyReader(r.Body).
		CopyHeaders(r).
		Build()
	if err != nil {
		RespondHTTPErrorWithStatus(w, "Internal error", http.StatusInternalServerError)
		return
	}

	client := &http.Client{}
	resp, err := client.Do(proxyReq)
	if err != nil {
		log.Error().Err(err).Msg("WebDAV DELETE failed")
		RespondHTTPErrorWithStatus(w, "Proxy error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	httputil.CopyResponseHeaders(w, resp)
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
				converter := encryption.NewFileNameConverter(destPasswd.Password, destPasswd.EncType, destPasswd.EncSuffix)
				fileName := path.Base(destPath)
				ext := destPasswd.EncSuffix
				if ext == "" {
					ext = path.Ext(fileName)
				}
				encName := converter.EncryptFileName(strings.TrimSuffix(fileName, path.Ext(fileName)))
				realDestPath := path.Dir(destPath) + "/" + encName + ext

				// Rebuild destination URL
				destURL.Path = "/dav" + realDestPath
				destination = destURL.String()
			}
		}
	}

	targetURL := httputil.BuildTargetURL(h.cfg.GetAlistURL(), "/dav"+realSrcPath, r)

	body, _ := io.ReadAll(r.Body)
	proxyReq, err := httputil.NewRequest(method, targetURL).
		WithContext(r.Context()).
		WithBody(body).
		CopyHeadersExcept(r, "Destination").
		Build()
	if err != nil {
		RespondHTTPErrorWithStatus(w, "Internal error", http.StatusInternalServerError)
		return
	}

	if destination != "" {
		proxyReq.Header.Set("Destination", destination)
	}

	client := &http.Client{}
	resp, err := client.Do(proxyReq)
	if err != nil {
		log.Error().Err(err).Msgf("WebDAV %s failed", method)
		RespondHTTPErrorWithStatus(w, "Proxy error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	httputil.CopyResponseHeaders(w, resp)
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

// handlePropfind handles PROPFIND requests and caches file info
func (h *WebDAVHandler) handlePropfind(w http.ResponseWriter, r *http.Request, davPath string) {
	// Check if encryption is enabled for this path
	passwdInfo, found := h.passwdDAO.FindByPath(davPath)

	// For PROPFIND, we should NOT convert directory paths
	// Only convert if it looks like a file request (has extension and doesn't end with /)
	realPath := davPath
	isDirectoryRequest := strings.HasSuffix(davPath, "/") || davPath == "" || path.Ext(davPath) == ""

	if found && passwdInfo.EncName && !isDirectoryRequest {
		// This looks like a file PROPFIND - convert the filename
		realPath = h.convertToRealPath(davPath)
		log.Debug().Str("display", davPath).Str("real", realPath).Msg("WebDAV PROPFIND file path conversion")
	}

	targetURL := httputil.BuildTargetURL(h.cfg.GetAlistURL(), "/dav"+realPath, r)

	// Read request body
	body, _ := io.ReadAll(r.Body)

	proxyReq, err := httputil.NewRequest("PROPFIND", targetURL).
		WithContext(r.Context()).
		WithBody(body).
		CopyHeaders(r).
		Build()
	if err != nil {
		RespondHTTPErrorWithStatus(w, "Internal error", http.StatusInternalServerError)
		return
	}

	client := &http.Client{}
	resp, err := client.Do(proxyReq)
	if err != nil {
		log.Error().Err(err).Msg("WebDAV PROPFIND failed")
		RespondHTTPErrorWithStatus(w, "Proxy error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	// Parse and cache file info from PROPFIND response
	h.parsePropfindResponse(respBody, davPath)

	// Decrypt filenames in the XML response if encryption is enabled
	if found && passwdInfo.EncName {
		respBody = h.decryptPropfindResponse(respBody, passwdInfo)
	}

	// Copy response headers (recalculate Content-Length since body may have changed)
	httputil.CopyResponseHeaders(w, resp, "Content-Length")
	w.Header().Set("Content-Length", strconv.Itoa(len(respBody)))
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

// handlePassthrough passes requests directly to Alist
func (h *WebDAVHandler) handlePassthrough(w http.ResponseWriter, r *http.Request) {
	targetURL := httputil.BuildTargetURL(h.cfg.GetAlistURL(), r.URL.Path, r)

	if err := h.streamProxy.ProxyRequest(w, r, targetURL); err != nil {
		log.Error().Err(err).Str("method", r.Method).Msg("WebDAV passthrough failed")
		RespondHTTPErrorWithStatus(w, "Proxy error", http.StatusBadGateway)
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

// decryptPropfindResponse decrypts filenames in WebDAV PROPFIND XML response
func (h *WebDAVHandler) decryptPropfindResponse(body []byte, passwdInfo *config.PasswdInfo) []byte {
	result := string(body)

	// Decrypt displayname elements: <D:displayname>encryptedName.ext</D:displayname>
	// Match both <D:displayname> and <displayname> variants
	displayNamePatterns := []string{
		`<D:displayname>`, `</D:displayname>`,
		`<d:displayname>`, `</d:displayname>`,
		`<displayname>`, `</displayname>`,
	}

	for i := 0; i < len(displayNamePatterns); i += 2 {
		startTag := displayNamePatterns[i]
		endTag := displayNamePatterns[i+1]
		result = h.decryptXMLElements(result, startTag, endTag, passwdInfo)
	}

	// Decrypt href elements: <D:href>/dav/path/encryptedName.ext</D:href>
	hrefPatterns := []string{
		`<D:href>`, `</D:href>`,
		`<d:href>`, `</d:href>`,
		`<href>`, `</href>`,
	}

	for i := 0; i < len(hrefPatterns); i += 2 {
		startTag := hrefPatterns[i]
		endTag := hrefPatterns[i+1]
		result = h.decryptHrefElements(result, startTag, endTag, passwdInfo)
	}

	return []byte(result)
}

// decryptXMLElements decrypts content between XML tags (for displayname)
func (h *WebDAVHandler) decryptXMLElements(xmlStr, startTag, endTag string, passwdInfo *config.PasswdInfo) string {
	result := xmlStr
	searchPos := 0

	for {
		startIdx := strings.Index(result[searchPos:], startTag)
		if startIdx == -1 {
			break
		}
		startIdx += searchPos

		endIdx := strings.Index(result[startIdx:], endTag)
		if endIdx == -1 {
			break
		}
		endIdx += startIdx

		contentStart := startIdx + len(startTag)
		encryptedName := result[contentStart:endIdx]

		if encryptedName != "" && encryptedName != "/" {
			decryptedName := encryption.ConvertShowName(passwdInfo.Password, passwdInfo.EncType, encryptedName)
			if decryptedName != "" {
				result = result[:contentStart] + decryptedName + result[endIdx:]
				searchPos = contentStart + len(decryptedName) + len(endTag)
				continue
			}
		}
		searchPos = endIdx + len(endTag)
	}

	return result
}

// decryptHrefElements decrypts filenames in href paths
func (h *WebDAVHandler) decryptHrefElements(xmlStr, startTag, endTag string, passwdInfo *config.PasswdInfo) string {
	result := xmlStr
	searchPos := 0

	for {
		startIdx := strings.Index(result[searchPos:], startTag)
		if startIdx == -1 {
			break
		}
		startIdx += searchPos

		endIdx := strings.Index(result[startIdx:], endTag)
		if endIdx == -1 {
			break
		}
		endIdx += startIdx

		contentStart := startIdx + len(startTag)
		hrefValue := result[contentStart:endIdx]

		// Only process /dav/ paths
		if strings.HasPrefix(hrefValue, "/dav/") {
			davPath := strings.TrimPrefix(hrefValue, "/dav")
			if davPath != "/" && davPath != "" {
				// Get the filename from the path
				fileName := path.Base(davPath)
				if fileName != "" && fileName != "/" && fileName != "." {
					decryptedName := encryption.ConvertShowName(passwdInfo.Password, passwdInfo.EncType, fileName)
					if decryptedName != "" && !encryption.IsOriginalFile(decryptedName) {
						// Replace only the filename part in the href
						newHref := "/dav" + path.Dir(davPath) + "/" + url.PathEscape(decryptedName)
						// Normalize path (remove double slashes)
						newHref = httputil.CleanPath(newHref)
						result = result[:contentStart] + newHref + result[endIdx:]
						searchPos = contentStart + len(newHref) + len(endTag)
						continue
					}
				}
			}
		}
		searchPos = endIdx + len(endTag)
	}

	return result
}
