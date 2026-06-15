package proxy

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/encryption"
	"github.com/alist-encrypt-go/internal/errors"
	"github.com/alist-encrypt-go/internal/httputil"
)

// RedirectRewriter can rewrite upstream redirect locations for decrypt streams.
// Return the new location and true if rewritten.
type RedirectRewriter func(req *http.Request, location string, fileSize int64, passwdInfo *config.PasswdInfo) (string, bool)

func (s *StreamProxy) handleRedirect(w http.ResponseWriter, req *http.Request, resp *http.Response, passwdInfo *config.PasswdInfo, fileSize int64, meta encryption.ContentMeta, rangeHeader string, strategy StreamStrategy, targetURL, compatStorageKey string) *StreamOutcome {
	location := resp.Header.Get("Location")
	if location == "" {
		return &StreamOutcome{Err: errors.NewProxyError("redirect without Location header")}
	}

	if s.shouldFollowRedirect(passwdInfo) {
		return s.followRedirectDecrypt(w, req, resp, passwdInfo, fileSize, meta, rangeHeader, strategy, targetURL, compatStorageKey)
	}

	newLocation := location
	if s.redirectRewriter != nil && passwdInfo != nil && passwdInfo.Enable {
		if rewritten, ok := s.redirectRewriter(req, location, fileSize, passwdInfo); ok && rewritten != "" {
			newLocation = rewritten
		}
	}

	httputil.CopyResponseHeaders(w, resp)
	w.Header().Set("Location", newLocation)
	w.WriteHeader(resp.StatusCode)
	return &StreamOutcome{ResponseStarted: true}
}

func (s *StreamProxy) shouldFollowRedirect(passwdInfo *config.PasswdInfo) bool {
	if s == nil || s.cfg == nil {
		return false
	}
	if !s.cfg.AlistServer.FollowRedirectForDecrypt {
		return false
	}
	return passwdInfo != nil && passwdInfo.Enable
}

func (s *StreamProxy) followRedirectDecrypt(w http.ResponseWriter, req *http.Request, resp *http.Response, passwdInfo *config.PasswdInfo, fileSize int64, meta encryption.ContentMeta, rangeHeader string, strategy StreamStrategy, targetURL, compatStorageKey string) *StreamOutcome {
	baseURL := resp.Request.URL
	currentURL := resolveRedirectURL(baseURL, resp.Header.Get("Location"))
	if currentURL == "" {
		return &StreamOutcome{Err: errors.NewProxyError("invalid redirect location")}
	}

	maxHops := 2
	if s.cfg != nil && s.cfg.AlistServer.RedirectMaxHops > 0 {
		maxHops = s.cfg.AlistServer.RedirectMaxHops
	}

	for hop := 0; hop < maxHops; hop++ {
		newReq, err := httputil.NewRequest(req.Method, currentURL).
			WithContext(req.Context()).
			CopyHeaders(req).
			Build()
		if err != nil {
			return &StreamOutcome{Err: errors.NewInternalWithCause("failed to create redirect request", err)}
		}

		sanitizeRedirectHeaders(newReq, req.URL, currentURL)
		applyStrategyHeaders(newReq, strategy)
		if strategy == StreamStrategyRange {
			newReq.Header.Set("Range", buildUpstreamRangeHeader(rangeHeader, meta))
		}
		if rangeHeader != "" && s.shouldSkipRange(currentURL, compatStorageKey) {
			newReq.Header.Del("Range")
		}

		nextResp, err := s.client.Do(newReq)
		if err != nil {
			reason, retryable := classifyStreamError(err)
			return &StreamOutcome{Err: errors.NewProxyErrorWithCause("failed to follow redirect", err), FailureReason: reason, Retryable: retryable}
		}

		if isRedirectStatus(nextResp.StatusCode) {
			location := nextResp.Header.Get("Location")
			nextResp.Body.Close()
			if location == "" {
				return &StreamOutcome{Err: errors.NewProxyError("redirect without Location header")}
			}
			baseURL, _ = url.Parse(currentURL)
			currentURL = resolveRedirectURL(baseURL, location)
			if currentURL == "" {
				return &StreamOutcome{Err: errors.NewProxyError("invalid redirect location")}
			}
			continue
		}

		return s.streamDecryptResponse(w, newReq, nextResp, passwdInfo, fileSize, meta, rangeHeader, strategy, currentURL, compatStorageKey)
	}

	return &StreamOutcome{Err: errors.NewProxyError("redirect hop limit exceeded")}
}

func isRedirectStatus(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

func resolveRedirectURL(base *url.URL, location string) string {
	if location == "" {
		return ""
	}
	loc, err := url.Parse(location)
	if err != nil {
		return ""
	}
	if loc.IsAbs() {
		return loc.String()
	}
	if base == nil {
		return ""
	}
	return base.ResolveReference(loc).String()
}

func sanitizeRedirectHeaders(req *http.Request, originalURL *url.URL, targetURL string) {
	if req == nil {
		return
	}
	target, err := url.Parse(targetURL)
	if err != nil {
		return
	}
	originalHost := ""
	if originalURL != nil {
		originalHost = originalURL.Host
	}
	if target.Host != "" && originalHost != "" && !strings.EqualFold(target.Host, originalHost) {
		req.Header.Del("Authorization")
		req.Header.Del("Cookie")
	}
	// Always strip WebDAV-specific and other foreign headers on redirect.
	// CDNs reject requests with unusual headers from WebDAV players.
	StripWebDAVHeaders(req)
	req.Header.Del("Referer")
	req.Host = ""
}
