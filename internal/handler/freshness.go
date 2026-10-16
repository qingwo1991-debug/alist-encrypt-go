package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/httputil"
	"github.com/alist-encrypt-go/internal/proxy"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

type playbackAdmissionKey struct{}
type playbackAdmission struct{ revision uint64 }

// Capture before ANY rule lookup, alias restoration or route selection. Never
// manufacture a new epoch later around an already selected password/path.
func withPlaybackAdmission(r *http.Request, cfg *config.Config) *http.Request {
	if r == nil || cfg == nil {
		return r
	}
	if _, ok := r.Context().Value(playbackAdmissionKey{}).(playbackAdmission); ok {
		return r
	}
	return r.WithContext(context.WithValue(r.Context(), playbackAdmissionKey{}, playbackAdmission{cfg.RuntimeRevision()}))
}

func samePlaybackOrigin(a, b string) bool {
	left, le := url.Parse(a)
	right, re := url.Parse(b)
	if le != nil || re != nil || left.Hostname() == "" || right.Hostname() == "" {
		return false
	}
	port := func(u *url.URL) string {
		if u.Port() != "" {
			return u.Port()
		}
		if strings.EqualFold(u.Scheme, "https") {
			return "443"
		}
		return "80"
	}
	return strings.EqualFold(left.Scheme, right.Scheme) && strings.EqualFold(left.Hostname(), right.Hostname()) && port(left) == port(right)
}

// strictPlaybackMetadata deliberately does not publish into legacy unscoped
// metadata caches. A late inspection therefore cannot resurrect revoked state.
// The canonical fs/get is mandatory even if an old signed URL still works.
func strictPlaybackMetadata(req decryptPlaybackRequest, headers http.Header) (string, encryption.ContentMeta, uint64, error) {
	if req.Config == nil || req.Request == nil || req.StreamProxy == nil || req.FileItem.EncryptedPath == "" {
		return "", encryption.ContentMeta{}, 0, fmt.Errorf("strict freshness requires canonical encrypted path")
	}
	admission, admitted := req.Request.Context().Value(playbackAdmissionKey{}).(playbackAdmission)
	revision := admission.revision
	if !admitted || req.Config.RuntimeRevision() != revision || req.Request.Context().Err() != nil {
		return "", encryption.ContentMeta{}, revision, fmt.Errorf("missing or superseded playback admission")
	}
	body, _ := json.Marshal(map[string]interface{}{"path": req.FileItem.EncryptedPath, "refresh": true})
	target := httputil.BuildTargetURLStripped(req.Config.GetAlistURL(), "/api/fs/get")
	upstream, err := http.NewRequestWithContext(req.Request.Context(), http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return "", encryption.ContentMeta{}, revision, err
	}
	upstream.Header.Set("Content-Type", "application/json")
	copyAuthHeaders(upstream, headers)
	upstream.Header.Set("Cache-Control", "no-cache")
	resp, err := proxy.NewHTTPClient(req.Config, 8*time.Second).Do(upstream)
	if err != nil {
		return "", encryption.ContentMeta{}, revision, err
	}
	defer resp.Body.Close()
	var payload struct {
		Code int `json:"code"`
		Data struct {
			RawURL string `json:"raw_url"`
		} `json:"data"`
	}
	if resp.StatusCode != http.StatusOK {
		return "", encryption.ContentMeta{}, revision, fmt.Errorf("authorized metadata status %d", resp.StatusCode)
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&payload); err != nil {
		return "", encryption.ContentMeta{}, revision, err
	}
	raw := strings.TrimSpace(payload.Data.RawURL)
	if payload.Code != http.StatusOK || raw == "" {
		return "", encryption.ContentMeta{}, revision, fmt.Errorf("authorized metadata denied or missing route")
	}
	if req.Config.RuntimeRevision() != revision || req.Request.Context().Err() != nil {
		return "", encryption.ContentMeta{}, revision, fmt.Errorf("playback admission superseded before geometry inspection")
	}
	// No service/admin fallback credentials and no TTL or supplied-size geometry.
	probeHeaders := headers
	if !samePlaybackOrigin(raw, target) {
		probeHeaders = nil
	}
	result := req.StreamProxy.InspectEncryptedContentResult(req.Request.Context(), raw, probeHeaders, req.PasswdInfo, 0)
	if !result.Confirmed || result.Meta.CiphertextSize <= 0 || req.Request.Context().Err() != nil || req.Config.RuntimeRevision() != revision {
		return "", encryption.ContentMeta{}, revision, fmt.Errorf("fresh geometry unconfirmed or configuration changed")
	}
	return raw, result.Meta, revision, nil
}
