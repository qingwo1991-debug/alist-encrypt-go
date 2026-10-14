package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/alist-encrypt-go/internal/httputil"
	"github.com/alist-encrypt-go/internal/proxy"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

// strictPlaybackMetadata deliberately does not publish into legacy unscoped
// metadata caches. A late inspection therefore cannot resurrect revoked state.
// The canonical fs/get is mandatory even if an old signed URL still works.
func strictPlaybackMetadata(req decryptPlaybackRequest, headers http.Header) (string, encryption.ContentMeta, uint64, error) {
	if req.Config == nil || req.Request == nil || req.StreamProxy == nil || req.FileItem.EncryptedPath == "" {
		return "", encryption.ContentMeta{}, 0, fmt.Errorf("strict freshness requires canonical encrypted path")
	}
	revision := req.Config.RuntimeRevision()
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
	// No service/admin fallback credentials and no TTL or supplied-size geometry.
	probeHeaders := headers
	if hostOfURL(raw) != hostOfURL(target) {
		probeHeaders = nil
	}
	result := req.StreamProxy.InspectEncryptedContentResult(req.Request.Context(), raw, probeHeaders, req.PasswdInfo, 0)
	if !result.Confirmed || result.Meta.CiphertextSize <= 0 || req.Request.Context().Err() != nil || req.Config.RuntimeRevision() != revision {
		return "", encryption.ContentMeta{}, revision, fmt.Errorf("fresh geometry unconfirmed or configuration changed")
	}
	return raw, result.Meta, revision, nil
}
