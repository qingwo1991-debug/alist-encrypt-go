package handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/alist-encrypt-go/internal/storage"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

type filenameRetryRepository interface {
	FindFilenameReservationForRead(string, string) (storage.FilenameRecord, bool, error)
	ReleaseFailedFilename(storage.FilenameRecord) error
}

func filenameOperationError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": code, "retryable": false})
}

// The management JWT belongs exclusively in Authorizetoken. Requiring explicit
// DAV Basic credentials also prevents accidentally treating that JWT as an
// upstream credential. Never fall back to configured administrator credentials.
func filenameRetryDAVCredentials(r *http.Request) bool {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Basic ") || values[0] == r.Header.Get("Authorizetoken") {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(values[0], "Basic "))
	user, _, ok := strings.Cut(string(decoded), ":")
	return err == nil && ok && user != "" && !strings.ContainsAny(string(decoded), "\x00\r\n")
}

// Retry must reproduce the *current* protected write mapping exactly, including
// its shortening policy. Merely being decryptable is insufficient for release.
func (h *WebDAVHandler) freshFilenameRetryRule(rec storage.FilenameRecord, revision uint64) bool {
	ep, ok := h.freshFilenameRecoveryRule(rec, revision)
	limit := protectedFilenameLimit(h.cfg, rec.OriginalPath)
	if !ok || limit <= 0 || path.Dir(rec.EncryptedPath) != path.Dir(rec.OriginalPath) {
		return false
	}
	suffix := ep.EncSuffix
	if suffix == "" {
		suffix = path.Ext(rec.OriginalPath)
	}
	encoded, short, err := encryption.BoundEncryptedFilename(ep.Password, ep.EncType, path.Base(rec.OriginalPath), suffix, limit)
	return err == nil && path.Join(path.Dir(rec.OriginalPath), encoded) == rec.EncryptedPath && short == rec.DisplayName && h.cfg.RuntimeRevision() == revision
}

// filenameRetryAPIJSON sends only an explicitly chosen API credential. It never
// copies request headers, configured credentials, cookies or the management JWT.
// Login tokens live only in this call stack, with no logging or persistence.
func filenameRetryAPIJSON(ctx context.Context, client *http.Client, origin, endpoint, token string, payload interface{}, result interface{}) bool {
	body, err := json.Marshal(payload)
	if err != nil {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	u.Path, u.RawPath, u.RawQuery, u.Fragment = endpoint, "", "", ""
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	if token != "" {
		req.Header.Set("Authorization", token)
	}
	if client == nil {
		client = http.DefaultClient
	}
	snapshot := *client
	snapshot.Jar = nil
	snapshot.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := snapshot.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	const maxBody = 8 * 1024 * 1024
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	return err == nil && len(raw) <= maxBody && json.Unmarshal(raw, result) == nil
}

// This caller-scoped parent probe can reject unsafe inputs but CANNOT establish
// physical absence. Login may rewrite paths through base_path, and fs/list may
// filter, deduplicate or return virtual navigation even after driver failure.
// Neither success nor total == len(content) authorizes releasing a local claim.
// Login derives an API token ONLY from the caller's explicit DAV Basic pair.
func filenameRetryCheckParentAbsent(r *http.Request, origin, raw string, client *http.Client) (int, string) {
	if !strings.HasPrefix(raw, "/") || path.Clean(raw) != raw || raw == "/" || strings.ContainsAny(raw, "\x00\r\n\\") {
		return http.StatusConflict, "filename_mapping_changed"
	}
	user, password, ok := r.BasicAuth()
	if !ok || user == "" {
		return http.StatusServiceUnavailable, "parent_inventory_unavailable"
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	var login struct {
		Code int `json:"code"`
		Data *struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if !filenameRetryAPIJSON(ctx, client, origin, "/api/auth/login", "", map[string]string{"username": user, "password": password}, &login) || login.Code != 200 || login.Data == nil || login.Data.Token == "" || strings.TrimSpace(login.Data.Token) != login.Data.Token || strings.ContainsAny(login.Data.Token, "\x00\r\n") {
		return http.StatusServiceUnavailable, "parent_inventory_unavailable"
	}
	var listing struct {
		Code int `json:"code"`
		Data *struct {
			Total   *int64          `json:"total"`
			Content json.RawMessage `json:"content"`
		} `json:"data"`
	}
	payload := map[string]interface{}{"path": path.Dir(raw), "page": 1, "per_page": 0, "refresh": true, "password": ""}
	if !filenameRetryAPIJSON(ctx, client, origin, "/api/fs/list", login.Data.Token, payload, &listing) || listing.Code != 200 || listing.Data == nil || listing.Data.Total == nil || *listing.Data.Total < 0 {
		return http.StatusServiceUnavailable, "parent_inventory_unavailable"
	}
	content := bytes.TrimSpace(listing.Data.Content)
	if len(content) == 0 || content[0] != '[' {
		return http.StatusServiceUnavailable, "parent_inventory_unavailable"
	}
	var entries []struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(content, &entries) != nil || entries == nil || int64(len(entries)) != *listing.Data.Total {
		return http.StatusServiceUnavailable, "parent_inventory_unavailable"
	}
	seen := make(map[string]bool, len(entries))
	found := false
	for _, entry := range entries {
		name := entry.Name
		if name == "" || name == "." || name == ".." || path.Base(name) != name || strings.ContainsAny(name, "\x00\r\n\\/") || seen[name] {
			return http.StatusServiceUnavailable, "parent_inventory_unavailable"
		}
		seen[name] = true
		found = found || name == path.Base(raw)
	}
	if found {
		return http.StatusConflict, "destination_present"
	}
	return 0, ""
}

// Two canonical DAV 404s are NOT sufficient proof of physical absence: base_path
// may rewrite the namespace, and unhealthy mounts or denied access can yield 404.
// These read-only probes can only reject; they never authorize local release.
// Task lists also cannot prove quiescence, especially with task_persistant=false.
func filenameRetryCheckAbsent(r *http.Request, origin, raw string, client *http.Client) (int, string) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	u, err := url.Parse(origin)
	if err != nil {
		return http.StatusServiceUnavailable, "upstream_unavailable"
	}
	u.Path, u.RawPath, u.RawQuery, u.Fragment = "/dav"+raw, "", "", ""
	if client == nil {
		client = http.DefaultClient
	}
	snapshot := *client
	snapshot.Jar = nil
	snapshot.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for _, method := range []string{http.MethodHead, "PROPFIND"} {
		var body io.Reader
		if method == "PROPFIND" {
			body = strings.NewReader(`<d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/></d:prop></d:propfind>`)
		}
		probe, err := http.NewRequestWithContext(ctx, method, u.String(), body)
		if err != nil {
			return http.StatusServiceUnavailable, "upstream_unavailable"
		}
		probe.Header.Set("Authorization", r.Header.Get("Authorization"))
		probe.Header.Set("Accept-Encoding", "identity")
		if method == "PROPFIND" {
			probe.Header.Set("Depth", "0")
			probe.Header.Set("Content-Type", "application/xml")
		}
		resp, err := snapshot.Do(probe)
		if err != nil {
			var timeout net.Error
			if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &timeout) && timeout.Timeout() {
				return http.StatusGatewayTimeout, "upstream_unavailable"
			}
			return http.StatusServiceUnavailable, "upstream_unavailable"
		}
		status := resp.StatusCode
		_ = resp.Body.Close()
		if status >= 200 && status < 300 {
			return http.StatusConflict, "destination_present"
		}
		if status != http.StatusNotFound {
			return http.StatusServiceUnavailable, "upstream_unavailable"
		}
	}
	return 0, ""
}

// HandleRetryFilename MUST remain in the management JWT group. It never uploads
// or deletes a cloud object, nor releases a local claim. dry_run inspects only
// the local digest/status. Even with the environment opt-in, valid maintenance
// approval, fresh rules and successful API/DAV probes, release fails closed until
// an authoritative bridge can prove the physical namespace, inventory and safety.
func (h *WebDAVHandler) HandleRetryFilename(w http.ResponseWriter, r *http.Request) {
	fail := func(status int, code string) { filenameOperationError(w, status, code) }
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		fail(http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	var req struct {
		OriginalPath         string `json:"original_path"`
		AuditDigest          string `json:"audit_digest"`
		MaintenanceConfirmed bool   `json:"maintenance_confirmed"`
		DryRun               bool   `json:"dry_run"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	dec.DisallowUnknownFields()
	if dec.Decode(&req) != nil || dec.Decode(new(interface{})) != io.EOF || len(req.OriginalPath) > 4096 || req.OriginalPath == "/" || path.Clean(req.OriginalPath) != req.OriginalPath || !strings.HasPrefix(req.OriginalPath, "/") || strings.ContainsAny(req.OriginalPath, "\x00\r\n\\") {
		fail(http.StatusBadRequest, "invalid_request")
		return
	}
	if !filenameRetryDAVCredentials(r) {
		fail(http.StatusBadRequest, "explicit_dav_credentials_required")
		return
	}
	if !req.DryRun && os.Getenv("ALIST_FILENAME_RETRY_MAINTENANCE_ENABLE") != "1" {
		fail(http.StatusServiceUnavailable, "maintenance_release_disabled")
		return
	}
	if !req.DryRun && (!req.MaintenanceConfirmed || len(req.AuditDigest) != 64) {
		fail(http.StatusBadRequest, "maintenance_confirmation_and_audit_required")
		return
	}
	repo, ok := h.fileDAO.(filenameRetryRepository)
	if !ok || h.cfg == nil || h.passwdDAO == nil {
		fail(http.StatusServiceUnavailable, "filename_store_unavailable")
		return
	}
	revision, origin := h.cfg.RuntimeRevision(), h.cfg.GetAlistURL()
	rec, found, err := repo.FindFilenameReservationForRead(origin, req.OriginalPath)
	if err != nil {
		fail(http.StatusServiceUnavailable, "filename_inspection_unavailable")
		return
	}
	if !found || !h.freshFilenameRetryRule(rec, revision) {
		fail(http.StatusConflict, "filename_mapping_changed")
		return
	}
	digest := storage.FilenameAuditDigest(rec)
	if req.DryRun {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]string{"audit_digest": digest, "status": rec.Status})
		return
	}
	if req.AuditDigest != digest {
		fail(http.StatusConflict, "filename_audit_changed")
		return
	}
	if rec.Status != storage.FilenameFailed {
		fail(http.StatusConflict, "reserved_"+rec.Status)
		return
	}
	if rec.UpdatedAt.IsZero() || time.Since(rec.UpdatedAt) < storage.FilenameRetryMinAge {
		fail(http.StatusConflict, "failed_reservation_too_recent")
		return
	}
	if status, code := filenameRetryCheckParentAbsent(r, origin, rec.EncryptedPath, h.getShortClient()); status != 0 {
		fail(status, code)
		return
	}
	if status, code := filenameRetryCheckAbsent(r, origin, rec.EncryptedPath, h.getShortClient()); status != 0 {
		fail(status, code)
		return
	}
	if !h.freshFilenameRetryRule(rec, revision) || r.Context().Err() != nil {
		fail(http.StatusConflict, "filename_mapping_changed")
		return
	}
	// Mandatory final safety gate: caller-scoped API/DAV paths and successful
	// lists cannot prove the physical parent or cross-writer quiescence. Keep
	// every reservation and its audit intact even when the opt-in is "1".
	// No local ReleaseFailedFilename/PublishIfRevision call is reachable here.
	fail(http.StatusServiceUnavailable, "physical_parent_proof_unavailable")
}
