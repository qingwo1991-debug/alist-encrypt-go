package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/metrics"
	"github.com/alist-encrypt-go/internal/trace"
)

func (h *AlistHandler) fetchFsListContent(r *http.Request, realPath string) ([]interface{}, error) {
	const perPage = 1000
	const maxFetchPages = 100 // Safety limit to prevent unbounded memory consumption

	var all []interface{}
	for page := 1; ; page++ {
		if page > maxFetchPages {
			log.Warn().Int("max_pages", maxFetchPages).Msg("fetchFsListContent reached page limit, stopping pagination")
			break
		}
		reqData := map[string]interface{}{
			"path":     realPath,
			"page":     page,
			"per_page": perPage,
			"refresh":  false,
		}
		body, _ := json.Marshal(reqData)
		resp, err := h.proxyToAlist(nil, "POST", "/api/fs/list", body, r)
		if err != nil {
			return nil, err
		}
		respBody, err := readLimitedBody(resp, maxProxyResponseBody)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}

		var respData map[string]interface{}
		if err := json.Unmarshal(respBody, &respData); err != nil {
			return nil, err
		}
		code, _ := respData["code"].(float64)
		if code != 200 {
			return nil, fmt.Errorf("list failed with code %.0f", code)
		}
		data, _ := respData["data"].(map[string]interface{})
		if data == nil {
			return nil, nil
		}
		content, _ := data["content"].([]interface{})
		if len(content) == 0 {
			break
		}
		all = append(all, content...)
		if len(content) < perPage {
			break
		}
	}

	return all, nil
}

// HandleFsList intercepts /api/fs/list to handle filename decryption
func (h *AlistHandler) HandleFsList(w http.ResponseWriter, r *http.Request) {
	body, err := readLimitedRequestBody(r)
	if err != nil {
		RespondHTTPErrorWithStatus(w, "Failed to read request", http.StatusBadRequest)
		return
	}

	var reqData map[string]interface{}
	if err := json.Unmarshal(body, &reqData); err != nil {
		RespondHTTPErrorWithStatus(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	dirPath, _ := reqData["path"].(string)
	if refresh, _ := reqData["refresh"].(bool); refresh && h.cfg.AlistServerSnapshot().PlaybackProfile == config.PlaybackProfileTrustedLocal && h.fileDAO != nil {
		h.fileDAO.InvalidateDisplayPath(dirPath)
	}
	page, perPage := listPaginationFromBody(reqData)
	trace.Logf(r.Context(), "list", "Handling fs list for path: %s", dirPath)
	listStart := time.Now()
	listResult := "live"
	defer func() {
		metrics.Inc("alist_fs_list_total", map[string]string{"result": listResult}, 1)
		metrics.Observe("alist_fs_list_duration_seconds", map[string]string{"result": listResult}, time.Since(listStart).Seconds())
	}()
	h.ensureDirSyncLoop()
	reqHeaders := h.requestAuthHeaders(r)
	authHash := h.requestScopeHash(reqHeaders)
	scopeKey := buildDirScopeKey(dirPath, authHash)
	if h.dirSyncStore != nil && h.snapshotScopeEnabled(dirPath) {
		h.rememberRecentList(dirPath, scopeKey, reqHeaders)
		snap, snapOK, _ := h.dirSyncStore.GetSnapshot(r.Context(), scopeKey)
		tok := effectiveBearerToken(reqHeaders)
		user := jwtUsernameClaim(tok)
		sum := sha256.Sum256([]byte(tok))
		log.Info().
			Str("path", dirPath).
			Str("scope_key", scopeKey).
			Bool("snap_ok", snapOK).
			Bool("has_payload", snap != nil && len(snap.PayloadJSON) > 0).
			Bool("scope_match", snap != nil && h.snapshotScopeMatches(snap, authHash)).
			Bool("tok_validated", h.authScope.has(tok)).
			Str("tok_fp", hex.EncodeToString(sum[:])[:8]).
			Str("user_fp", func() string {
				if user == "" {
					return ""
				}
				s := sha256.Sum256([]byte(user))
				return hex.EncodeToString(s[:])[:8]
			}()).
			Bool("has_cookie", strings.TrimSpace(reqHeaders.Get("Cookie")) != "").
			Msg("fslist snapshot lookup")
		if snapOK && snap != nil && len(snap.PayloadJSON) > 0 && h.snapshotScopeMatches(snap, authHash) {
			if isSuccessfulListPayload(snap.PayloadJSON) && !h.snapshotPayloadRootPoisoned(dirPath, snap.PayloadJSON) {
				if valid, reason := validateSnapshotForDir(dirPath, snap); valid {
					listResult = "snapshot"
					items := h.serveSnapshot(w, snap, "snapshot", page, perPage)
					h.enqueueProbeFromSnapshotItems(r, dirPath, items)
					if snap.NextRefreshAt.IsZero() || time.Now().After(snap.NextRefreshAt) || snap.Stale {
						h.refreshDirSnapshotAsync(dirPath, body, h.requestAuthHeaders(r), scopeKey, dirSyncModeReq)
					}
					return
				} else {
					log.Warn().
						Str("path", dirPath).
						Str("scope_key", scopeKey).
						Str("cache_mode", "snapshot").
						Str("reason", reason).
						Msg("Rejecting invalid dir snapshot")
				}
			} else if snapOK && snap != nil && h.snapshotPayloadRootPoisoned(dirPath, snap.PayloadJSON) {
				log.Error().
					Str("path", dirPath).
					Str("scope_key", scopeKey).
					Int("item_count", snap.ItemCount).
					Msg("Deleting root-poisoned dir snapshot (will fall back to live)")
				h.dirSyncStore.DeleteSnapshot(r.Context(), scopeKey)
			}
		}
		// Cross-session reuse: a rotated/new auth scope that misses its own
		// snapshot can still serve another of this same directory's fresh
		// request_fill snapshots (same creds, different session hash),
		// avoiding a ~1.5s rebuild per new token. Only request_fill rows are
		// eligible — background scan snapshots may carry a privileged scan
		// account and must not be served from this public endpoint. The lookup
		// is additionally filtered by the caller's auth hash AND provider host
		// so a higher-privileged account's listing is never served to a lower
		// one, and snapshots from another upstream URL are never reused.
		if snap, ok, _ := h.dirSyncStore.GetRequestFilledSnapshotByDisplay(r.Context(), normalizeDirPath(dirPath), authHash, h.cfg.GetAlistURL()); ok && snap != nil && len(snap.PayloadJSON) > 0 && snap.ItemCount > 0 && h.snapshotScopeMatches(snap, authHash) && !h.snapshotPayloadRootPoisoned(dirPath, snap.PayloadJSON) {
			if snap.NextRefreshAt.IsZero() || time.Now().Before(snap.NextRefreshAt) {
				if valid, reason := validateSnapshotForDir(dirPath, snap); valid {
					listResult = "snapshot-shared"
					items := h.serveSnapshot(w, snap, "snapshot-shared", page, perPage)
					h.enqueueProbeFromSnapshotItems(r, dirPath, items)
					if snap.NextRefreshAt.IsZero() || time.Now().After(snap.NextRefreshAt) || snap.Stale {
						h.refreshDirSnapshotAsync(dirPath, body, h.requestAuthHeaders(r), scopeKey, dirSyncModeReq)
					}
					return
				} else {
					log.Warn().
						Str("path", dirPath).
						Str("cache_mode", "snapshot-shared").
						Str("reason", reason).
						Msg("Rejecting shared dir snapshot")
				}
			}
		}
		// Background scan snapshots are populated with the configured scan account,
		// which may have broader permissions than the current caller. They are used
		// for preheating and the authenticated dir-sync views only; serving one from
		// this public Alist-compatible endpoint would bypass upstream authorization.
	}

	// Cold path (no local snapshot): coalesce concurrent misses for this same
	// directory into ONE shared full upstream listing via singleflight keyed by
	// the auth-scoped directory key (path + auth hash). This keeps the
	// thundering-herd optimization (N callers with the same credential fetch
	// once) while never letting a higher-privileged account's listing be served
	// to a different credential's callers, and keeps the persisted snapshot in
	// the correct scope for every joiner. The shared full payload is then
	// paginated per caller so every client keeps its own page window contract.
	// A full (per_page=5000) listing is persisted once by the flight leader.
	v, flightErr, _ := h.liveListGroup.Do(scopeKey, func() (interface{}, error) {
		// Build a detached request so no single client disconnect can abort the
		// shared flight (which would revive the thundering herd for the waiters).
		flightCtx := h.dirSyncCtx
		if flightCtx == nil {
			flightCtx = context.Background()
		}
		fakeAuth := h.requestAuthHeaders(r)
		detachReq, derr := http.NewRequestWithContext(flightCtx, http.MethodPost, "http://encrypt.local/api/fs/list", nil)
		if derr != nil {
			return nil, derr
		}
		for key, values := range fakeAuth {
			for _, value := range values {
				detachReq.Header.Add(key, value)
			}
		}
		detachReq.Header.Set("Content-Type", "application/json")
		var flightDoc map[string]interface{}
		fetch := func(reqBody []byte) (int, []byte, int, error) {
			status, doc, payload, count, err := h.liveFsListResponse(detachReq, reqBody, dirPath, true)
			flightDoc = doc
			return status, payload, count, err
		}
		upstreamBody := fullListRequestBody(body)
		statusCode, payload, itemCount, err := fetch(upstreamBody)
		if err != nil {
			return nil, err
		}
		// Upstream intermittently returns a drive-root masquerade (the 10
		// top-level mounts) instead of the real encrypted directory — a
		// transient cache bug in openalist. Retry once with refresh:true to
		// force the upstream to fetch fresh data; never serve the poisoned view.
		if h.snapshotScopeEnabled(dirPath) && h.snapshotPayloadRootPoisoned(dirPath, payload) {
			refreshBody := withRefreshTrue(upstreamBody)
			statusCode2, payload2, itemCount2, err2 := fetch(refreshBody)
			if err2 == nil && statusCode2 >= 200 && statusCode2 < 300 && !h.snapshotPayloadRootPoisoned(dirPath, payload2) {
				log.Info().Str("path", dirPath).Msg("Recovered from root-poison via refresh:true retry")
				statusCode, payload, itemCount = statusCode2, payload2, itemCount2
			} else {
				log.Warn().Str("path", dirPath).Msg("Root-poison retry with refresh:true did not help; serving poisoned fallback")
			}
		}
		// Persist the shared FULL listing immediately (single writer) as the
		// request-fill snapshot. This replaces the old "queue async refresh"
		// behavior on the cold path while keeping page-windowed callers from
		// ever overwriting the full row (fullListRequestBody guarantees full).
		// Use the handler's long-lived dir-sync context so the write outlives
		// the (possibly cancelled) leading request that triggered the flight.
		//
		// The fetch above just proved this credential upstream-valid, so
		// requestScopeHash now resolves to the stable per-account "u:" scope
		// for JWT credentials: persist under THAT scope so every rotated
		// token of the same account shares this snapshot instead of each
		// minting its own legacy-scope row.
		if h.dirSyncStore != nil && h.snapshotScopeEnabled(dirPath) && statusCode >= 200 && statusCode < 300 && isSuccessfulListPayload(payload) && !h.snapshotPayloadRootPoisoned(dirPath, payload) {
			persistHash := authHash
			if stable := h.requestScopeHash(fakeAuth); stable != "" {
				persistHash = stable
			}
			h.persistSnapshot(flightCtx, dirPath, buildDirScopeKey(dirPath, persistHash), persistHash, payload, itemCount, dirSyncModeReq, "")
		} else {
			log.Info().
				Str("path", dirPath).
				Str("scope_key", scopeKey).
				Int("status", statusCode).
				Bool("store", h.dirSyncStore != nil).
				Bool("scope_enabled", h.snapshotScopeEnabled(dirPath)).
				Bool("payload_ok", isSuccessfulListPayload(payload)).
				Bool("poisoned", h.snapshotPayloadRootPoisoned(dirPath, payload)).
				Msg("fslist snapshot persist skipped")
		}
		return &liveListFlight{StatusCode: statusCode, Payload: payload, ItemCount: itemCount, Doc: flightDoc}, nil
	})
	if flightErr != nil {
		listResult = "error"
		log.Error().Err(flightErr).Msg("Failed to proxy fs/list")
		RespondHTTPErrorWithStatus(w, "Proxy error", http.StatusBadGateway)
		return
	}
	flight := v.(*liveListFlight)
	respond := flight.Payload
	if page > 0 && perPage > 0 {
		if flight.Doc != nil {
			if sliced, ok := paginateListDoc(flight.Doc, page, perPage); ok {
				respond = sliced
			}
		} else if sliced, ok := paginateSnapshotJSON(respond, page, perPage); ok {
			respond = sliced
		}
	}
	RespondRaw(w, flight.StatusCode, "application/json", respond)
}
