package handler

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/alist-encrypt-go/internal/httputil"
)

// Mount quota (upstream "mount_details") is attached by OpenList to every
// storage mount entry of an fs/list response. Upstream computes it with a
// per-driver GetDetails call behind a 1s wait and then caches the result for
// 30 minutes, so a listing either blocks for up to a second on a cold cache
// or serves a value that is almost half an hour old. On top of that, this
// proxy serves many listings from a directory snapshot, which freezes
// whatever quota upstream happened to return when the snapshot was taken.
//
// 5344 therefore keeps its own short-lived copy:
//
//   - every live fs/list response that passes through here is scanned for
//     mount entries and whatever quota it carries is remembered, keyed by the
//     caller's upstream account so a guest never sees quota that upstream
//     deliberately hides from guests;
//   - cached values are injected into every subsequent response for the same
//     account and directory (snapshot, shared snapshot and live alike), so
//     the page converges on the next natural listing instead of waiting;
//   - when a mount's quota is missing or older than mountQuotaTTL, the next
//     listing triggers ONE detached background refresh (coalesced per
//     account, bounded, honouring Stop). The current response is served
//     immediately with the value already cached.
//
// The refresh reuses the caller's own credentials exactly like the
// request_fill dir-sync path; no background scan account is involved.

const (
	// mountQuotaTTL is how long a cached quota value is served before a
	// refresh is attempted. The refresh is asynchronous, so an expired entry
	// keeps being served (stale-while-revalidate) until replaced.
	mountQuotaTTL = 60 * time.Second
	// mountQuotaRefreshTimeout bounds one background quota refresh. Upstream
	// spends up to 1s per mount on GetDetails; with many mounts a full root
	// listing can take several seconds, which must not pin the worker.
	mountQuotaRefreshTimeout = 20 * time.Second
	// mountQuotaRefreshMaxConcurrent bounds detached refreshes across all
	// accounts. Refreshes are pure optimization; excess work is dropped and
	// the next listing tries again.
	mountQuotaRefreshMaxConcurrent = 2
	// mountQuotaMaxEntries bounds the cache so account/token churn cannot
	// grow it without limit.
	mountQuotaMaxEntries = 512
)

// mountQuota is the upstream StorageDetails subset the UI renders.
type mountQuota struct {
	TotalSpace float64 `json:"total_space"`
	UsedSpace  float64 `json:"used_space"`
}

// mountQuotaEntry is one cached value plus enough context to refresh it.
type mountQuotaEntry struct {
	quota   mountQuota
	fetched time.Time
}

// mountQuotaCache is a small per-account quota store. Zero value is ready.
type mountQuotaCache struct {
	mu      sync.Mutex
	entries map[string]mountQuotaEntry // key = mountQuotaKey(account, mount path)
}

func mountQuotaKey(authHash, mountPath string) string {
	return authHash + "\x00" + mountPath
}

func (c *mountQuotaCache) get(authHash, mountPath string) (mountQuotaEntry, bool) {
	if c == nil {
		return mountQuotaEntry{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[mountQuotaKey(authHash, mountPath)]
	return e, ok
}

// remember stores a quota value with one of three freshness modes:
//
//   - freshQuota: the value came from an upstream call that bypassed its
//     details cache (refresh:true). Every entry is rewritten and starts a
//     new TTL.
//   - fillQuota: a plain live listing. Upstream serves its own 30-minute
//     cache here, so the value may already be old; it is only written when
//     the entry is missing (so the first listing after a restart has
//     something to show) and never postpones a pending refresh.
//   - replaceQuota: a plain listing used as fallback after refresh was
//     refused. The VALUE is updated (upstream may have re-cached since) but
//     the original fetched time is kept, so the entry stays stale and the
//     next listing retries a real refresh.
type quotaFreshness int

const (
	fillQuota quotaFreshness = iota
	freshQuota
	replaceQuota
)

func (c *mountQuotaCache) remember(authHash, mountPath string, q mountQuota, at time.Time, mode quotaFreshness) {
	if c == nil || authHash == "" || mountPath == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[string]mountQuotaEntry)
	}
	key := mountQuotaKey(authHash, mountPath)
	prev, exists := c.entries[key]
	switch mode {
	case fillQuota:
		if exists {
			return
		}
	case replaceQuota:
		if exists {
			at = prev.fetched
		}
	}
	if len(c.entries) >= mountQuotaMaxEntries {
		c.evictOldestHalfLocked()
	}
	c.entries[key] = mountQuotaEntry{quota: q, fetched: at}
}

// evictOldestHalfLocked drops the oldest half of the cache by fetched time.
// Caller holds c.mu.
func (c *mountQuotaCache) evictOldestHalfLocked() {
	type kv struct {
		k string
		e mountQuotaEntry
	}
	all := make([]kv, 0, len(c.entries))
	for k, e := range c.entries {
		all = append(all, kv{k, e})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].e.fetched.Before(all[j].e.fetched) })
	for i := 0; i < len(all)/2; i++ {
		delete(c.entries, all[i].k)
	}
}

// mountRef names one mount entry observed in a listing.
type mountRef struct {
	dirPath string
	name    string
}

func (m mountRef) mountPath() string {
	return joinMountPath(m.dirPath, m.name)
}

func joinMountPath(dirPath, name string) string {
	if dirPath == "" || dirPath == "/" {
		return "/" + name
	}
	return strings.TrimSuffix(dirPath, "/") + "/" + name
}

// hasStale reports whether any of the mounts lacks a fresh cached quota for
// this account.
func (c *mountQuotaCache) hasStale(authHash string, mounts []mountRef) bool {
	if c == nil || len(mounts) == 0 {
		return false
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, m := range mounts {
		e, ok := c.entries[mountQuotaKey(authHash, m.mountPath())]
		if !ok || now.Sub(e.fetched) > mountQuotaTTL {
			return true
		}
	}
	return false
}

// listMountEntries returns the directory entries of a list document. Upstream
// flags storage mounts as plain directories, so every is_dir entry is a
// candidate; the cache is keyed by path, so ordinary directories simply never
// match a quota and are left untouched.
func listMountEntries(doc map[string]interface{}) []map[string]interface{} {
	data, ok := doc["data"].(map[string]interface{})
	if !ok {
		return nil
	}
	content, ok := data["content"].([]interface{})
	if !ok {
		return nil
	}
	var out []map[string]interface{}
	for _, item := range content {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		isDir, _ := m["is_dir"].(bool)
		name, _ := m["name"].(string)
		if !isDir || name == "" {
			continue
		}
		out = append(out, m)
	}
	return out
}

func mountRefsFor(dirPath string, doc map[string]interface{}) []mountRef {
	var refs []mountRef
	for _, m := range listMountEntries(doc) {
		name, _ := m["name"].(string)
		refs = append(refs, mountRef{dirPath: dirPath, name: name})
	}
	return refs
}

// parseMountDetails reads the quota an upstream list entry carries. Upstream
// emits {"mount_details":{"total_space":..,"used_space":..}} on mount entries
// and omits it (or emits null) when details are unavailable or hidden.
func parseMountDetails(entry map[string]interface{}) (mountQuota, bool) {
	raw, ok := entry["mount_details"]
	if !ok || raw == nil {
		return mountQuota{}, false
	}
	md, ok := raw.(map[string]interface{})
	if !ok {
		return mountQuota{}, false
	}
	total, totalOK := md["total_space"].(float64)
	used, usedOK := md["used_space"].(float64)
	if !totalOK && !usedOK {
		return mountQuota{}, false
	}
	return mountQuota{TotalSpace: total, UsedSpace: used}, true
}

func (q mountQuota) encode() map[string]interface{} {
	return map[string]interface{}{
		"total_space": q.TotalSpace,
		"used_space":  q.UsedSpace,
	}
}

// observeMountQuota records whatever quota an upstream response carried, in
// the given freshness mode (see quotaFreshness). Read-only on doc, so it is
// safe on a doc shared between singleflight joiners.
func (h *AlistHandler) observeMountQuota(authHash, dirPath string, doc map[string]interface{}, mode quotaFreshness) {
	if h == nil || doc == nil {
		return
	}
	now := time.Now()
	for _, m := range listMountEntries(doc) {
		name, _ := m["name"].(string)
		if q, ok := parseMountDetails(m); ok {
			h.mountQuota.remember(authHash, joinMountPath(dirPath, name), q, now, mode)
		}
	}
}

// injectMountQuota writes the cached quota for this account into every mount
// entry that has one. The cached copy always wins over what the response
// carries: on the snapshot path the response value is frozen at snapshot
// time; on the live path the cache was just seeded from this same response,
// so the two are equal. Entries without a cached value are left untouched so
// a live response keeps whatever upstream sent and a snapshot keeps its
// (possibly null) copy rather than losing information.
//
// doc must be private to the caller: this writes into entry maps, and a doc
// shared between singleflight joiners (whose paginateListDoc only shallow
// copies) would race. Use applyMountQuotaToResponse for shared documents.
func (h *AlistHandler) injectMountQuota(authHash, dirPath string, doc map[string]interface{}) {
	if h == nil || doc == nil {
		return
	}
	for _, m := range listMountEntries(doc) {
		name, _ := m["name"].(string)
		e, ok := h.mountQuota.get(authHash, joinMountPath(dirPath, name))
		if !ok {
			continue
		}
		m["mount_details"] = e.quota.encode()
	}
}

// ensureMountQuotaForList is the entry point for a doc that is private to the
// caller (snapshot path: freshly unmarshalled per request). A snapshot's own
// quota is frozen at snapshot time and is never observed; only the cache is
// injected.
func (h *AlistHandler) ensureMountQuotaForList(authHash, dirPath string, doc map[string]interface{}, headers http.Header) {
	if h == nil || doc == nil {
		return
	}
	h.injectMountQuota(authHash, dirPath, doc)
	if h.mountQuota.hasStale(authHash, mountRefsFor(dirPath, doc)) {
		h.scheduleMountQuotaRefresh(authHash, dirPath, headers)
	}
}

// observeMountQuotaForSharedDoc is the live-flight variant: observe (as a
// best-effort fill, see observeMountQuota) and schedule, never write into
// doc, because every singleflight joiner shares it. Injection is then done
// per caller on the encoded response. Observation happens before the stale
// check only to fill missing entries; existing entries keep their TTL.
func (h *AlistHandler) observeMountQuotaForSharedDoc(authHash, dirPath string, doc map[string]interface{}, headers http.Header) {
	if h == nil || doc == nil {
		return
	}
	h.observeMountQuota(authHash, dirPath, doc, fillQuota)
	if h.mountQuota.hasStale(authHash, mountRefsFor(dirPath, doc)) {
		h.scheduleMountQuotaRefresh(authHash, dirPath, headers)
	}
}

// applyMountQuotaToResponse parses a caller-private encoded list response,
// injects cached quota, and re-encodes it. On any parse failure the input is
// returned unchanged so quota handling can never break a listing. Already
// paginated responses only carry the caller's page window; entries outside
// the window were already considered for refresh by the shared-doc pass.
func (h *AlistHandler) applyMountQuotaToResponse(authHash, dirPath string, respond []byte) []byte {
	if h == nil || len(respond) == 0 || h.mountQuota == nil {
		return respond
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(respond, &doc); err != nil || doc == nil {
		return respond
	}
	h.injectMountQuota(authHash, dirPath, doc)
	encoded, err := json.Marshal(doc)
	if err != nil {
		return respond
	}
	return encoded
}

// scheduleMountQuotaRefresh triggers one detached background refresh for the
// account when none is already running. Coalesced per account, bounded
// globally, and never blocks or fails the caller's response.
func (h *AlistHandler) scheduleMountQuotaRefresh(authHash, dirPath string, headers http.Header) {
	if h == nil || authHash == "" || len(headers) == 0 {
		return
	}
	h.mountQuotaMu.Lock()
	if h.mountQuotaStopped {
		h.mountQuotaMu.Unlock()
		return
	}
	if h.mountQuotaRefreshing == nil {
		h.mountQuotaRefreshing = make(map[string]bool)
	}
	if h.mountQuotaRefreshing[authHash] {
		h.mountQuotaMu.Unlock()
		return
	}
	select {
	case h.mountQuotaSem <- struct{}{}:
	default:
		h.mountQuotaMu.Unlock()
		return
	}
	h.mountQuotaRefreshing[authHash] = true
	ctx := h.mountQuotaCtx
	// Resolve the upstream URL here, on the caller's goroutine, so the
	// detached worker never reads the shared config. The request path already
	// dereferences cfg under its lock; doing it here keeps the worker free of
	// any config access for its whole lifetime.
	target := httputil.BuildTargetURL(h.cfg.GetAlistURL(), "/api/fs/list", nil)
	h.mountQuotaWG.Add(1)
	h.mountQuotaMu.Unlock()

	go func() {
		defer h.mountQuotaWG.Done()
		defer func() {
			if r := recover(); r != nil {
				log.Error().Interface("panic", r).Msg("Mount quota refresh panicked")
			}
			h.mountQuotaMu.Lock()
			delete(h.mountQuotaRefreshing, authHash)
			h.mountQuotaMu.Unlock()
			<-h.mountQuotaSem
		}()
		h.refreshMountQuota(ctx, authHash, dirPath, headers, target)
	}()
}

// stopMountQuota cancels and joins any in-flight refresh. Safe to call more
// than once; the first call wins.
func (h *AlistHandler) stopMountQuota() {
	if h == nil {
		return
	}
	h.mountQuotaStop.Do(func() {
		h.mountQuotaMu.Lock()
		h.mountQuotaStopped = true
		if h.mountQuotaCancel != nil {
			h.mountQuotaCancel()
		}
		h.mountQuotaMu.Unlock()
		h.mountQuotaWG.Wait()
	})
}

// refreshMountQuota performs one quota refresh for an account by listing the
// directory that owns the mounts with refresh:true so upstream bypasses its
// 30-minute details cache. refresh needs upstream write permission; a 403 for
// a read-only account falls back to the plain listing, which still carries
// upstream's cached (older but valid) quota instead of none.
func (h *AlistHandler) refreshMountQuota(ctx context.Context, authHash, dirPath string, headers http.Header, target string) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, mountQuotaRefreshTimeout)
	defer cancel()

	run := func(refresh bool) bool {
		reqBody, _ := json.Marshal(map[string]interface{}{
			"path":     dirPath,
			"page":     1,
			"per_page": 0,
			"refresh":  refresh,
			"password": "",
		})
		req, err := httputil.NewRequest(http.MethodPost, target).
			WithContext(ctx).
			WithBody(reqBody).
			WithHeader("Content-Type", "application/json").
			Build()
		if err != nil {
			return false
		}
		for k, vs := range headers {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
		resp, err := h.httpClient.Do(req)
		if err != nil {
			log.Warn().Err(err).Str("path", dirPath).Bool("refresh", refresh).Msg("Mount quota refresh failed")
			return false
		}
		respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxProxyResponseBody+1))
		resp.Body.Close()
		if err != nil || int64(len(respBody)) > maxProxyResponseBody {
			return false
		}
		var doc map[string]interface{}
		if err := json.Unmarshal(respBody, &doc); err != nil {
			return false
		}
		if code, _ := doc["code"].(float64); code != 200 {
			log.Debug().Float64("code", code).Bool("refresh", refresh).Str("path", dirPath).Msg("Mount quota refresh rejected upstream")
			return false
		}
		// Only a refresh:true listing bypassed upstream's details cache, so
		// only it restarts the TTL. The plain fallback updates the value but
		// stays stale so the next listing retries a real refresh.
		mode := replaceQuota
		if refresh {
			mode = freshQuota
		}
		h.observeMountQuota(authHash, dirPath, doc, mode)
		return true
	}

	if run(true) {
		return
	}
	run(false)
}
