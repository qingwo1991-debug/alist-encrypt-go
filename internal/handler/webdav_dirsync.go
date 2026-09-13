package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/alist-encrypt-go/internal/trace"
)

// snapshotScopeEnabled reports whether the given directory is eligible for
// snapshot read/write caching by the WebDAV handler. Only directories matched
// by the user's configured encryption path whitelist (via MatchDir, which
// honors * and even "/") are cached; every other path stays a pure live proxy.
func (h *WebDAVHandler) snapshotScopeEnabled(dirPath string) bool {
	return h != nil && h.passwdDAO != nil && h.passwdDAO.MatchDir(dirPath)
}

// davScopeDir normalizes a WebDAV request path to the directory scope used by
// the shared snapshot store: leading "/", no trailing "/", empty -> "/".
func davScopeDir(davPath string) string {
	return normalizeDirPath(strings.TrimSuffix(strings.TrimSuffix(davPath, "/"), "/"))
}

// davHref returns the WebDAV href (with /dav prefix) for a snapshot display path.
func davHref(displayPath string) string {
	if displayPath == "" {
		return "/dav"
	}
	if !strings.HasPrefix(displayPath, "/") {
		displayPath = "/" + displayPath
	}
	return "/dav" + displayPath
}

func writeDavEscaped(b *bytes.Buffer, s string) {
	_ = xml.EscapeText(b, []byte(s))
}

// writeSnapshotResponse writes one DAV <response> block (href + propstat) for a
// single item. isDir selects resourcetype; size is only emitted for non-dirs.
func writeSnapshotResponse(b *bytes.Buffer, href, name string, isDir bool, size int64) {
	b.WriteString(`<D:response>`)
	b.WriteString(`<D:href>`)
	writeDavEscaped(b, href)
	b.WriteString(`</D:href>`)
	b.WriteString(`<D:propstat>`)
	b.WriteString(`<D:prop>`)
	b.WriteString(`<D:displayname>`)
	writeDavEscaped(b, name)
	b.WriteString(`</D:displayname>`)
	if !isDir {
		b.WriteString(`<D:getcontentlength>`)
		b.WriteString(strconv.FormatInt(size, 10))
		b.WriteString(`</D:getcontentlength>`)
	}
	b.WriteString(`<D:resourcetype>`)
	if isDir {
		b.WriteString(`<D:collection/>`)
	}
	b.WriteString(`</D:resourcetype>`)
	b.WriteString(`</D:prop>`)
	b.WriteString(`<D:status>HTTP/1.1 200 OK</D:status>`)
	b.WriteString(`</D:propstat>`)
	b.WriteString(`</D:response>`)
}

// itemDAVHref computes the href for a snapshot child entry.
func itemDAVHref(dirPath, childPath, name string, isDir bool) string {
	itemPath := childPath
	if itemPath == "" {
		itemPath = path.Join(dirPath, name)
	} else {
		itemPath = normalizeDirPath(childPath)
	}
	href := davHref(itemPath)
	if isDir && !strings.HasSuffix(href, "/") {
		href += "/"
	}
	return href
}

// serveSnapshotListing tries to satisfy a directory PROPFIND request from the
// shared dir-sync snapshot, returning (body, true) on cache hit or (nil, false)
// so the caller falls through to the live upstream call. Only directory
// listings are eligible — single-file PROPFINDs and the neg-cache path always
// go live — and only for whitelisted encrypted paths.
func (h *WebDAVHandler) serveSnapshotListing(r *http.Request, davPath string) ([]byte, bool) {
	if h == nil || h.dirSyncStore == nil || h.passwdDAO == nil {
		return nil, false
	}
	// Depth:0 asks only for the resource's own props; serving children would
	// diverge from the live response, so only cover actual listings.
	if strings.TrimSpace(r.Header.Get("Depth")) == "0" {
		return nil, false
	}
	dirPath := davScopeDir(davPath)
	if !h.snapshotScopeEnabled(dirPath) {
		return nil, false
	}
	// Cross-storage reuse: a rotated/new auth scope shares the fresh
	// request_fill snapshot of the same directory (like the HTTP path), so the
	// WebDAV cold path is fast before scan preheats the directory. Only the
	// MySQL backend can enumerate by display path; the Bolt backend falls back
	// to the same-session scope key.
	var snap *DirListSnapshot
	var ok bool
	if s, found, _ := h.dirSyncStore.GetRequestFilledSnapshotByDisplay(r.Context(), dirPath); found && s != nil {
		snap, ok = s, true
	} else {
		scopeKey := buildDirScopeKey(dirPath, authScopeHash(h.webdavAuthHeaders(r)))
		s, found, _ := h.dirSyncStore.GetSnapshot(r.Context(), scopeKey)
		snap, ok = s, found
	}
	if !ok || snap == nil || len(snap.PayloadJSON) == 0 {
		return nil, false
	}
	// Only fresh 200-list payloads are cacheable; a non-success payload must
	// never be re-emitted as a directory listing.
	if !isSuccessfulListPayload(snap.PayloadJSON) {
		return nil, false
	}
	if valid, reason := validateSnapshotForDir(dirPath, snap); !valid {
		trace.Logf(r.Context(), "propfind", "Snapshot cache rejected %s: %s", davPath, reason)
		return nil, false
	}
	body := h.buildSnapshotMultistatus(dirPath, snap.PayloadJSON)
	if len(body) == 0 {
		return nil, false
	}
	return body, true
}

// buildSnapshotMultistatus converts a directory snapshot payload (OpenList
// /api/fs/list style JSON with data.content items: {name,is_dir,size,path}) into
// a WebDAV multistatus body. The requested directory itself is included as the
// first <response> so the body is a drop-in for what the live upstream PROPFIND
// would have produced after the passwd-name rewrites.
func (h *WebDAVHandler) buildSnapshotMultistatus(dirPath string, payload []byte) []byte {
	var resp struct {
		Data struct {
			Content []map[string]interface{} `json:"content"`
		} `json:"data"`
	}
	if err := json.Unmarshal(payload, &resp); err != nil {
		return nil
	}

	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?>`)
	b.WriteString(`<D:multistatus xmlns:D="DAV:">`)

	// The collection itself.
	rootName := path.Base(strings.TrimSuffix(normalizeDirPath(dirPath), "/"))
	if rootName == "" || rootName == "." || rootName == "/" {
		rootName = "/"
	}
	writeSnapshotResponse(&b, davHref(dirPath)+"/", rootName, true, 0)

	// Children.
	for _, item := range resp.Data.Content {
		name, _ := item["name"].(string)
		if name == "" {
			continue
		}
		isDir, _ := item["is_dir"].(bool)
		size := int64(0)
		if s, ok := item["size"].(float64); ok {
			size = int64(s)
		}
		childPath, _ := item["path"].(string)
		href := itemDAVHref(dirPath, childPath, name, isDir)
		writeSnapshotResponse(&b, href, name, isDir, size)
	}
	b.WriteString(`</D:multistatus>`)
	return b.Bytes()
}

// persistWebDAVSnapshot writes a live WebDAV directory listing into the shared
// dir-sync snapshot store so subsequent HTTP fs/list and WebDAV reads in this
// whitelist hit the fast path. Only directory listings are persisted; a
// single-file PROPFIND carries no directory snapshot.
func (h *WebDAVHandler) persistWebDAVSnapshot(r *http.Request, davPath string, entries []propfindEntry) {
	if h == nil || h.dirSyncStore == nil {
		return
	}
	dirPath := davScopeDir(davPath)
	if !h.snapshotScopeEnabled(dirPath) {
		return
	}
	if len(entries) == 0 {
		return
	}
	// Entries include the directory's own response (self) plus each child; the
	// snapshot content holds children only, matching the HTTP fs/list payload.
	// Names here are already the decrypted display names from parsePropfindResponse.
	content := make([]map[string]interface{}, 0, len(entries))
	for _, e := range entries {
		childPath := normalizeDirPath(e.Path)
		if childPath == dirPath || childPath == "" {
			continue // self response
		}
		content = append(content, map[string]interface{}{
			"name":   e.Name,
			"path":   childPath,
			"size":   float64(e.Size),
			"is_dir": e.IsDir,
		})
	}
	if len(content) == 0 {
		return
	}
	payload, err := json.Marshal(map[string]interface{}{
		"code": 200,
		"data": map[string]interface{}{
			"total":   len(content),
			"content": content,
		},
	})
	if err != nil {
		return
	}
	scopeKey := buildDirScopeKey(dirPath, authScopeHash(h.webdavAuthHeaders(r)))
	h.upsertWebDAVSnapshot(r.Context(), dirPath, scopeKey, payload, len(content))
}

// upsertWebDAVSnapshot persists a request-fill dir snapshot under the shared
// store, mirroring AlistHandler.persistSnapshot semantics (same string
// constants and TTL) so HTTP and WebDAV serve identical cached listings.
func (h *WebDAVHandler) upsertWebDAVSnapshot(ctx context.Context, dirPath, scopeKey string, payload []byte, itemCount int) {
	if h == nil || h.dirSyncStore == nil || h.cfg == nil {
		return
	}
	now := time.Now()
	snap := DirListSnapshot{
		ScopeKey:      scopeKey,
		ProviderHost:  h.cfg.GetAlistURL(),
		DisplayPath:   dirPath,
		AuthScopeHash: "",
		RuleVersion:   "v1",
		ItemCount:     itemCount,
		Stale:         false,
		SyncState:     "fresh",
		LastSyncAt:    now,
		LastSuccessAt: now,
		NextRefreshAt: now.Add(listResponseTTL(dirSyncModeReq)),
		SourceMode:    dirSyncModeReq,
		PayloadJSON:   payload,
		UpdatedAt:     now,
		LastAccessed:  now,
	}
	_ = h.dirSyncStore.UpsertSnapshot(ctx, snap)
}

func (h *WebDAVHandler) webdavAuthHeaders(r *http.Request) http.Header {
	if r == nil {
		return nil
	}
	if a := strings.TrimSpace(r.Header.Get("Authorization")); a != "" {
		hdr := make(http.Header, 1)
		hdr.Set("Authorization", a)
		return hdr
	}
	return nil
}
