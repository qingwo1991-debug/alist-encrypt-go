package handler

import (
	"encoding/json"
	"net/http"
	"path"

	"github.com/alist-encrypt-go/internal/config"
)

func (h *AlistHandler) resolveRemoveName(dirPath, name string, passwdInfo *config.PasswdInfo) string {
	return h.resolveUpstreamNameForRequest(nil, dirPath, name, passwdInfo)
}

// resolveUpstreamNameForRequest maps one display basename under dirPath to the
// single upstream basename that mutating APIs (remove/move/copy) must send.
// Cached mappings win; otherwise plaintext directories/files keep their
// spelling and only names with no upstream object are filename-encrypted.
func (h *AlistHandler) resolveUpstreamNameForRequest(r *http.Request, dirPath, name string, passwdInfo *config.PasswdInfo) string {
	displayPath := path.Join(dirPath, name)
	return h.resolveUpstreamNameWithProbe(r, dirPath, name, displayPath, passwdInfo, func() bool {
		exists, _ := h.probeDisplayObject(r, displayPath)
		return exists
	})
}

// resolveUpstreamNameWithProbe is resolveUpstreamNameForRequest with the
// upstream existence probe injectable, so batch callers can substitute one
// directory listing for N per-name fs/get probes. The decision chain itself
// lives in nameResolver so every mutation entry point shares it.
func (h *AlistHandler) resolveUpstreamNameWithProbe(r *http.Request, dirPath, name, displayPath string, passwdInfo *config.PasswdInfo, probe func() bool) string {
	return newNameResolver(h.fileDAO, passwdInfo).upstreamBasename(dirPath, name, probe)
}

// probeDisplayObject asks upstream whether displayPath exists as a real
// object and reports whether it is a directory.
func (h *AlistHandler) probeDisplayObject(r *http.Request, displayPath string) (bool, bool) {
	if r == nil || h == nil {
		return false, false
	}
	body, err := json.Marshal(map[string]string{"path": displayPath})
	if err != nil {
		return false, false
	}
	resp, err := h.proxyToAlist(r, http.MethodPost, "/api/fs/get", body, r)
	if err != nil {
		return false, false
	}
	defer resp.Body.Close()
	respBody, err := readLimitedBody(resp, maxProxyResponseBody)
	if err != nil {
		return false, false
	}
	var payload struct {
		Code float64 `json:"code"`
		Data *struct {
			IsDir bool `json:"is_dir"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &payload); err != nil {
		return false, false
	}
	return payload.Code == 200 && payload.Data != nil, payload.Data != nil && payload.Data.IsDir
}

// displayPathForUpstreamName recovers the cached display path for a request
// name that may carry the upstream spelling (already-encrypted or
// orig_-stripped). Falls back to dirPath/name when nothing is cached.
func (h *AlistHandler) displayPathForUpstreamName(dirPath, name string, upstreamNames []string, index int) string {
	displayPath := path.Join(dirPath, name)
	upstreamName := name
	if index >= 0 && index < len(upstreamNames) && upstreamNames[index] != "" {
		upstreamName = upstreamNames[index]
	}
	if info, ok := h.fileDAO.Get(path.Join(dirPath, upstreamName)); ok && info != nil && info.Path != "" {
		return info.Path
	}
	return displayPath
}

// dirObjectSet is one upstream directory listing used to answer existence
// probes locally during batch name resolution.
type dirObjectSet struct {
	names map[string]bool // upstream basename -> is_dir
}

// fetchDirObjectSet lists dirPath once upstream and indexes the raw entry
// names. It also warms the display<->upstream name mappings from the same
// payload so subsequent mutations on this directory resolve from cache
// instead of re-listing. Returns nil when the listing cannot be fetched;
// callers then fall back to per-name probes.
func (h *AlistHandler) fetchDirObjectSet(r *http.Request, dirPath string, passwdInfo *config.PasswdInfo) *dirObjectSet {
	items, err := h.fetchFsListContent(r, dirPath)
	if err != nil {
		return nil
	}
	set := &dirObjectSet{names: make(map[string]bool, len(items))}
	for _, item := range items {
		m, _ := item.(map[string]interface{})
		name, _ := m["name"].(string)
		isDir, _ := m["is_dir"].(bool)
		if name != "" {
			set.names[name] = isDir
		}
	}
	h.warmDirNameCache(dirPath, items, passwdInfo)
	return set
}

// warmDirNameCache writes the display<->upstream path mappings for a freshly
// listed directory into the in-memory path cache, mirroring what the fs/list
// pipeline persists. This is what lets a batch mutation warm the cache once
// and have every later remove/move/rename hit cache instead of upstream.
func (h *AlistHandler) warmDirNameCache(dirPath string, items []interface{}, passwdInfo *config.PasswdInfo) {
	if h == nil || h.fileDAO == nil || passwdInfo == nil || !passwdInfo.EncName {
		return
	}
	if len(items) >= dirServerHugeListEntries {
		return
	}
	for _, item := range items {
		fileData, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		rawName, _ := fileData["name"].(string)
		if rawName == "" {
			continue
		}
		isDir, _ := fileData["is_dir"].(bool)
		size := int64(0)
		if s, ok := fileData["size"].(float64); ok {
			size = int64(s)
		}
		showName := h.convertEntryShowName(passwdInfo, rawName, isDir)
		displayPath := path.Join(dirPath, showName)
		encPath := path.Join(dirPath, rawName)
		h.fileDAO.SetEncPathMapping(displayPath, encPath)
		h.fileDAO.SetEncPathMappingWithInfo(displayPath, encPath, showName, size, isDir)
	}
}

func (h *AlistHandler) resolveUpstreamNames(r *http.Request, dirPath string, names []string, passwdInfo *config.PasswdInfo) []string {
	if len(names) == 0 {
		return nil
	}
	if len(names) == 1 {
		return []string{h.resolveUpstreamNameForRequest(r, dirPath, names[0], passwdInfo)}
	}

	// Batch path: names that miss every cache and reach the existence probe
	// share one upstream directory listing instead of one fs/get each. The
	// listing is fetched lazily on the first probe so fully-cached batches
	// cost nothing extra.
	var listing *dirObjectSet
	listingFetched := false
	probe := func(displayPath string) bool {
		if !listingFetched {
			listingFetched = true
			listing = h.fetchDirObjectSet(r, dirPath, passwdInfo)
		}
		if listing == nil {
			exists, _ := h.probeDisplayObject(r, displayPath)
			return exists
		}
		_, exists := listing.names[path.Base(displayPath)]
		return exists
	}

	resolved := make([]string, 0, len(names))
	for _, name := range names {
		displayPath := path.Join(dirPath, name)
		resolved = append(resolved, h.resolveUpstreamNameWithProbe(r, dirPath, name, displayPath, passwdInfo, func() bool {
			return probe(displayPath)
		}))
	}
	return resolved
}

// resolveRenameSource maps a full display path to its upstream path and
// reports whether the object is a directory. Directory display names are
// never filename-encrypted, so cached or probed directories keep their
// spelling instead of being run through ToRealName.
func (h *AlistHandler) resolveRenameSource(r *http.Request, displayPath string, passwdInfo *config.PasswdInfo) (string, bool) {
	return newNameResolver(h.fileDAO, passwdInfo).sourcePath(displayPath, func() (bool, bool) {
		return h.probeDisplayObject(r, displayPath)
	})
}
