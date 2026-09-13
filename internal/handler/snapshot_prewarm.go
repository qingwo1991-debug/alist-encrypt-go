package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"path"
	"strings"

	"github.com/alist-encrypt-go/internal/httputil"
)

// enqueueProbeFromSnapshot warms content metadata for every encrypted video in
// a directory snapshot that is being served straight from cache. The live
// refresh path already enqueues probes per item; the snapshot fast-path did
// not, so the very first click on a file under a snapshot-served directory
// always paid for a cold ContentMeta probe (~300-900ms). Async goroutine so
// the snapshot response is not blocked; the probe scheduler applies its own
// per-provider concurrency and video/size filters.
func (h *AlistHandler) enqueueProbeFromSnapshot(r *http.Request, dirPath string, payload []byte) {
	if h == nil || h.probe == nil || len(payload) == 0 || strings.TrimSpace(dirPath) == "" {
		return
	}
	allowDecrypt := h.passwdDAO.MatchDir(dirPath)
	if !allowDecrypt {
		return
	}
	var body struct {
		Data struct {
			Content []map[string]interface{} `json:"content"`
		} `json:"data"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		return
	}
	type probeTask struct {
		displayPath string
		size        int64
	}
	var tasks []probeTask
	for _, item := range body.Data.Content {
		if item == nil {
			continue
		}
		isDir, _ := item["is_dir"].(bool)
		if isDir {
			continue
		}
		name, _ := item["name"].(string)
		if name == "" {
			continue
		}
		size := int64(0)
		if s, ok := item["size"].(float64); ok {
			size = int64(s)
		}
		tasks = append(tasks, probeTask{
			displayPath: path.Join(dirPath, name),
			size:        size,
		})
	}
	if len(tasks) == 0 {
		return
	}
	// Run asynchronously so the snapshot response latency is untouched. The
	// scheduler's own cooldown/queueing guarantees we don't duplicate or flood.
	authHeaders := make(http.Header)
	if r != nil {
		if auth := r.Header.Get("Authorization"); auth != "" {
			authHeaders.Set("Authorization", auth)
		}
		if cookie := r.Header.Get("Cookie"); cookie != "" {
			authHeaders.Set("Cookie", cookie)
		}
	}
	h.startDirSyncWork(func(ctx context.Context) {
		for _, t := range tasks {
			if t.size > 0 {
				h.upsertMetaFromListing(ctx, t.displayPath, t.size)
			}
			h.enqueueProbeWithHeaders(t.displayPath, t.size, authHeaders)
		}
	})
}

// enqueueProbeWithHeaders mirrors enqueueProbeFromList but accepts explicitly
// provided auth headers (used by the snapshot fast-path where the request is
// served after the snapshot response has been flushed).
func (h *AlistHandler) enqueueProbeWithHeaders(displayPath string, reportedSize int64, authHeaders http.Header) {
	if h.probe == nil {
		return
	}
	passwdInfo, found := h.passwdDAO.PathFindPasswd(displayPath)
	if !found || passwdInfo == nil {
		return
	}
	realPath := displayPath
	if passwdInfo.EncName {
		realPath = h.proxyHandler.convertDisplayToRealPath(displayPath, passwdInfo)
	}
	targetURL := httputil.BuildTargetURLStripped(h.cfg.GetAlistURL(), "/d"+realPath)
	file := FileItem{
		DisplayPath:      displayPath,
		EncryptedPath:    realPath,
		TargetURL:        targetURL,
		FileName:         path.Base(displayPath),
		CompatStorageKey: buildRangeCompatStorageKey(passwdInfo, displayPath),
		PasswdInfo:       passwdInfo,
	}
	h.probe.EnqueueWithSource(file, authHeaders, reportedSize, probeSourceFSList)
}
