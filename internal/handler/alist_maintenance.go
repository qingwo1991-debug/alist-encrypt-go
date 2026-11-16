package handler

import (
	"context"
	"net/http"
	"path"

	"github.com/rs/zerolog/log"

	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/httputil"
)

// fsListMetaUpsert / fsListProbeJob are the deferred per-entry maintenance
// records collected during a live fs/list pass.
type fsListMetaUpsert struct {
	path string
	size int64
}

type fsListProbeJob struct {
	path string
	size int64
}

// deferListMaintenance moves listing cache-warming off the request path. The
// response body is already fully computed when this runs, so persistence,
// meta upserts and probe admission can no longer inflate fs/list latency.
// Work is bounded by listMaintenanceSem; on shutdown in-flight passes abort.
func (h *AlistHandler) deferListMaintenance(prepared []*dao.FileInfo, metaUpserts []fsListMetaUpsert, probes []fsListProbeJob, authHeaders http.Header, probeSource string) {
	if len(prepared)+len(metaUpserts)+len(probes) == 0 {
		return
	}
	work := func() {
		if len(prepared) > 0 {
			if err := h.fileDAO.PersistFromList(prepared); err != nil {
				log.Warn().Err(err).Int("items", len(prepared)).Msg("failed to batch-persist directory listing")
			}
		}
		for _, m := range metaUpserts {
			h.upsertMetaFromListing(context.Background(), m.path, m.size)
		}
		for _, p := range probes {
			h.enqueueProbeFromListWithHeaders(p.path, p.size, authHeaders, probeSource)
		}
	}
	if h.listMaintenanceSem == nil {
		work()
		return
	}
	go func() {
		select {
		case h.listMaintenanceSem <- struct{}{}:
			defer func() { <-h.listMaintenanceSem }()
		case <-h.dirSyncCtx.Done():
			return
		}
		work()
	}()
}

func (h *AlistHandler) upsertMetaFromListing(ctx context.Context, displayPath string, size int64) {
	if h.metaStore == nil || size <= 0 {
		return
	}
	providerKey := ProviderKey(h.cfg.GetAlistURL(), displayPath)
	_ = h.metaStore.Upsert(ctx, FileMeta{
		ProviderKey:  providerKey,
		OriginalPath: displayPath,
		Size:         size,
		StatusCode:   0,
	})
}

func (h *AlistHandler) enqueueProbeFromList(r *http.Request, displayPath string, reportedSize int64) {
	authHeaders := make(http.Header)
	var source string
	if r != nil {
		if auth := r.Header.Get("Authorization"); auth != "" {
			authHeaders.Set("Authorization", auth)
		}
		if cookie := r.Header.Get("Cookie"); cookie != "" {
			authHeaders.Set("Cookie", cookie)
		}
		source = probeSourceFromContext(r.Context(), probeSourceFSList)
	} else {
		source = probeSourceFSList
	}
	h.enqueueProbeFromListWithHeaders(displayPath, reportedSize, authHeaders, source)
}

// enqueueProbeFromListWithHeaders is the request-free variant used by the
// deferred post-response listing maintenance pass.
func (h *AlistHandler) enqueueProbeFromListWithHeaders(displayPath string, reportedSize int64, authHeaders http.Header, source string) {
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
	h.probe.EnqueueWithSource(file, authHeaders, reportedSize, source)
}
