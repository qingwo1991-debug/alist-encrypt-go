package handler

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/alist-encrypt-go/internal/quota"
)

// QuotaHandler exposes read-only storage quota through one endpoint so a caller
// does not need to know which provider backs a mount. Providers are registered
// once in a registry keyed by driver name, so adding a provider never touches
// the request path: it never learns which drivers exist and every provider stays
// unaware of the others.
//
// Only drivers with an implemented quota client report numbers. Every other
// driver is reported as supported=false with an explicit reason: "unknown" must
// never be rendered as a zero, because a zero total is indistinguishable from a
// genuinely empty account.
type QuotaHandler struct {
	admin    *WopanAdminHandler
	registry *quota.Registry
}

func NewQuotaHandler(admin *WopanAdminHandler) *QuotaHandler {
	h := &QuotaHandler{admin: admin}
	if admin != nil {
		h.registry = quota.NewRegistry(
			newWopanQuotaProvider(admin),
			quota.NewYun139Provider(quota.DefaultYun139Endpoint),
		)
	}
	return h
}

// quotaStorageView is one storage's quota state. Byte counts are decimal
// strings because a personal quota can exceed 2^53, which a JSON number cannot
// carry without silently rounding.
type quotaStorageView struct {
	StorageID         int    `json:"storage_id"`
	MountPath         string `json:"mount_path"`
	Driver            string `json:"driver"`
	Supported         bool   `json:"supported"`
	Scope             string `json:"scope,omitempty"`
	TotalBytes        string `json:"total_bytes,omitempty"`
	UsedBytes         string `json:"used_bytes,omitempty"`
	AvailableBytes    string `json:"available_bytes,omitempty"`
	UnsupportedReason string `json:"unsupported_reason,omitempty"`
}

// Quota reports every configured storage's quota state. An optional
// ?storage_id=N narrows the answer to a single mount; a malformed or repeated
// id is a client error rather than a silently empty list. No quota value is
// cached: an error can never turn into a stale or fabricated byte count.
func (h *QuotaHandler) Quota(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.admin == nil {
		RespondHTTPErrorWithStatus(w, "Internal error", http.StatusInternalServerError)
		return
	}
	wopanPrivate(w)
	local, err := h.admin.localAdmin(r)
	if err != nil {
		h.admin.fail(w, err)
		return
	}
	filter, err := quotaStorageFilter(r)
	if err != nil {
		h.admin.fail(w, err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), wopanOperationTimeout)
	defer cancel()
	s, err := h.admin.snapshot()
	if err == nil {
		err = h.admin.upstreamAdmin(ctx, &s, local)
	}
	if err != nil {
		h.admin.fail(w, err)
		return
	}

	views := make([]quotaStorageView, 0)
	seen := make(map[int]bool)
	matched := false
	for page, count := 1, 0; ; page++ {
		var batch struct {
			Content []wopanStorage `json:"content"`
			Total   *int           `json:"total"`
		}
		if err = h.admin.upstreamJSON(ctx, s, http.MethodGet, "/api/admin/storage/list?page="+strconv.Itoa(page)+"&per_page=100", nil, &batch); err != nil {
			h.admin.fail(w, err)
			return
		}
		// Same bounds as Storages: a truncated or duplicated listing must not
		// be reported as a complete quota answer.
		if batch.Total == nil || *batch.Total < 0 || *batch.Total > 1000 || len(batch.Content) > 100 || count+len(batch.Content) > 1000 || (len(batch.Content) == 0 && count < *batch.Total) {
			h.admin.fail(w, wopanError(http.StatusBadGateway, "storage_list_limit"))
			return
		}
		for _, entry := range batch.Content {
			if entry.ID <= 0 || seen[entry.ID] {
				h.admin.fail(w, wopanError(http.StatusBadGateway, "upstream_invalid_response"))
				return
			}
			seen[entry.ID] = true
			if filter > 0 && entry.ID != filter {
				continue
			}
			matched = true
			view, viewErr := h.storageQuota(ctx, s, entry)
			if viewErr != nil {
				h.admin.fail(w, viewErr)
				return
			}
			views = append(views, view)
		}
		count += len(batch.Content)
		if count >= *batch.Total {
			break
		}
		if page >= 10 {
			h.admin.fail(w, wopanError(http.StatusBadGateway, "storage_list_limit"))
			return
		}
	}
	if filter > 0 && !matched {
		h.admin.fail(w, wopanError(http.StatusNotFound, "storage_not_found"))
		return
	}
	if !h.admin.unchanged(s) {
		h.admin.fail(w, wopanError(http.StatusConflict, "configuration_changed"))
		return
	}
	RespondSuccess(w, map[string]interface{}{
		"checked_at": h.admin.now().UTC().Format(time.RFC3339),
		"storages":   views,
	})
}

// quotaStorageFilter parses the optional single storage_id selector. Zero means
// "every storage"; duplicates are rejected so a caller cannot believe it asked
// for two mounts and silently receive one.
func quotaStorageFilter(r *http.Request) (int, error) {
	values := r.URL.Query()["storage_id"]
	if len(values) == 0 {
		return 0, nil
	}
	if len(values) > 1 {
		return 0, wopanError(http.StatusBadRequest, "invalid_storage_id")
	}
	id, err := strconv.Atoi(values[0])
	if err != nil || id <= 0 {
		return 0, wopanError(http.StatusBadRequest, "invalid_storage_id")
	}
	return id, nil
}

// storageQuota resolves one storage through the registry. A driver without a
// registered provider is marked unsupported instead of being probed with a
// guess. The addition loader is handed to the provider rather than resolved
// here, so a driver nobody owns never costs an upstream round trip.
func (h *QuotaHandler) storageQuota(ctx context.Context, s wopanUpstreamSession, entry wopanStorage) (quotaStorageView, error) {
	view := quotaStorageView{StorageID: entry.ID, MountPath: entry.MountPath, Driver: entry.Driver}
	provider, ok := h.registry.Provider(entry.Driver)
	if !ok {
		view.UnsupportedReason = "unsupported_driver"
		return view, nil
	}
	result, err := provider.Quota(ctx, quota.Storage{
		ID:        entry.ID,
		MountPath: entry.MountPath,
		Driver:    entry.Driver,
		Disabled:  entry.Disabled,
		Status:    entry.Status,
		Addition: func(ctx context.Context) (string, error) {
			// List responses hide additions on purpose, so the raw record is
			// required before any provider can read its own credential.
			value, err := h.admin.storageRecord(ctx, s, entry.ID)
			if err != nil {
				return "", err
			}
			return value.Addition, nil
		},
	})
	if err != nil {
		return view, quotaFailure(err)
	}
	if err := result.Validate(); err != nil {
		return view, quotaFailure(err)
	}
	view.Supported = true
	view.Scope = result.Scope
	view.TotalBytes = strconv.FormatInt(result.Total, 10)
	view.UsedBytes = strconv.FormatInt(result.Used, 10)
	// An over-quota account has no available bytes to report. Omitting the field
	// is honest; a negative or clamped count would not be.
	if !result.OverQuota {
		view.AvailableBytes = strconv.FormatInt(result.Total-result.Used, 10)
	}
	return view, nil
}

// quotaFailure maps a provider error onto the endpoint's error contract. Errors
// that are not quota errors already carry their own upstream status.
func quotaFailure(err error) error {
	var failure *quota.Error
	if errors.As(err, &failure) {
		return wopanError(failure.Status, failure.Code)
	}
	return err
}
