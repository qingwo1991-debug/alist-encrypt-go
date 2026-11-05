package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alist-encrypt-go/internal/wopan"
)

func quotaUnifiedRequest(f *wopanFixture, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "http://manager.test"+path, nil)
	if token != "" {
		req.Header.Set("Authorizetoken", token)
	}
	rr := httptest.NewRecorder()
	NewQuotaHandler(f.h).Quota(rr, req)
	return rr
}

func quotaUnifiedStorages(t *testing.T, rr *httptest.ResponseRecorder) map[int]quotaStorageView {
	t.Helper()
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var views []quotaStorageView
	if err := json.Unmarshal(wopanResponseData(t, rr)["storages"], &views); err != nil {
		t.Fatal(err)
	}
	indexed := make(map[int]quotaStorageView, len(views))
	for _, view := range views {
		indexed[view.StorageID] = view
	}
	return indexed
}

// A storage without a quota client must be reported unsupported and must not
// expose byte fields at all: an absent field is unambiguous, a zero is not.
func TestQuotaUnifiedCoversEveryStorageAndNeverFabricates(t *testing.T) {
	f := newWopanFixture(t)
	f.upstream.change(func() {
		f.upstream.storages[28] = wopanStorage{ID: 28, MountPath: "/any-mobile-mount", Driver: "139Yun", Status: "work"}
	})
	rr := quotaUnifiedRequest(f, "/enc-api/quota", f.jwt)
	views := quotaUnifiedStorages(t, rr)
	if len(views) != 2 {
		t.Fatalf("storages=%d", len(views))
	}
	personal := views[27]
	if !personal.Supported || personal.Driver != "WoPan" || personal.Scope != "personal" {
		t.Fatalf("personal view=%+v", personal)
	}
	if personal.TotalBytes != "9007199254740993" || personal.UsedBytes != "123" || personal.AvailableBytes != "9007199254740870" {
		t.Fatalf("bytes=%s/%s/%s", personal.TotalBytes, personal.UsedBytes, personal.AvailableBytes)
	}
	other := views[28]
	if other.Supported || other.Driver != "139Yun" || other.UnsupportedReason != "unsupported_driver" {
		t.Fatalf("other view=%+v", other)
	}
	var raw []map[string]json.RawMessage
	if err := json.Unmarshal(wopanResponseData(t, rr)["storages"], &raw); err != nil {
		t.Fatal(err)
	}
	for _, entry := range raw {
		if string(entry["storage_id"]) != "28" {
			continue
		}
		for _, key := range []string{"total_bytes", "used_bytes", "available_bytes", "scope"} {
			if _, ok := entry[key]; ok {
				t.Fatalf("unsupported storage exposed %s", key)
			}
		}
	}
	wopanAssertPrivate(t, rr, f.jwt, f.cfg.GetAlistURL(), "access_token", "refresh_token")
}

func TestQuotaUnifiedAuthAndSelector(t *testing.T) {
	f := newWopanFixture(t)
	f.upstream.change(func() {
		f.upstream.storages[28] = wopanStorage{ID: 28, MountPath: "/any-mobile-mount", Driver: "139Yun", Status: "work"}
	})
	if rr := quotaUnifiedRequest(f, "/enc-api/quota", ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d", rr.Code)
	}
	selected := quotaUnifiedStorages(t, quotaUnifiedRequest(f, "/enc-api/quota?storage_id=27", f.jwt))
	if len(selected) != 1 || selected[27].Driver != "WoPan" || !selected[27].Supported {
		t.Fatalf("selector views=%+v", selected)
	}
	for _, path := range []string{
		"/enc-api/quota?storage_id=0",
		"/enc-api/quota?storage_id=-1",
		"/enc-api/quota?storage_id=x",
		"/enc-api/quota?storage_id=1.5",
		"/enc-api/quota?storage_id=27&storage_id=27",
	} {
		if rr := quotaUnifiedRequest(f, path, f.jwt); rr.Code != http.StatusBadRequest {
			t.Fatalf("%s status=%d", path, rr.Code)
		}
	}
	if rr := quotaUnifiedRequest(f, "/enc-api/quota?storage_id=999", f.jwt); rr.Code != http.StatusNotFound {
		t.Fatalf("unknown storage status=%d", rr.Code)
	}
}

// A provider failure or an impossible byte triple must fail the request, never
// degrade into a cached or zeroed quota.
func TestQuotaUnifiedProviderFailureIsNotZero(t *testing.T) {
	f := newWopanFixture(t)
	f.provider.quotaErr = errors.New("upstream secret " + wopanTestAccess)
	rr := quotaUnifiedRequest(f, "/enc-api/quota", f.jwt)
	if rr.Code != http.StatusBadGateway || strings.Contains(rr.Body.String(), "total_bytes") {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	wopanAssertPrivate(t, rr, "secret")
	f.provider.quotaErr = nil
	for _, quota := range []wopan.Quota{
		{},
		{TotalBytes: -1},
		{TotalBytes: 100, UsedBytes: 101, AvailableBytes: -1},
		{TotalBytes: 100, UsedBytes: -1, AvailableBytes: 101},
		{TotalBytes: 100, UsedBytes: 10, AvailableBytes: 0},
	} {
		f.provider.quota = quota
		if rr := quotaUnifiedRequest(f, "/enc-api/quota", f.jwt); rr.Code != http.StatusBadGateway {
			t.Fatalf("invalid quota accepted: %+v", quota)
		}
	}
	f.provider.quota = wopan.Quota{TotalBytes: 100, UsedBytes: 0, AvailableBytes: 100}
	empty := quotaUnifiedStorages(t, quotaUnifiedRequest(f, "/enc-api/quota", f.jwt))[27]
	if !empty.Supported || empty.TotalBytes != "100" || empty.UsedBytes != "0" || empty.AvailableBytes != "100" {
		t.Fatalf("valid empty quota rejected: %+v", empty)
	}
}
