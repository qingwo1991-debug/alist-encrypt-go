package handler

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/storage"
	"github.com/alist-encrypt-go/internal/storage/mysqlstore"
)

type exportTestPage struct {
	Items      []mysqlstore.FileMetaRecord `json:"items"`
	HasMore    bool                        `json:"has_more"`
	NextCursor string                      `json:"next_cursor"`
	NextSince  int64                       `json:"next_since"`
	Status     string                      `json:"status"`
	Supported  bool                        `json:"supported"`
}

func exportTestRequest(t *testing.T, h *APIHandler, q url.Values) exportTestPage {
	t.Helper()
	rr := httptest.NewRecorder()
	h.ExportFileMeta(rr, httptest.NewRequest(http.MethodGet, "/enc-api/exportFileMeta?"+q.Encode(), nil))
	var envelope struct {
		Code int            `json:"code"`
		Data exportTestPage `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if rr.Code != 200 || envelope.Code != 0 {
		t.Fatalf("export: %d %s", rr.Code, rr.Body.String())
	}
	return envelope.Data
}

func TestFileExportBoltPagingContract(t *testing.T) {
	for _, version := range []string{"1", "2"} {
		t.Run(version, func(t *testing.T) {
			store, err := storage.NewStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			d := dao.NewFileDAO(store)
			defer d.Stop()
			h := &APIHandler{fileDAO: d}
			for i := 0; i < 9; i++ {
				// Same second, deliberately different fractions: legacy must order by key,
				// not by fractions that next_since cannot transport.
				info := &dao.FileInfo{Path: fmt.Sprintf("/A%%_=/movie%d", i), RawURL: "https://Host:443/a?token=secret", Sign: "secret", RawURLAuthScope: "credential", Modified: time.Unix(1700000000, int64(9-i)*1000000), ContentVersion: 3, HeaderLen: 48, ChunkSize: 1024, NonceField: []byte{1, 2}, CiphertextSize: 4096, Size: 2048}
				if err := store.SetJSON(storage.BucketFileInfo, info.Path, info); err != nil {
					t.Fatal(err)
				}
			}
			q := url.Values{"version": {version}, "limit": {"2"}, "provider": {"Host:443"}, "path_prefix": {"/A%_=/"}}
			seen := map[string]bool{}
			pages := 0
			for {
				p := exportTestRequest(t, h, q)
				pages++
				for _, item := range p.Items {
					if seen[item.KeyHash] {
						t.Fatal("duplicate", item.KeyHash)
					}
					seen[item.KeyHash] = true
					if item.RawURL != "" || item.Sign != "" || item.RawURLAuthScope != "" {
						t.Fatal("sensitive fields exported")
					}
					if item.ContentVersion != 3 || item.HeaderLen != 48 || item.ChunkSize != 1024 || item.Size != 2048 || len(item.NonceField) != 2 {
						t.Fatal("geometry lost")
					}
					if version == "1" && item.UpdatedAt.Nanosecond() != 0 {
						t.Fatal("legacy precision not normalized")
					}
				}
				if !p.HasMore {
					break
				}
				if len(p.Items) != 2 {
					t.Fatal("incorrect lookahead trimming")
				}
				// Deleting the last anchor must not prevent cursor continuation.
				if err := d.Delete(p.Items[len(p.Items)-1].OriginalPath); err != nil {
					t.Fatal(err)
				}
				if version == "1" {
					q.Set("since", fmt.Sprint(p.NextSince))
				}
				q.Set("cursor", p.NextCursor)
				if pages > 8 {
					t.Fatal("paging failed to terminate")
				}
			}
			if len(seen) != 9 || pages != 5 {
				t.Fatalf("seen=%d pages=%d", len(seen), pages)
			}
			// Literal filtering remains case sensitive; unknown URL host stays empty.
			q = url.Values{"provider": {"host:443"}}
			if p := exportTestRequest(t, h, q); len(p.Items) != 0 {
				t.Fatal("provider case mismatch")
			}
			q = url.Values{"path_prefix": {"/Axxx/"}}
			if p := exportTestRequest(t, h, q); len(p.Items) != 0 {
				t.Fatal("SQL wildcards treated as wildcards")
			}
		})
	}
}

func TestFileExportExactLimitOffsetAndIdentity(t *testing.T) {
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	d := dao.NewFileDAO(store)
	defer d.Stop()
	h := &APIHandler{fileDAO: d}
	for _, p := range []string{"/a", "/b"} {
		if err := store.SetJSON(storage.BucketFileInfo, p, &dao.FileInfo{Path: p}); err != nil {
			t.Fatal(err)
		}
	}
	p := exportTestRequest(t, h, url.Values{"limit": {"2"}})
	if p.HasMore || len(p.Items) != 2 {
		t.Fatal("exact limit incorrectly has more")
	}
	for _, item := range p.Items {
		if item.ProviderHost != "" || item.KeyHash != mysqlstore.KeyHash("", item.OriginalPath) {
			t.Fatal("invented provider identity")
		}
	}
	p = exportTestRequest(t, h, url.Values{"limit": {"1"}, "offset": {"1"}})
	if p.HasMore || len(p.Items) != 1 {
		t.Fatal("offset not applied after ordering")
	}
	if p = exportTestRequest(t, h, url.Values{"path": {"/a"}}); len(p.Items) != 1 || p.Items[0].OriginalPath != "/a" {
		t.Fatal("path filter")
	}
}

func TestFileExportStrictValidationAndScope(t *testing.T) {
	h := &APIHandler{}
	q := url.Values{"version": {"2"}, "path_prefix": {"/a"}}
	req, err := parseFileExport(httptest.NewRequest("GET", "/?"+q.Encode(), nil), "boltdb")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(fileExportCursor{Version: 2, Timestamp: "2026-01-01T00:00:00Z", Key: mysqlstore.KeyHash("", "/a"), Backend: "boltdb", Scope: req.scope})
	// Use the same encoder as the response.
	cursor := base64.RawURLEncoding.EncodeToString(raw)
	q.Set("cursor", cursor)
	if _, err := parseFileExport(httptest.NewRequest("GET", "/?"+q.Encode(), nil), "boltdb"); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{"version=2&cursor=bad", "version=2&cursor=%ZZ", "version=2&path_prefix=/a&cursor=" + cursor + "&offset=0", "cursor=0123456789abcdef0123456789abcdef", "since=oops", "limit=0", "offset=-1", "version=3", "limit=1&limit=2", "consistency=snapshot", "mode=strict_incremental", "include_sensitive=true", "since=1&updated_after=2026-01-01T00:00:00Z", "version=2&path_prefix=/b&cursor=" + cursor, "version=2&path_prefix=/a&cursor=" + cursor + "&offset=1"} {
		rr := httptest.NewRecorder()
		h.ExportFileMeta(rr, httptest.NewRequest("GET", "/?"+query, nil))
		if rr.Code != 400 {
			t.Fatalf("%s: %d %s", query, rr.Code, rr.Body.String())
		}
	}
	if _, err := parseFileExport(httptest.NewRequest("GET", "/?"+q.Encode(), nil), "mysql"); err == nil {
		t.Fatal("backend scope accepted")
	}
}

func TestFileExportBoltErrorsNotEmptySuccess(t *testing.T) {
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	d := dao.NewFileDAO(store)
	defer d.Stop()
	h := &APIHandler{fileDAO: d}
	if err := store.Set(storage.BucketFileInfo, "broken", []byte("not JSON")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		rr := httptest.NewRecorder()
		h.ExportFileMeta(rr, httptest.NewRequest("GET", "/", nil))
		if rr.Code != 500 {
			t.Fatalf("got empty success: %s", rr.Body.String())
		}
		if i == 0 {
			store.Close()
		}
	}
}
