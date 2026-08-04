package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/storage"
)

// TestExportFileMetaWithoutMySQL verifies that the DB_EXPORT metadata endpoint
// still serves FileInfo records from BoltDB when MySQL is not enabled, so a
// mobile client can sync preheat metadata from a default deployment.
func TestExportFileMetaWithoutMySQL(t *testing.T) {
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	defer store.Close()

	fileDAO := dao.NewFileDAO(store)
	defer fileDAO.Stop()

	// Seed the file info cache with two records.
	seed := []*dao.FileInfo{
		{
			Path:              "/google/movieA.mp4",
			EncryptedPath:     "/google/encA.bin",
			Name:              "movieA.mp4",
			Size:              123456,
			CiphertextSize:    123488,
			ContentVersion:    2,
			HeaderLen:         32,
			NonceField:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			RawURL:            "https://drive.google.com/f/d/A",
			UpstreamFetchedAt: mustTime("2026-08-04T10:00:00Z", t),
		},
		{
			Path:              "/local/movieB.mp4",
			EncryptedPath:     "/local/encB.bin",
			Name:              "movieB.mp4",
			Size:              999,
			ContentVersion:    1,
			RawURL:            "http://192.168.1.5:5244/d/local/encB.bin",
			UpstreamFetchedAt: mustTime("2026-08-04T11:00:00Z", t),
		},
	}
	for _, info := range seed {
		if err := fileDAO.Set(info); err != nil {
			t.Fatalf("seed file meta: %v", err)
		}
	}

	h := NewAPIHandler(config.DefaultConfig(), nil, nil, fileDAO, nil)
	req := httptest.NewRequest(http.MethodGet, "/enc-api/exportFileMeta?limit=10", nil)
	rr := httptest.NewRecorder()
	h.ExportFileMeta(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want %d body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var resp struct {
		Code int `json:"code"`
		Data struct {
			Items []struct {
				KeyHash           string `json:"KeyHash"`
				ProviderHost      string `json:"ProviderHost"`
				OriginalPath      string `json:"OriginalPath"`
				EncryptedPath     string `json:"EncryptedPath"`
				Size              int64  `json:"Size"`
				ContentVersion    int    `json:"ContentVersion"`
				HeaderLen         int64  `json:"HeaderLen"`
				RawURL            string `json:"RawURL"`
				UpstreamFetchedAt string `json:"UpstreamFetchedAt"`
			} `json:"items"`
			HasMore bool   `json:"has_more"`
			Backend string `json:"backend"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Code != 0 {
		t.Fatalf("code=%d, want 0", resp.Code)
	}
	if resp.Data.Backend != "boltdb" {
		t.Fatalf("backend=%q, want boltdb", resp.Data.Backend)
	}
	if len(resp.Data.Items) != 2 {
		t.Fatalf("items=%d, want 2 (body=%s)", len(resp.Data.Items), rr.Body.String())
	}

	// Verify provider host is derived from raw_url.
	var found bool
	for _, item := range resp.Data.Items {
		if item.OriginalPath == "/google/movieA.mp4" {
			found = true
			if item.ProviderHost == "" {
				t.Fatalf("provider host missing for google record")
			}
			if item.KeyHash == "" {
				t.Fatalf("KeyHash missing for google record")
			}
			if item.ContentVersion != 2 || item.HeaderLen != 32 {
				t.Fatalf("google record v2 meta wrong: version=%d headerLen=%d", item.ContentVersion, item.HeaderLen)
			}
		}
	}
	if !found {
		t.Fatalf("google record not exported")
	}
}

// TestExportStrategyAndRangeWithoutMySQL verifies these endpoints return an
// empty success payload instead of 500 when MySQL is disabled.
func TestExportStrategyAndRangeWithoutMySQL(t *testing.T) {
	h := NewAPIHandler(config.DefaultConfig(), nil, nil, nil, nil)

	for _, path := range []string{"/enc-api/exportStrategy", "/enc-api/exportRangeCompat"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rr := httptest.NewRecorder()
		if path == "/enc-api/exportStrategy" {
			h.ExportStrategy(rr, req)
		} else {
			h.ExportRangeCompat(rr, req)
		}
		if rr.Code != http.StatusOK {
			t.Fatalf("%s status=%d, want 200", path, rr.Code)
		}
		var resp struct {
			Code int `json:"code"`
			Data struct {
				Items []interface{} `json:"items"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("%s unmarshal: %v", path, err)
		}
		if resp.Code != 0 {
			t.Fatalf("%s code=%d, want 0", path, resp.Code)
		}
		if len(resp.Data.Items) != 0 {
			t.Fatalf("%s items=%d, want empty", path, len(resp.Data.Items))
		}
	}
}

func mustTime(value string, t *testing.T) time.Time {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("parse time %q: %v", value, err)
	}
	return parsed
}
