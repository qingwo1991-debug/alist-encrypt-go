package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type overviewStatusStore struct {
	DirSyncStore
	status DirSyncStatus
}

func (s *overviewStatusStore) GetStatus(context.Context, string) (*DirSyncStatus, bool, error) {
	return &s.status, true, nil
}

func (s *overviewStatusStore) CountSnapshots(context.Context) (int64, int64, int64, int64, error) {
	return 3, 1, 1, 1, nil
}

func TestDirSyncOverviewSanitizesErrorPreservesSchema(t *testing.T) {
	for _, raw := range []string{"", "synthetic internal diagnostic"} {
		store := &overviewStatusStore{status: DirSyncStatus{Status: "done", LastError: raw, DirsScanned: 2, TotalDirsEstimate: 4}}
		h := &AlistHandler{dirSyncStore: store}
		rr := httptest.NewRecorder()
		h.HandleDirSyncOverview(rr, httptest.NewRequest(http.MethodGet, "/api/encrypt/dir-sync/overview", nil))
		var body struct {
			Code int `json:"code"`
			Data struct {
				CurrentJob    map[string]interface{} `json:"current_job"`
				SnapshotStats map[string]interface{} `json:"snapshot_stats"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		job := body.Data.CurrentJob
		if rr.Code != http.StatusOK || body.Code != 0 || len(job) != 17 || job["status"] != "done" || job["progress_percent"] != float64(50) {
			t.Fatalf("unexpected overview: %s", rr.Body.String())
		}
		if job["last_error"] != publicDirSyncError(raw) || body.Data.SnapshotStats["total_snapshots"] != float64(3) {
			t.Fatalf("unexpected overview data: %s", rr.Body.String())
		}
		if store.status.LastError != raw {
			t.Fatal("response mutated stored diagnostics")
		}
		if raw != "" && strings.Contains(rr.Body.String(), raw) {
			t.Fatal("raw diagnostic in response")
		}
	}
}

func TestDirSyncSnapshotSanitizesDegradedReason(t *testing.T) {
	h := &AlistHandler{}
	snap := &DirListSnapshot{LastError: "synthetic internal diagnostic"}
	payload := h.markSnapshotServingMode([]byte(`{"code":200,"data":{"content":[]}}`), true, false, "request_fill", snap)
	var body map[string]interface{}
	if err := json.Unmarshal(payload, &body); err != nil {
		t.Fatal(err)
	}
	if body["degraded_reason"] != publicDirSyncError(snap.LastError) || body["stale"] != true || body["cache_hit"] != true {
		t.Fatalf("unexpected snapshot: %s", payload)
	}
}

func TestDirSyncDiagnosticsUseStructuredContext(t *testing.T) {
	var output bytes.Buffer
	previous := log.Logger
	log.Logger = zerolog.New(&output)
	t.Cleanup(func() { log.Logger = previous })
	logDirSyncFailure("scan", "/library", 503, 500, errors.New("synthetic internal diagnostic"))
	var event map[string]interface{}
	if err := json.Unmarshal(output.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	if event["stage"] != "scan" || event["path"] != "/library" || event["http_status"] != float64(503) || event["upstream_code"] != float64(500) || event["error_type"] == "" {
		t.Fatalf("missing diagnostic context: %s", output.String())
	}
	if strings.Contains(output.String(), "synthetic internal diagnostic") {
		t.Fatal("arbitrary error text was logged")
	}
}

func TestDirSyncPageUsesExistingLoginAndHandlesFailure(t *testing.T) {
	rr := httptest.NewRecorder()
	(&AlistHandler{}).HandleDirSyncPage(rr, httptest.NewRequest(http.MethodGet, dirSyncPageRoute, nil))
	for _, text := range []string{"localStorage.getItem('basic')", "headers:{Authorization:'Bearer '+token}", "res.status===401", "if(root.code!==0)", "/public/index.html#/login", "role=\"status\""} {
		if !strings.Contains(rr.Body.String(), text) {
			t.Errorf("missing page auth/error contract %q", text)
		}
	}
}
