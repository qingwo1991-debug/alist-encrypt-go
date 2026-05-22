package encrypt

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLocalStoreSyncStatusAndCycle(t *testing.T) {
	store, err := newLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("newLocalStore failed: %v", err)
	}
	defer store.Close()

	status := LocalSyncStatusRecord{
		Name:              dbExportSyncStatusName,
		LastSuccessAt:     time.Now().Unix(),
		LastCycleImported: 12,
		TotalImported:     34,
		LastError:         "",
		SyncMode:          dbExportSyncModeFull,
	}
	if err := store.UpsertSyncStatus(status); err != nil {
		t.Fatalf("UpsertSyncStatus failed: %v", err)
	}
	got, err := store.GetSyncStatus(dbExportSyncStatusName)
	if err != nil {
		t.Fatalf("GetSyncStatus failed: %v", err)
	}
	if got == nil {
		t.Fatalf("GetSyncStatus got nil")
	}
	if got.TotalImported != 34 || got.LastCycleImported != 12 || got.SyncMode != dbExportSyncModeFull {
		t.Fatalf("unexpected status: %+v", got)
	}

	for i := 0; i < 5; i++ {
		err := store.AppendSyncCycle(dbExportSyncStatusName, LocalSyncCycleRecord{
			CycleAt:  int64(1700000000 + i),
			Imported: i + 1,
			OK:       i%2 == 0,
		}, 3)
		if err != nil {
			t.Fatalf("AppendSyncCycle failed: %v", err)
		}
	}
	cycles, err := store.ListRecentSyncCycles(dbExportSyncStatusName, 10)
	if err != nil {
		t.Fatalf("ListRecentSyncCycles failed: %v", err)
	}
	if len(cycles) != 3 {
		t.Fatalf("unexpected cycle size: %d", len(cycles))
	}
}

func TestHandleSyncOverview(t *testing.T) {
	store, err := newLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("newLocalStore failed: %v", err)
	}
	defer store.Close()

	now := time.Now().Unix()
	if err := store.SaveSyncCheckpoint(dbExportCheckpointName, now-10, "c1"); err != nil {
		t.Fatalf("save meta checkpoint: %v", err)
	}
	if err := store.SaveSyncCheckpoint(dbExportStrategyCheckpointName, now-20, "c2"); err != nil {
		t.Fatalf("save strategy checkpoint: %v", err)
	}
	if err := store.SaveSyncCheckpoint(dbExportRangeCheckpointName, now-30, "c3"); err != nil {
		t.Fatalf("save range checkpoint: %v", err)
	}
	if err := store.UpsertSyncStatus(LocalSyncStatusRecord{
		Name:              dbExportSyncStatusName,
		LastSuccessAt:     now,
		LastCycleImported: 7,
		TotalImported:     70,
		LastError:         "",
		SyncMode:          dbExportSyncModeFull,
	}); err != nil {
		t.Fatalf("upsert status: %v", err)
	}
	if err := store.AppendSyncCycle(dbExportSyncStatusName, LocalSyncCycleRecord{CycleAt: now, Imported: 7, OK: true}, 20); err != nil {
		t.Fatalf("append cycle: %v", err)
	}

	p := &ProxyServer{
		config: &ProxyConfig{
			EnableDBExportSync: true,
			DBExportBaseURL:    "http://user:pass@127.0.0.1:5344/enc-api",
		},
		localStore: store,
	}

	req := httptest.NewRequest(http.MethodGet, "/api/encrypt/sync/overview", nil)
	w := httptest.NewRecorder()
	p.handleSyncOverview(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", w.Code, w.Body.String())
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	data, _ := payload["data"].(map[string]interface{})
	if data == nil {
		t.Fatalf("missing data: %s", w.Body.String())
	}
	if data["sync_mode"] != dbExportSyncModeFull {
		t.Fatalf("unexpected sync_mode: %v", data["sync_mode"])
	}
	if data["base_url_masked"] != "http://127.0.0.1:5344" {
		t.Fatalf("unexpected masked base url: %v", data["base_url_masked"])
	}
	if _, ok := data["recent_cycles"].([]interface{}); !ok {
		t.Fatalf("recent_cycles missing or invalid: %T", data["recent_cycles"])
	}
}
