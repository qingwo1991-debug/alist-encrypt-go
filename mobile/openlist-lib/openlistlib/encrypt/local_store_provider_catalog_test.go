package encrypt

import (
	"path/filepath"
	"testing"
	"time"
)

func TestLocalStoreProviderCatalogUpsertAndList(t *testing.T) {
	store, err := newLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("newLocalStore failed: %v", err)
	}
	defer store.Close()

	now := time.Now().Unix()
	err = store.UpsertProviderCatalog([]LocalProviderCatalogRecord{
		{
			ProviderKey: "china_mobile_cloud",
			DisplayName: "移动云盘",
			SourceMask:  providerSourceBuiltin,
			FirstSeenAt: now - 100,
			LastSeenAt:  now - 100,
			UpdatedAt:   now - 100,
		},
		{
			ProviderKey: "china_mobile_cloud",
			DisplayName: "",
			SourceMask:  providerSourceRemote,
			FirstSeenAt: now - 50,
			LastSeenAt:  now,
			UpdatedAt:   now,
		},
	})
	if err != nil {
		t.Fatalf("UpsertProviderCatalog failed: %v", err)
	}
	rows, err := store.ListProviderCatalog()
	if err != nil {
		t.Fatalf("ListProviderCatalog failed: %v", err)
	}
	if len(rows) == 0 {
		t.Fatalf("expected non-empty provider catalog rows")
	}
	var target *LocalProviderCatalogRecord
	for i := range rows {
		if rows[i].ProviderKey == "china_mobile_cloud" {
			target = &rows[i]
			break
		}
	}
	if target == nil {
		t.Fatalf("china_mobile_cloud not found in rows: %+v", rows)
	}
	if target.DisplayName != "移动云盘" {
		t.Fatalf("expected display name preserved, got %q", target.DisplayName)
	}
	if target.SourceMask&(providerSourceBuiltin|providerSourceRemote) != (providerSourceBuiltin | providerSourceRemote) {
		t.Fatalf("source mask merge failed, got %d", target.SourceMask)
	}
}

func TestLocalStoreProviderCatalogMeta(t *testing.T) {
	baseDir := t.TempDir()
	store, err := newLocalStore(baseDir)
	if err != nil {
		t.Fatalf("newLocalStore failed: %v", err)
	}
	defer store.Close()

	ts := time.Now().UTC().Format(time.RFC3339)
	if err := store.SetMeta(providerCatalogMetaLastRefresh, ts); err != nil {
		t.Fatalf("SetMeta failed: %v", err)
	}
	got, _, err := store.GetMeta(providerCatalogMetaLastRefresh)
	if err != nil {
		t.Fatalf("GetMeta failed: %v", err)
	}
	if got != ts {
		t.Fatalf("meta value mismatch: got=%q want=%q", got, ts)
	}
	// reopen and ensure persisted
	_ = store.Close()
	store2, err := newLocalStore(filepath.Clean(baseDir))
	if err != nil {
		t.Fatalf("reopen local store failed: %v", err)
	}
	defer store2.Close()
	got, _, err = store2.GetMeta(providerCatalogMetaLastRefresh)
	if err != nil {
		t.Fatalf("GetMeta after reopen failed: %v", err)
	}
	if got != ts {
		t.Fatalf("meta persisted value mismatch: got=%q want=%q", got, ts)
	}
}
