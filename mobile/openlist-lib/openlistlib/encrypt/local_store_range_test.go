package encrypt

import (
	"testing"
	"time"
)

func TestLocalStoreRangeCompatCRUD(t *testing.T) {
	dir := t.TempDir()
	store, err := newLocalStore(dir)
	if err != nil {
		t.Fatalf("newLocalStore failed: %v", err)
	}
	defer store.Close()

	key := "example.com|storage"
	blockedUntil := time.Now().Add(10 * time.Minute).Truncate(time.Second)
	if err := store.UpsertRangeCompat(key, blockedUntil, 0); err != nil {
		t.Fatalf("UpsertRangeCompat blocked failed: %v", err)
	}

	records, err := store.LoadRangeCompat(time.Now())
	if err != nil {
		t.Fatalf("LoadRangeCompat failed: %v", err)
	}
	if got, ok := records[key]; !ok || got.Unix() != blockedUntil.Unix() {
		t.Fatalf("unexpected blocked record: ok=%v got=%v want=%v", ok, got, blockedUntil)
	}

	if err := store.UpsertRangeCompat(key, time.Time{}, 1); err != nil {
		t.Fatalf("UpsertRangeCompat failures failed: %v", err)
	}
	records, err = store.LoadRangeCompat(time.Now())
	if err != nil {
		t.Fatalf("LoadRangeCompat after clear failed: %v", err)
	}
	if _, ok := records[key]; ok {
		t.Fatalf("expected key removed from blocked view after clear")
	}

	if err := store.DeleteRangeCompat(key); err != nil {
		t.Fatalf("DeleteRangeCompat failed: %v", err)
	}
}
