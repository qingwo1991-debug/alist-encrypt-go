package encrypt

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func TestMobileV3SQLiteRoundtripAndPartialPreservation(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "v3.db")
	db, err := sql.Open("sqlite3", filename)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Exec(`CREATE TABLE local_media_size (key TEXT PRIMARY KEY,provider_host TEXT NOT NULL,original_path TEXT NOT NULL,size INTEGER NOT NULL,last_accessed INTEGER NOT NULL,updated_at INTEGER NOT NULL)`)
	if err != nil {
		t.Fatal(err)
	}
	if err = initLocalSchema(db); err != nil {
		t.Fatal(err)
	}
	store := &localStore{db: db, flushThreshold: 100}
	meta := ContentMeta{Version: 3, HeaderLen: 48, PlainSize: 17, CiphertextSize: 112, NonceField: make([]byte, 16), ChunkSize: 16, KDFIterations: 123}
	empty := meta
	empty.PlainSize = 0
	empty.CiphertextSize = 64
	now := time.Now()
	store.AddContentMeta("real", "cdn", "/real", "/encrypted", meta, now)
	store.AddContentMeta("empty", "cdn", "/empty", "/encrypted-empty", empty, now)
	if err = store.Flush(true); err != nil {
		t.Fatal(err)
	}
	// Plain size and prewarm observations are partial, not V3 replacements.
	store.AddSize("real", "cdn", "/real", 999, now)
	store.AddFullMeta("real", "cdn", "/real", 999, &prewarmMeta{name: "renamed"}, now)
	if err = store.Flush(true); err != nil {
		t.Fatal(err)
	}
	rec, ok := store.GetFileMeta("real")
	if !ok || rec.Size != 17 || rec.ChunkSize != 16 || rec.KDFIterations != 123 || rec.ContentVersion != 3 || rec.CiphertextSize != 112 {
		t.Fatalf("rec=%+v", rec)
	}
	if rec.Name != "renamed" {
		t.Fatal("ordinary metadata lost")
	}
	snap, _, err := store.GetSnapshot("empty")
	if err != nil || snap == nil || snap.Size != 0 || snap.ChunkSize != 16 {
		t.Fatalf("snapshot=%+v err=%v", snap, err)
	}
	exported, err := store.ExportAll()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(exported)
	if err != nil {
		t.Fatal(err)
	}
	var imported LocalExport
	if err = json.Unmarshal(raw, &imported); err != nil {
		t.Fatal(err)
	}
	other, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "import.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err = initLocalSchema(other); err != nil {
		t.Fatal(err)
	}
	dst := &localStore{db: other}
	if err = dst.Import(&imported); err != nil {
		t.Fatal(err)
	}
	got, ok := dst.GetFileMeta("empty")
	if !ok || !validEmptyV3LocalRecord(*got) {
		t.Fatalf("empty=%+v", got)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := sql.Open("sqlite3", filename)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	store.db = reopened
	rec, ok = store.GetFileMeta("real")
	if !ok || rec.ChunkSize != 16 || rec.KDFIterations != 123 || ValidateV3ContentMeta(localRecordContentMeta(*rec)) != nil {
		t.Fatalf("restart=%+v", rec)
	}
}
