//go:build unix

package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"
)

func TestRestoreInvalidatesOnlyTransport(t *testing.T) {
	o, _ := restoreFixture(t)
	s, err := NewStore(o.StoreDir)
	if err != nil {
		t.Fatal(err)
	}
	original := []byte(`{"path":"/movie","name":"movie","size":100,"ciphertext_size":132,"content_version":2,"header_len":32,"chunk_size":0,"kdf_iterations":0,"raw_url":"https://cdn/secret?token=x","raw_url_auth_scope":"old-scope","sign":"old-sign","modified":"2024-01-02T03:04:05Z","upstream_fetched_at":"2024-01-02T03:04:06Z"}`)
	if err = s.Set(BucketFileInfo, "/movie", original); err != nil {
		t.Fatal(err)
	}
	// Replace fixture bundle with one containing transport entries.
	if err = os.Remove(o.Bundle); err != nil {
		t.Fatal(err)
	}
	if _, err = s.CreateSnapshot(context.Background(), o.StoreDir, "snapshot.tar", SnapshotOptions{MaxBytes: o.MaxBytes}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err = RestoreOffline(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	s, err = NewStore(o.StoreDir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	raw, err := s.Get(BucketFileInfo, "/movie")
	if err != nil {
		t.Fatal(err)
	}
	var before, after map[string]json.RawMessage
	json.Unmarshal(original, &before)
	json.Unmarshal(raw, &after)
	for k, v := range before {
		switch k {
		case "raw_url", "raw_url_auth_scope", "sign":
			if !bytes.Equal(after[k], []byte(`""`)) {
				t.Fatalf("transport survived: %s", k)
			}
		default:
			if !bytes.Equal(v, after[k]) {
				t.Fatalf("metadata/TTL changed: %s", k)
			}
		}
	}
}
func TestRestoreRejectsUnknownFileEntity(t *testing.T) {
	o, _ := restoreFixture(t)
	s, err := NewStore(o.StoreDir)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Set(BucketFileInfo, "/future", []byte(`{"path":"/future","future_session":"secret"}`)); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(o.Bundle); err != nil {
		t.Fatal(err)
	}
	if _, err = s.CreateSnapshot(context.Background(), o.StoreDir, "snapshot.tar", SnapshotOptions{MaxBytes: o.MaxBytes}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err = RestoreOffline(context.Background(), o); err == nil {
		t.Fatal("unknown entity silently migrated")
	}
}
