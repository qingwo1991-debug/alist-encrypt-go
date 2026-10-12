package dao

import (
	"bytes"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/storage"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

func TestFileDAOV3RoundTripAndSizeOnlyUpdates(t *testing.T) {
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	d := NewFileDAO(store)
	t.Cleanup(func() { d.Stop(); store.Close() })
	original := &FileInfo{Path: "/plain.bin", EncryptedPath: "/encrypted.bin", Name: "plain.bin", Size: 12345, CiphertextSize: 16448, ContentVersion: encryption.ContentVersionV3, HeaderLen: encryption.V3HeaderSize, NonceField: bytes.Repeat([]byte{7}, 16), ChunkSize: 4096, KDFIterations: 1234}
	if err := d.SetComplete(original); err != nil {
		t.Fatal(err)
	}
	check := func(label string) {
		t.Helper()
		got, ok := d.Get(original.Path)
		if !ok || got.ChunkSize != 4096 || got.KDFIterations != 1234 || got.Size != 12345 || !bytes.Equal(got.NonceField, original.NonceField) {
			t.Fatalf("%s: %+v", label, got)
		}
	}
	check("cache")
	d.pathCache.Delete(original.Path)
	check("persistent")
	if err := d.Set(&FileInfo{Path: original.Path, Size: original.CiphertextSize}); err != nil {
		t.Fatal(err)
	}
	check("merge")
	d.SetEncPathMappingWithInfo(original.Path, original.EncryptedPath, original.Name, original.CiphertextSize, false)
	check("mapping")
	d.SetFileSize(original.Path, original.CiphertextSize, time.Hour)
	check("size-only")
	prepared := d.PrepareFromAlistResponse(original.Path, map[string]interface{}{"size": float64(original.CiphertextSize)}, "anon")
	if err := d.PersistFromList([]*FileInfo{prepared}); err != nil {
		t.Fatal(err)
	}
	check("listing")
	if got := d.List(0); len(got) != 1 || got[0].ChunkSize != 4096 || got[0].KDFIterations != 1234 {
		t.Fatalf("list: %+v", got)
	}
}

func TestFileDAOV3MergeReplacementNonce(t *testing.T) {
	existing := &FileInfo{Size: 12345, CiphertextSize: 16448, ContentVersion: encryption.ContentVersionV3, HeaderLen: encryption.V3HeaderSize, NonceField: bytes.Repeat([]byte{1}, 16), ChunkSize: 4096, KDFIterations: 1234}
	for _, tc := range []struct {
		name    string
		nonce   []byte
		version int
		want    uint32
	}{
		{"same nonce", bytes.Repeat([]byte{1}, 16), encryption.ContentVersionV3, 4096},
		{"missing nonce", nil, 0, 4096},
		{"new nonce", bytes.Repeat([]byte{2}, 16), encryption.ContentVersionV3, 0},
		{"changed version", bytes.Repeat([]byte{1}, 16), encryption.ContentVersionV2, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			incoming := &FileInfo{Size: 100, ContentVersion: tc.version, NonceField: tc.nonce}
			mergeMissingFields(incoming, existing)
			if incoming.ChunkSize != tc.want || (tc.want == 0 && incoming.KDFIterations != 0) || (tc.want != 0 && incoming.KDFIterations != 1234) {
				t.Fatalf("merge: %+v", incoming)
			}
			if tc.want == 0 && incoming.Size != 100 {
				t.Fatalf("replacement size inherited: %+v", incoming)
			}
		})
	}
	// V3 overhead is per-record, not just the header: no fixed-header subtraction.
	incoming := &FileInfo{Size: existing.Size + existing.HeaderLen}
	mergeMissingFields(incoming, existing)
	if incoming.Size != 12345+encryption.V3HeaderSize {
		t.Fatalf("unexpected fixed-header reconciliation: %d", incoming.Size)
	}
}
