package handler

import (
	"bytes"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/encryption"
	"github.com/alist-encrypt-go/internal/storage/mysqlstore"
)

func TestPreserveV2FileMetaRecordKeepsPlainSizeForSizeOnlyUpdate(t *testing.T) {
	nonce := bytes.Repeat([]byte{7}, 16)
	fetchedAt := time.Now().Add(-time.Minute)
	existing := &mysqlstore.FileMetaRecord{
		OriginalPath:      "/encrypt/movie.mp4",
		EncryptedPath:     "/encrypt/movie.bin",
		Name:              "movie.mp4",
		Size:              4096,
		CiphertextSize:    4128,
		ContentVersion:    encryption.ContentVersionV2,
		HeaderLen:         encryption.ContentHeaderSize(),
		NonceField:        nonce,
		RawURL:            "https://cdn.example/movie.bin",
		Sign:              "sign",
		UpstreamFetchedAt: fetchedAt,
	}
	incoming := &mysqlstore.FileMetaRecord{
		OriginalPath: "/encrypt/movie.mp4",
		Size:         4128,
		StatusCode:   206,
	}

	preserveV2FileMetaRecord(existing, incoming)

	if incoming.Size != 4096 {
		t.Fatalf("size=%d, want plaintext size 4096", incoming.Size)
	}
	if incoming.CiphertextSize != 4128 {
		t.Fatalf("ciphertext size=%d, want 4128", incoming.CiphertextSize)
	}
	if incoming.ContentVersion != encryption.ContentVersionV2 {
		t.Fatalf("content version=%d, want v2", incoming.ContentVersion)
	}
	if incoming.HeaderLen != encryption.ContentHeaderSize() {
		t.Fatalf("header len=%d, want %d", incoming.HeaderLen, encryption.ContentHeaderSize())
	}
	if !bytes.Equal(incoming.NonceField, nonce) {
		t.Fatal("nonce was not preserved")
	}
	if incoming.RawURL != existing.RawURL || incoming.Sign != existing.Sign || incoming.EncryptedPath != existing.EncryptedPath || incoming.Name != existing.Name {
		t.Fatal("existing path metadata was not preserved")
	}
	if !incoming.UpstreamFetchedAt.Equal(fetchedAt) {
		t.Fatalf("upstream fetched at=%v, want %v", incoming.UpstreamFetchedAt, fetchedAt)
	}
}
