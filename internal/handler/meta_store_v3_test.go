package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/storage"
	"testing"

	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/storage/mysqlstore"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

func TestExportV3FileMetaWithoutMySQL(t *testing.T) {
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	d := dao.NewFileDAO(store)
	t.Cleanup(func() { d.Stop(); store.Close() })
	if err := d.SetComplete(&dao.FileInfo{Path: "/v3.bin", Size: 12345, CiphertextSize: 16448, ContentVersion: 3, HeaderLen: 64, NonceField: bytes.Repeat([]byte{7}, 16), ChunkSize: 4096, KDFIterations: 1234}); err != nil {
		t.Fatal(err)
	}
	h := NewAPIHandler(config.DefaultConfig(), nil, nil, d, nil)
	rr := httptest.NewRecorder()
	h.ExportFileMeta(rr, httptest.NewRequest(http.MethodGet, "/enc-api/exportFileMeta", nil))
	var response struct {
		Data struct {
			Items []mysqlstore.FileMetaRecord `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Data.Items) != 1 || response.Data.Items[0].ChunkSize != 4096 || response.Data.Items[0].KDFIterations != 1234 {
		t.Fatalf("export: %s", rr.Body.String())
	}
}

func TestV3FileMetaRecordMapping(t *testing.T) {
	info := &dao.FileInfo{Path: "/plain", Size: 12345, CiphertextSize: 16448, ContentVersion: encryption.ContentVersionV3, HeaderLen: encryption.V3HeaderSize, NonceField: bytes.Repeat([]byte{7}, 16), ChunkSize: 4096, KDFIterations: 1234, RawURL: "https://provider.example/file"}
	got := fileMetaRecordFromInfo(info)
	if got.ChunkSize != 4096 || got.KDFIterations != 1234 || got.Size != 12345 || got.ProviderHost != "provider.example" {
		t.Fatalf("mapped record: %+v", got)
	}
	got.NonceField[0] = 0
	if info.NonceField[0] != 7 {
		t.Fatal("nonce mapping aliases DAO")
	}
	existing := fileMetaRecordFromInfo(info)
	incoming := &mysqlstore.FileMetaRecord{Size: 16448}
	preserveV2FileMetaRecord(&existing, incoming)
	if incoming.Size != 12345 || incoming.ChunkSize != 4096 || incoming.KDFIterations != 1234 {
		t.Fatalf("size-only: %+v", incoming)
	}
	replacement := &mysqlstore.FileMetaRecord{Size: 100, ContentVersion: encryption.ContentVersionV3, NonceField: bytes.Repeat([]byte{2}, 16)}
	preserveV2FileMetaRecord(&existing, replacement)
	if replacement.Size != 100 || replacement.ChunkSize != 0 || replacement.KDFIterations != 0 {
		t.Fatalf("replacement inherited: %+v", replacement)
	}
}
