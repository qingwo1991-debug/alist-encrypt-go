package encrypt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func completeV3CacheTestInfo() *FileInfo {
	return &FileInfo{Name: "movie", Path: "/movie", RawURL: "https://cdn.example/movie?a",
		Size: 17, CiphertextSize: 112, ContentVersion: ContentVersionV3, HeaderLen: V3HeaderSize,
		NonceField: bytes.Repeat([]byte{7}, 16), ChunkSize: 16, KDFIterations: 123}
}

func TestV3MetadataCacheMergeIdentity(t *testing.T) {
	for _, list := range []bool{false, true} {
		t.Run(fmt.Sprintf("list=%v", list), func(t *testing.T) {
			store := func(p *ProxyServer, info *FileInfo) {
				if list {
					p.storeFileCacheList("/movie", info)
				} else {
					p.storeFileCache("/movie", info)
				}
			}
			t.Run("complete tuple retained", func(t *testing.T) {
				p := newRuntimeCacheTestServer()
				old := completeV3CacheTestInfo()
				store(p, old)
				incoming := &FileInfo{Size: 112}
				store(p, incoming)
				if !fileInfoHasCompleteV3(incoming) || incoming.Size != old.Size || incoming.ChunkSize != 16 || incoming.KDFIterations != 123 || !bytes.Equal(incoming.NonceField, old.NonceField) {
					t.Fatalf("incomplete merged tuple: %+v", incoming)
				}
				incoming.NonceField[0]++
				if old.NonceField[0] != 7 {
					t.Fatal("nonce snapshot aliased")
				}
			})
			t.Run("changed URL resets all fields", func(t *testing.T) {
				p := newRuntimeCacheTestServer()
				store(p, completeV3CacheTestInfo())
				incoming := &FileInfo{RawURL: "https://cdn.example/movie?b", Size: 112, ChunkSize: 16, KDFIterations: 123}
				store(p, incoming)
				if incoming.Size != 0 || incoming.ContentVersion != 0 || incoming.CiphertextSize != 0 || incoming.HeaderLen != 0 || len(incoming.NonceField) != 0 || incoming.ChunkSize != 0 || incoming.KDFIterations != 0 {
					t.Fatalf("stale metadata survived: %+v", incoming)
				}
			})
			t.Run("explicit V2 clears V3 fields", func(t *testing.T) {
				p := newRuntimeCacheTestServer()
				store(p, completeV3CacheTestInfo())
				incoming := &FileInfo{ContentVersion: ContentVersionV2, Size: 12, CiphertextSize: 44, HeaderLen: 32, NonceField: bytes.Repeat([]byte{8}, 16), ChunkSize: 16, KDFIterations: 123}
				store(p, incoming)
				if incoming.ChunkSize != 0 || incoming.KDFIterations != 0 || incoming.HeaderLen != 32 || incoming.NonceField[0] != 8 {
					t.Fatalf("cross-version merge: %+v", incoming)
				}
			})
			t.Run("new complete V3 is authoritative", func(t *testing.T) {
				p := newRuntimeCacheTestServer()
				store(p, completeV3CacheTestInfo())
				incoming := completeV3CacheTestInfo()
				incoming.RawURL += "new"
				incoming.NonceField[0] = 9
				store(p, incoming)
				if !fileInfoHasCompleteV3(incoming) || incoming.NonceField[0] != 9 {
					t.Fatalf("fresh metadata lost: %+v", incoming)
				}
			})
			t.Run("unbound persisted V3 cannot follow URL", func(t *testing.T) {
				p := newRuntimeCacheTestServer()
				old := completeV3CacheTestInfo()
				old.RawURL = ""
				store(p, old)
				incoming := &FileInfo{RawURL: "https://cdn.example/movie?a", Size: 112}
				store(p, incoming)
				if incoming.ContentVersion != 0 || incoming.ChunkSize != 0 || incoming.Size != 0 {
					t.Fatalf("persisted identity trusted: %+v", incoming)
				}
			})
			t.Run("partial V3 is not completed by old tuple", func(t *testing.T) {
				p := newRuntimeCacheTestServer()
				store(p, completeV3CacheTestInfo())
				incoming := &FileInfo{ContentVersion: ContentVersionV3, HeaderLen: V3HeaderSize}
				store(p, incoming)
				if fileInfoHasCompleteV3(incoming) || incoming.ChunkSize != 0 || len(incoming.NonceField) != 0 {
					t.Fatalf("placeholder promoted: %+v", incoming)
				}
			})
		})
	}
}

func TestV3MetadataSQLiteSeedKeepsGeometryUnbound(t *testing.T) {
	store, err := newLocalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	p := newRuntimeCacheTestServer()
	p.localStore = store
	p.config = &ProxyConfig{AlistHost: "127.0.0.1", AlistPort: 5244}
	old := completeV3CacheTestInfo()
	key := buildLocalKey("127.0.0.1:5244", "/movie")
	rec := LocalSizeRecord{Key: key, ProviderHost: "127.0.0.1:5244", OriginalPath: "/movie", Size: old.Size,
		CiphertextSize: old.CiphertextSize, ContentVersion: old.ContentVersion, HeaderLen: old.HeaderLen,
		NonceField: old.NonceField, ChunkSize: old.ChunkSize, KDFIterations: old.KDFIterations,
		RawURL: old.RawURL, UpstreamFetchedAt: time.Now().Unix(), UpdatedAt: time.Now().Unix(), LastAccessed: time.Now().Unix()}
	if err := store.Import(&LocalExport{Sizes: []LocalSizeRecord{rec}}); err != nil {
		t.Fatal(err)
	}
	info, ok := p.loadFileCache("/dav/movie")
	if !ok || !fileInfoHasCompleteV3(info) || info.ChunkSize != 16 || info.KDFIterations != 123 || info.RawURL != "" {
		t.Fatalf("seed must keep geometry but require fresh identity: %+v, ok=%v", info, ok)
	}
	alias, ok := p.loadFileCacheInMem("/movie")
	if !ok || !fileInfoHasCompleteV3(alias) || alias.RawURL != "" {
		t.Fatalf("seed alias: %+v, ok=%v", alias, ok)
	}
	empty := rec
	empty.Key = buildLocalKey("127.0.0.1:5244", "/empty")
	empty.OriginalPath = "/empty"
	empty.Size, empty.CiphertextSize, empty.RawURL = 0, 64, ""
	if err := store.Import(&LocalExport{Sizes: []LocalSizeRecord{empty}}); err != nil {
		t.Fatal(err)
	}
	emptyInfo, ok := p.loadFileCache("/empty")
	if !ok || !fileInfoHasCompleteV3(emptyInfo) || emptyInfo.Size != 0 || emptyInfo.RawURL != "" {
		t.Fatalf("empty seed: %+v ok=%v", emptyInfo, ok)
	}
	meta, ok := p.lookupLocalV3Meta(p.getAlistURL(), "/empty", 64)
	if !ok || ValidateV3ContentMeta(meta) != nil || meta.PlainSize != 0 {
		t.Fatalf("empty local geometry: %+v ok=%v", meta, ok)
	}
}

func TestV3MetadataSyncFieldsAndEmptyRoundtrip(t *testing.T) {
	p := &ProxyServer{config: &ProxyConfig{AlistHost: "127.0.0.1", AlistPort: 5244}}
	for _, cipherSize := range []int64{48, 64, 112} {
		t.Run(fmt.Sprint(cipherSize), func(t *testing.T) {
			plain := int64(0)
			if cipherSize == 112 {
				plain = 17
			}
			item := dbExportFileMetaResponseDataItem{ProviderHost: "cdn.example", OriginalPath: "/movie", Size: plain,
				ContentVersion: ContentVersionV3, CiphertextSize: cipherSize, HeaderLen: V3HeaderSize,
				NonceField: bytes.Repeat([]byte{7}, 16), ChunkSize: 16, KDFIterations: 123,
				RawURL: "https://cdn.example/signed", Sign: "signed"}
			raw, err := json.Marshal(item)
			if err != nil {
				t.Fatal(err)
			}
			var decoded dbExportFileMetaResponseDataItem
			if err := json.Unmarshal(raw, &decoded); err != nil {
				t.Fatal(err)
			}
			rec, ok := p.buildImportedSizeRecord(&decoded, time.Now().Unix())
			if !ok || rec.ChunkSize != 16 || rec.KDFIterations != 123 || rec.RawURL != "" || rec.Sign != "" || ValidateV3ContentMeta(localRecordContentMeta(*rec)) != nil {
				t.Fatalf("sync tuple=%+v ok=%v", rec, ok)
			}
			raw, err = json.Marshal(LocalExport{Sizes: []LocalSizeRecord{*rec}})
			if err != nil {
				t.Fatal(err)
			}
			var exported LocalExport
			if err := json.Unmarshal(raw, &exported); err != nil {
				t.Fatal(err)
			}
			if len(exported.Sizes) != 1 || ValidateV3ContentMeta(localRecordContentMeta(exported.Sizes[0])) != nil {
				t.Fatalf("export roundtrip: %+v", exported)
			}
		})
	}
	var legacy dbExportFileMetaResponseDataItem
	if err := json.Unmarshal([]byte(`{"ProviderHost":"cdn.example","OriginalPath":"/old","Size":5,"ContentVersion":2}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.ChunkSize != 0 || legacy.KDFIterations != 0 {
		t.Fatal("old JSON did not default V3 fields to zero")
	}
	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("ChunkSize")) || bytes.Contains(raw, []byte("KDFIterations")) {
		t.Fatalf("legacy fields not omitted: %s", raw)
	}
	partial := dbExportFileMetaResponseDataItem{ProviderHost: "cdn.example", OriginalPath: "/partial", ContentVersion: ContentVersionV3, CiphertextSize: 64, HeaderLen: 48, NonceField: make([]byte, 16)}
	if _, ok := p.buildImportedSizeRecord(&partial, 1); ok {
		t.Fatal("partial empty V3 imported")
	}
}
