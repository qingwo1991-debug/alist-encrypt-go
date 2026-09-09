package encrypt

import (
	"testing"
	"time"
)

// TestLocalStoreV2MetaPersistAcrossRestart 验证一次真实 INSPECT 的 V2 元数据
// 通过 localStore 落 SQLite，且在"重启"（重建 store 实例）后仍能读回、可被
// 播放路径复用，从而跳过对上游的重复探测。
func TestLocalStoreV2MetaPersistAcrossRestart(t *testing.T) {
	if testing.Short() {
		t.Skip("CGO sqlite in short mode")
	}
	dir := t.TempDir()

	// 第一轮：模拟一次真实播放的 INSPECT 结果落库。
	store1, err := newLocalStore(dir)
	if err != nil {
		t.Fatalf("newLocalStore #1 failed: %v", err)
	}
	key := "woyun-testhost::/dav/enc-V2-meta.mp4"
	// 触发 flush：直接复用 Flush（批量阈值 20，这里只写 1 条，显式 flush）
	store1.AddSizeV2Meta(
		key,                    // key
		"pan.example.com",      // providerHost
		"/dav/enc-V2-meta.mp4", // originalPath
		"/dav/enc-V2-meta.mp4", // encryptedPath
		1215720322,             // plainSize
		1215720354,             // ciphertextSize
		ContentVersionV2,       // version
		32,                     // headerLen
		[]byte("0123456789abcdef0123456789abcdef"), // nonceField 32B
		time.Now(),
	)
	if err := store1.Flush(true); err != nil {
		t.Fatalf("Flush #1 failed: %v", err)
	}
	if err := store1.Close(); err != nil {
		t.Fatalf("Close #1 failed: %v", err)
	}

	// 2) 模拟 App 重启：以同一目录新建 store，读回应命中 V2 meta。
	store2, err := newLocalStore(dir)
	if err != nil {
		t.Fatalf("newLocalStore #2 failed: %v", err)
	}
	defer store2.Close()

	rec, ok := store2.GetFileMeta(key)
	if !ok {
		t.Fatalf("expected V2 meta record after restart, got miss")
	}
	if rec.ContentVersion != ContentVersionV2 {
		t.Fatalf("expected content_version=%d, got %d", ContentVersionV2, rec.ContentVersion)
	}
	if rec.Size != 1215720322 {
		t.Fatalf("expected plain size=1215720322, got %d", rec.Size)
	}
	if rec.CiphertextSize != 1215720354 {
		t.Fatalf("expected ciphertext_size=1215720354, got %d", rec.CiphertextSize)
	}
	if rec.HeaderLen != 32 {
		t.Fatalf("expected header_len=32, got %d", rec.HeaderLen)
	}
	if len(rec.NonceField) != 32 {
		t.Fatalf("expected nonce_field 32B, got %d", len(rec.NonceField))
	}
}

// TestLocalStoreV2MetaLookupBuild 验证 SQLite 读回后各字段均正确
// （Version/Plain/Cipher/Header/Nonce）。
func TestLocalStoreV2MetaLookupBuild(t *testing.T) {
	if testing.Short() {
		t.Skip("CGO sqlite in short mode")
	}
	dir := t.TempDir()
	store, err := newLocalStore(dir)
	if err != nil {
		t.Fatalf("newLocalStore failed: %v", err)
	}
	defer store.Close()

	key := "provider-host|container-prefix:/dav/enc-v2-lookup.mp4"
	store.AddSizeV2Meta(
		key, "provider-host", "/dav/enc-v2-lookup.mp4", "/dav/enc-v2-lookup.mp4",
		1028, 1060, ContentVersionV2, 32, []byte("0123456789abcdef"), time.Now(),
	)
	if err := store.Flush(true); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}
	rec, ok := store.GetFileMeta(key)
	if !ok {
		t.Fatalf("expected meta record, got miss")
	}
	if rec.ContentVersion != ContentVersionV2 || rec.Size != 1028 || rec.HeaderLen != 32 || len(rec.NonceField) != 16 {
		t.Fatalf("unexpected meta fields: version=%d size=%d header=%d nonce=%d",
			rec.ContentVersion, rec.Size, rec.HeaderLen, len(rec.NonceField))
	}
	_ = store
}

// TestLookupLocalV2MetaStaleSizeRejected 验证一致性护栏：当持久化的
// ciphertext_size 与当前请求解析出的密文大小不一致（文件被替换/变更）时，
// lookupLocalV2Meta 拒绝复用旧 meta，避免拿过期加密元数据去解密新文件。
func TestLookupLocalV2MetaStaleSizeRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("CGO sqlite in short mode")
	}
	dir := t.TempDir()
	store, err := newLocalStore(dir)
	if err != nil {
		t.Fatalf("newLocalStore failed: %v", err)
	}
	defer store.Close()

	server, err := NewProxyServer(&ProxyConfig{
		AlistHost:                       "localhost",
		AlistPort:                       5244,
		ProxyPort:                       5245,
		ProviderCatalogEnabled:          false,
		ProviderCatalogTTLMinutes:       1,
		ProviderCatalogBootstrapOnStart: false,
	})
	if err != nil {
		t.Fatalf("NewProxyServer: %v", err)
	}
	defer server.stopRangeProbeLoop()
	defer server.stopCacheCleanup()
	server.localStore = store

	providerURL := "https://hydtest.example.com/redirect/opendata?download&fid=1"
	originalPath := "/dav/enc/stale-meta.mp4"

	// 先落一条 ciphertext_size=1060 的 V2 meta。
	server.recordLocalV2Meta(providerURL, originalURL, ContentMeta{
		Version:        ContentVersionV2,
		HeaderLen:      32,
		PlainSize:      1028,
		CiphertextSize: 1060,
		NonceField:     []byte("0123456789abcdef"),
	})
	if err := store.Flush(true); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	// 同 path 密文大小变为 2000 → 文件被替换，旧 meta 必须被拒绝。
	if meta, ok := server.lookupLocalV2Meta(providerURL, originalURL, 2000); ok {
		t.Fatalf("expected stale meta rejected on size mismatch, got meta=%+v", meta)
	}

	// 同 path 密文大小一致（1060）→ 命中复用。
	if _, ok := server.lookupLocalV2Meta(providerURL, originalURL, 1060); !ok {
		t.Fatalf("expected meta hit when ciphertext size matches")
	}
}
