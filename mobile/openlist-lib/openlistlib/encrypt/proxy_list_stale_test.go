package encrypt

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestWebdavListCacheStaleAfterFreshMiss 验证：新鲜 TTL 过后 load 返回 miss
// 但条目保留，loadWebdavListCacheStale 能读到旧快照（供上游失败时回退）。
func TestWebdavListCacheStaleAfterFreshMiss(t *testing.T) {
	config := &ProxyConfig{
		AlistHost: "localhost",
		AlistPort: 5244,
		ProxyPort: 5245,
	}
	server, err := NewProxyServer(config)
	if err != nil {
		t.Fatalf("Failed to create proxy server: %v", err)
	}
	defer server.stopCacheCleanup()

	dir := "/dir"
	body := []byte("<multistatus>ok</multistatus>")
	server.storeWebdavListCache(dir, 207, body)

	// 新鲜命中 ok
	if status, got, ok := server.loadWebdavListCache(dir); !ok || status != 207 || string(got) != string(body) {
		t.Fatalf("expected fresh hit, ok=%v", ok)
	}

	// 拨快 ExpireAt（新鲜窗口过期），load 应 miss 但保留条目
	server.webdavListCacheMu.Lock()
	server.webdavListCache[dir].ExpireAt = time.Now().Add(-time.Second)
	server.webdavListCacheMu.Unlock()

	if _, _, ok := server.loadWebdavListCache(dir); ok {
		t.Fatal("expected fresh miss after ExpireAt")
	}
	status, got, storedAt, ok := server.loadWebdavListCacheStale(dir)
	if !ok || status != 207 || string(got) != string(body) {
		t.Fatalf("expected stale hit, ok=%v status=%d", ok, status)
	}
	if storedAt.IsZero() {
		t.Fatal("expected StoredAt to be set on stale entry")
	}

	// 拨过 StoredUntil 后 stale 也应 miss 且被清理
	server.webdavListCacheMu.Lock()
	server.webdavListCache[dir].StoredUntil = time.Now().Add(-time.Second)
	server.webdavListCacheMu.Unlock()
	if _, _, _, ok := server.loadWebdavListCacheStale(dir); ok {
		t.Fatal("expected miss after StoredUntil")
	}
}

// TestCleanupKeepsStaleSnapshot 验证清理任务不会提前删掉“新鲜已过但仍在 stale
// 窗口”的条目（这是历史列表回退能用的前提）。
func TestCleanupKeepsStaleSnapshot(t *testing.T) {
	config := &ProxyConfig{
		AlistHost: "localhost",
		AlistPort: 5244,
		ProxyPort: 5245,
	}
	server, err := NewProxyServer(config)
	if err != nil {
		t.Fatalf("Failed to create proxy server: %v", err)
	}
	defer server.stopCacheCleanup()

	dir := "/dir"
	server.storeWebdavListCache(dir, 207, []byte("<ok/>"))
	// 让新鲜窗口过期，但不触发 stale 上限清理。
	server.webdavListCacheMu.Lock()
	server.webdavListCache[dir].ExpireAt = time.Now().Add(-time.Hour)
	server.webdavListCacheMu.Unlock()

	server.cleanupExpiredCache()

	if _, _, _, ok := server.loadWebdavListCacheStale(dir); !ok {
		t.Fatal("expected stale snapshot to survive cleanup while within StoredUntil")
	}
}

// TestServeStaleWebDAVListHeaderOrder 验证 stale 回退时写头顺序正确：Content-Type
// 与 X-List-Stale 必须在 WriteHeader 之前设置，且 404 缺快照时返回 false（不吞咽）。
func TestServeStaleWebDAVListHeaderOrder(t *testing.T) {
	config := &ProxyConfig{
		AlistHost: "localhost",
		AlistPort: 5244,
		ProxyPort: 5245,
	}
	server, err := NewProxyServer(config)
	if err != nil {
		t.Fatalf("Failed to create proxy server: %v", err)
	}
	defer server.stopCacheCleanup()

	// 先造一份 stale 快照
	body := []byte(`<?xml version="1.0"?><D:multistatus xmlns:D="DAV:"><D:response><D:href>/dav/movies/</D:href><D:propstat><D:prop><D:displayname>movies</D:displayname></D:prop></D:propstat></D:response></D:multistatus>`)
	server.storeWebdavListCache("/movies", 207, body)

	w := httptest.NewRecorder()
	ctx := context.Background()
	srcHeaders := http.Header{}
	srcHeaders.Set("Authorization", "Bearer foo")

	ok := server.serveStaleWebDAVList(w, ctx, "/movies", "1", "/movies", "/dav/movies", srcHeaders)
	if !ok {
		t.Fatal("expected stale serve to write a response")
	}
	res := w.Result()
	if res.StatusCode != 207 {
		t.Fatalf("expected 207, got %d", res.StatusCode)
	}
	if res.Header.Get("X-List-Stale") != "1" {
		t.Fatalf("expected X-List-Stale marker, got %q", res.Header.Get("X-List-Stale"))
	}
	if ct := res.Header.Get("Content-Type"); ct != "text/xml; charset=utf-8" {
		t.Fatalf("expected XML content-type, got %q", ct)
	}

	// 无快照时应返回 false（调用方继续走真实 404/错误路径）
	w2 := httptest.NewRecorder()
	md2 := server.serveStaleWebDAVList(w2, ctx, "/none", "1", "/none", "/dav/none", srcHeaders)
	if md2 {
		t.Fatal("expected false when no stale snapshot exists")
	}
}

// TestExtractWebdavListEntries 验证从解密的 depth-1 正文抽取 (href, name, size, isDir)。
func TestExtractWebdavListEntries(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>/dav/movies/</D:href>
    <D:propstat><D:prop><D:displayname>movies</D:displayname></D:prop></D:propstat>
  </D:response>
  <D:response>
    <D:href>/dav/movies/a%20b.mp4</D:href>
    <D:propstat><D:prop>
      <D:displayname>a b.mp4</D:displayname>
      <D:getcontentlength>12345</D:getcontentlength>
    </D:prop></D:propstat>
  </D:response>
  <D:response>
    <D:href>/dav/movies/sub.srt</D:href>
    <D:propstat><D:prop>
      <D:displayname>sub.srt</D:displayname>
      <D:getcontentlength>0</D:getcontentlength>
    </D:prop></D:propstat>
  </D:response>
</D:multistatus>`)

	entries := extractWebdavListEntries(body)
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	dir := entries[0]
	if !dir.isDir || dir.name != "movies" {
		t.Fatalf("expected dir entry movies, got dir=%v name=%q", dir.isDir, dir.name)
	}
	video := entries[1]
	if video.isDir || video.size != 12345 || video.name != "a b.mp4" {
		t.Fatalf("unexpected video entry: dir=%v size=%d name=%q", video.isDir, video.size, video.name)
	}
	if video.showPath != "/dav/movies/a b.mp4" {
		t.Fatalf("expected decoded href, got %q", video.showPath)
	}
	sub := entries[2]
	if !sub.isDir {
		t.Fatal("expected zero-size entry treated as dir marker")
	}
}

// TestMaybePersistDirListWritesLocalStore 验证目录落盘：写入 localStore 后
// 能用 GetFileMeta 读回 name/size（重启后无需上游即可还原尺寸）。
func TestMaybePersistDirListWritesLocalStore(t *testing.T) {
	baseDir := t.TempDir()
	store, err := newLocalStore(baseDir)
	if err != nil {
		t.Fatalf("newLocalStore failed: %v", err)
	}
	defer store.Close()

	config := &ProxyConfig{
		AlistHost: "localhost",
		AlistPort: 5244,
		ProxyPort: 5245,
	}
	server, err := NewProxyServer(config)
	if err != nil {
		t.Fatalf("Failed to create proxy server: %v", err)
	}
	defer server.stopCacheCleanup()
	server.localStore = store

	body := []byte(`<?xml version="1.0"?>
<D:multistatus xmlns:D="DAV:">
  <D:response><D:href>/dav/movies/sample.mp4</D:href><D:propstat><D:prop>
    <D:displayname>sample.mp4</D:displayname>
    <D:getcontentlength>999</D:getcontentlength>
  </D:prop></D:propstat></D:response>
  <D:response><D:href>/dav/movies/folder/</D:href><D:propstat><D:prop>
    <D:displayname>folder</D:displayname>
  </D:prop></D:propstat></D:response>
</D:multistatus>`)

	server.maybePersistDirList(context.Background(), "/movies", body)
	if err := store.Flush(true); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	// 目录本身不落盘（isDir）；文件条目以 showPath 为键写入。
	key, providerHost, originalPath, ok := server.localKeyFromURLs("http://localhost:5244", "/dav/movies/sample.mp4")
	if !ok {
		t.Fatal("localKeyFromURLs failed")
	}
	if providerHost != "localhost:5244" {
		t.Fatalf("unexpected provider host %q", providerHost)
	}
	if originalPath != "/dav/movies/sample.mp4" {
		t.Fatalf("unexpected original path %q", originalPath)
	}
	meta, ok := store.GetFileMeta(key)
	if !ok {
		t.Fatal("expected persisted file meta")
	}
	if meta.Name != "sample.mp4" || meta.Size != 999 {
		t.Fatalf("unexpected persisted meta: name=%q size=%d", meta.Name, meta.Size)
	}
}
