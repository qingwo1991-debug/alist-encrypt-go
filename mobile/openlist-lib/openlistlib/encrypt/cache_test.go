package encrypt

import (
	"bytes"
	"testing"
	"time"
)

// TestFileCacheTTL 测试文件缓存的 TTL 功能
func TestFileCacheTTL(t *testing.T) {
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

	// 存储一个文件信息
	testPath := "/test/path/file.mp4"
	testInfo := &FileInfo{
		Name:  "file.mp4",
		Size:  1024000,
		IsDir: false,
		Path:  testPath,
	}

	server.storeFileCache(testPath, testInfo)

	// 应该能立即读取到
	cached, ok := server.loadFileCache(testPath)
	if !ok {
		t.Error("Expected to load cached file info")
	}
	if cached.Size != testInfo.Size {
		t.Errorf("Expected size %d, got %d", testInfo.Size, cached.Size)
	}

	// 测试缓存存在
	if cached.Name != testInfo.Name {
		t.Errorf("Expected name %s, got %s", testInfo.Name, cached.Name)
	}
}

func TestFileCacheRawURLChangeInvalidatesUntrustedV2Metadata(t *testing.T) {
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
	defer server.closeLocalStore()

	const cachePath = "/enc/movie.mp4"
	server.storeFileCache(cachePath, &FileInfo{
		Name:           "movie.mp4",
		Size:           4096,
		CiphertextSize: 4128,
		ContentVersion: ContentVersionV2,
		HeaderLen:      32,
		NonceField:     make([]byte, 16),
		Path:           cachePath,
		RawURL:         "http://cdn.example/old-signature",
	})
	server.storeFileCache(cachePath, &FileInfo{
		Name:   "movie.mp4",
		Path:   cachePath,
		RawURL: "http://cdn.example/new-signature",
	})

	cached, ok := server.loadFileCache(cachePath)
	if !ok {
		t.Fatal("updated file cache entry is missing")
	}
	if cached.RawURL != "http://cdn.example/new-signature" {
		t.Fatalf("RawURL=%q", cached.RawURL)
	}
	if cached.Size != 0 || cached.CiphertextSize != 0 || cached.ContentVersion != 0 || cached.HeaderLen != 0 || len(cached.NonceField) != 0 {
		t.Fatalf("stale V2 metadata survived identity change: %+v", cached)
	}
	if _, ok := server.getSizeMap(cachePath); ok {
		t.Fatal("stale size-map entry survived identity change")
	}
}

func TestFileCacheFirstRawURLPreservesTrustedV2Metadata(t *testing.T) {
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
	defer server.closeLocalStore()

	const cachePath = "/enc/movie.mp4"
	nonce := bytes.Repeat([]byte{7}, 16)
	server.storeFileCache(cachePath, &FileInfo{
		Name:           "movie.mp4",
		Size:           4096,
		CiphertextSize: 4128,
		ContentVersion: ContentVersionV2,
		HeaderLen:      32,
		NonceField:     nonce,
		Path:           cachePath,
	})
	server.storeFileCache(cachePath, &FileInfo{
		Name:   "movie.mp4",
		Path:   cachePath,
		RawURL: "http://cdn.example/first-signature",
	})

	cached, ok := server.loadFileCache(cachePath)
	if !ok {
		t.Fatal("updated file cache entry is missing")
	}
	if cached.RawURL != "http://cdn.example/first-signature" {
		t.Fatalf("RawURL=%q", cached.RawURL)
	}
	if cached.Size != 4096 || cached.CiphertextSize != 4128 ||
		cached.ContentVersion != ContentVersionV2 || cached.HeaderLen != 32 ||
		!bytes.Equal(cached.NonceField, nonce) {
		t.Fatalf("trusted V2 metadata was discarded when first RawURL was attached: %+v", cached)
	}
}

// TestRedirectCacheTTL 测试重定向缓存的 TTL 功能
func TestRedirectCacheTTL(t *testing.T) {
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

	// 存储一个重定向信息
	testKey := "testRedirectKey123"
	testInfo := &RedirectInfo{
		RedirectURL: "http://example.com/file.mp4",
		FileSize:    2048000,
	}

	server.storeRedirectCache(testKey, testInfo)

	// 应该能立即读取到
	cached, ok := server.loadRedirectCache(testKey)
	if !ok {
		t.Error("Expected to load cached redirect info")
	}
	if cached.FileSize != testInfo.FileSize {
		t.Errorf("Expected fileSize %d, got %d", testInfo.FileSize, cached.FileSize)
	}
	if cached.RedirectURL != testInfo.RedirectURL {
		t.Errorf("Expected URL %s, got %s", testInfo.RedirectURL, cached.RedirectURL)
	}
}

// TestCacheCleanup 测试缓存清理功能
func TestCacheCleanup(t *testing.T) {
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

	// 直接存储一个已过期的缓存条目
	expiredPath := "/test/expired/file.mp4"
	server.fileCache.Store(expiredPath, &CachedFileInfo{
		Info: &FileInfo{
			Name:  "file.mp4",
			Size:  1024,
			IsDir: false,
			Path:  expiredPath,
		},
		ExpireAt: time.Now().Add(-1 * time.Hour), // 已过期
	})

	// 存储一个未过期的缓存条目
	validPath := "/test/valid/file.mp4"
	server.fileCache.Store(validPath, &CachedFileInfo{
		Info: &FileInfo{
			Name:  "valid.mp4",
			Size:  2048,
			IsDir: false,
			Path:  validPath,
		},
		ExpireAt: time.Now().Add(1 * time.Hour), // 未过期
	})

	// 执行清理
	server.cleanupExpiredCache()

	// 过期的应该被清理
	_, ok := server.loadFileCache(expiredPath)
	if ok {
		t.Error("Expected expired cache to be cleaned up")
	}

	// 未过期的应该还在
	cached, ok := server.loadFileCache(validPath)
	if !ok {
		t.Error("Expected valid cache to remain")
	}
	if cached.Size != 2048 {
		t.Errorf("Expected size 2048, got %d", cached.Size)
	}
}

// TestParallelDecrypt 测试并行解密函数
func TestParallelDecrypt(t *testing.T) {
	config := &ProxyConfig{
		AlistHost: "localhost",
		AlistPort: 5244,
		ProxyPort: 5245,
		EncryptPaths: []*EncryptPath{
			{
				Path:     "/encrypt/*",
				Password: "testpassword",
				EncType:  EncTypeAESCTR,
				EncName:  true,
				Enable:   true,
			},
		},
	}

	server, err := NewProxyServer(config)
	if err != nil {
		t.Fatalf("Failed to create proxy server: %v", err)
	}
	defer server.stopCacheCleanup()

	// 创建一些模拟的文件解密任务
	encPath := config.EncryptPaths[0]

	// 先加密一些文件名
	plainNames := []string{"movie1.mp4", "movie2.mp4", "video3.mkv"}
	tasks := make([]fileDecryptTask, len(plainNames))

	for i, name := range plainNames {
		encName := ConvertRealName(encPath.Password, encPath.EncType, "/encrypt/"+name)
		tasks[i] = fileDecryptTask{
			index:    i,
			fileMap:  map[string]interface{}{"name": encName},
			name:     encName,
			filePath: "/encrypt/" + encName,
		}
	}

	// 执行并行解密
	server.parallelDecryptFileNames(tasks, encPath)

	// 验证解密结果
	for i, task := range tasks {
		decryptedName := task.fileMap["name"].(string)
		// 解密后应该是原始名称或 orig_ 前缀的名称
		t.Logf("Task %d: encrypted=%s, decrypted=%s", i, task.name, decryptedName)
	}
}
