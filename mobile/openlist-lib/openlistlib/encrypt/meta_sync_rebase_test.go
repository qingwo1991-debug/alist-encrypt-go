package encrypt

import (
	"strings"
	"testing"
	"time"
)

func TestRebaseImportedMetaKeyUsesPhoneHost(t *testing.T) {
	p := &ProxyServer{
		config: &ProxyConfig{AlistHost: "192.168.1.50", AlistPort: 5244},
	}

	// 服务端 ProviderHost 是 CDN host,手机端 key 应统一成手机自身 alist host。
	key, ok := p.rebaseImportedMetaKey("1f2.net", "/storage/电影.mp4")
	if !ok {
		t.Fatalf("expected rebase ok")
	}
	want := buildLocalKey("192.168.1.50:5244", "/storage/电影.mp4")
	if key != want {
		t.Fatalf("rebase key mismatch:\n got=%s\nwant=%s\n", key, want)
	}
}

func TestRebaseImportedMetaKeyFallbackToServerHost(t *testing.T) {
	// config 为 nil 时(拿不到手机 host),回退使用服务端 host,避免整条记录被丢弃。
	p := &ProxyServer{}
	key, ok := p.rebaseImportedMetaKey("cdn.example.com:443", "/a/b.mp4")
	if !ok {
		t.Fatalf("expected fallback rebase ok")
	}
	// url.Parse("http://:0") 时 Host 为空 → 走 providerHost fallback。
	want := buildLocalKey("cdn.example.com:443", "/a/b.mp4")
	if key != want {
		t.Fatalf("fallback key mismatch: got=%s want=%s", key, want)
	}
}

func TestRebaseImportedMetaKeyEmpty(t *testing.T) {
	p := &ProxyServer{config: &ProxyConfig{AlistHost: "127.0.0.1", AlistPort: 5244}}
	if _, ok := p.rebaseImportedMetaKey("cdn.example.com", ""); ok {
		t.Fatalf("expected false for empty original path")
	}
	if _, ok := p.rebaseImportedMetaKey("", ""); ok {
		t.Fatalf("expected false for empty everything")
	}
}

func TestBuildImportedSizeRecordDropsServerRawURL(t *testing.T) {
	// 核心行为:导入时丢弃服务端 RawURL/Sign,只保留 meta。
	// store.Import 本身会持久化给它的 RawURL;丢弃发生在 meta_sync 的转换层
	// (buildImportedSizeRecord),这里直接测转换层的输出。
	p := &ProxyServer{
		config: &ProxyConfig{AlistHost: "127.0.0.1", AlistPort: 5244},
	}

	item := dbExportFileMetaResponseDataItem{
		ProviderHost:      "cdn.example.com:443",
		OriginalPath:      "/movies/foo.mp4",
		Name:              "foo.mp4",
		Size:              1024 * 1024,
		ContentVersion:    ContentVersionV2,
		HeaderLen:         32,
		NonceField:        make([]byte, 16),
		RawURL:            "https://cdn.example.com/sig/abc",
		Sign:              "sig",
		UpdatedAt:         "2026-09-07T00:00:00+08:00",
		UpstreamFetchedAt: "2026-09-07T00:00:00+08:00",
	}
	rec, ok := p.buildImportedSizeRecord(&item, time.Now().Unix())
	if !ok || rec == nil {
		t.Fatalf("expected record built")
	}
	// key 必须是手机 host(alist host)重算,而不是服务端 CDN host。
	wantKey := buildLocalKey("127.0.0.1:5244", "/movies/foo.mp4")
	if rec.Key != wantKey {
		t.Fatalf("key not rebased: got=%s want=%s", rec.Key, wantKey)
	}
	if strings.TrimSpace(rec.RawURL) != "" {
		t.Fatalf("expected server raw_url dropped, got %q", rec.RawURL)
	}
	if strings.TrimSpace(rec.Sign) != "" {
		t.Fatalf("expected sign dropped, got %q", rec.Sign)
	}
	if rec.UpstreamFetchedAt != 0 {
		t.Fatalf("expected upstream_fetched_at reset, got %d", rec.UpstreamFetchedAt)
	}
	// meta 字段必须保留。
	if rec.ContentVersion != ContentVersionV2 || rec.HeaderLen != 32 || len(rec.NonceField) != 16 {
		t.Fatalf("meta fields not preserved: ver=%d header=%d nonce=%d", rec.ContentVersion, rec.HeaderLen, len(rec.NonceField))
	}
	if rec.Size != 1024*1024 {
		t.Fatalf("size not preserved: %d", rec.Size)
	}
}