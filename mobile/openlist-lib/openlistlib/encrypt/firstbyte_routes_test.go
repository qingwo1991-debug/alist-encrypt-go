package encrypt

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPlaybackFirstByteCacheRoutes(t *testing.T) {
	for _, route := range []string{"redirect", "api"} {
		t.Run(route, func(t *testing.T) {
			p, err := NewProxyServer(&ProxyConfig{ProxyPort: 5344, EncryptPaths: []*EncryptPath{{Path: "/enc/*", Password: "test", EncType: EncTypeAESCTR, Enable: true}}})
			if err != nil {
				t.Fatal(err)
			}
			p.stopRangeProbeLoop()
			p.stopCacheCleanup()
			p.closeLocalStore()
			defer p.closeLocalStore()
			store := &testSessionStore{}
			p.localStore = &localStore{}
			p.playbackSessionOnce.Do(func() { p.playbackSession = newPlaybackSessionTracker(store) })
			info := &RedirectInfo{RedirectURL: "http://upstream.local/encrypted", OriginalURL: "/enc/demo.mp4", FileSize: 4, ContentVersion: ContentVersionV1, PasswdInfo: &EncryptPath{Path: "/enc/*", Password: "test", EncType: EncTypeAESCTR, Enable: true}}
			p.storeRedirectCache("cached", info)
			p.decryptedBlockCache = newDecryptedBlockCache(64, 4)
			meta := ContentMeta{Version: ContentVersionV1, PlainSize: 4}
			p.decryptedBlockCache.putBlock(p.decryptedCacheBaseKey(info, meta), 0, []byte("body"))
			url := "http://local/redirect/cached?decode=1"
			if route == "api" {
				url = "http://local/api/play/stream/cached?decode=1"
			}
			req := httptest.NewRequest(http.MethodGet, url, nil)
			req.Header.Set("Range", "bytes=0-3")
			rec := httptest.NewRecorder()
			if route == "api" {
				p.handlePlayStream(rec, req)
			} else {
				newPlayOrchestrator(p).ServePlayback(rec, req)
			}
			if rec.Code != 206 || rec.Body.String() != "body" {
				t.Fatalf("response=%d %q", rec.Code, rec.Body.String())
			}
			p.FlushPlaybackSessions()
			if len(store.records) != 1 {
				t.Fatalf("records=%+v", store.records)
			}
			got := store.records[0]
			if got.BytesServed != 4 || got.FirstByteLatencyMs <= 0 || got.HeaderLatencyMs != 0 || got.DurationSecs != 0 {
				t.Fatalf("stats=%+v", got)
			}
		})
	}
}
