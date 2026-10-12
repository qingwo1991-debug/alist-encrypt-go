package encrypt

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPlaybackFirstByteCacheRoutes(t *testing.T) {
	for _, route := range []string{"redirect", "api"} {
		t.Run(route, func(t *testing.T) {
			// Exercise the playback boundary, not server startup/shutdown. The full
			// constructor starts unrelated asynchronous provider-catalog discovery.
			p := &ProxyServer{config: &ProxyConfig{StreamEngineVersion: 2}}
			p.ensureRuntimeCaches()
			store := &testSessionStore{}
			p.localStore = &localStore{}
			p.streamClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return nil, fmt.Errorf("unexpected upstream call in cache route test")
			})}
			p.playbackSessionOnce.Do(func() { p.playbackSession = newPlaybackSessionTracker(store) })
			info := &RedirectInfo{RedirectURL: "http://upstream.local/encrypted", OriginalURL: "/enc/demo.mp4", FileSize: 4, ContentVersion: ContentVersionV1, PasswdInfo: &EncryptPath{Path: "/enc/*", Password: "test", EncType: EncTypeAESCTR, Enable: true}}
			p.storeRedirectCache("cached", info)
			p.decryptedBlockCache = newDecryptedBlockCache(64, 4)
			meta := LegacyContentMeta(EncTypeAESCTR, 4)
			p.decryptedBlockCache.putBlock(p.decryptedCacheBaseKey(info, meta), 0, []byte("body"))
			url := "http://local/redirect/cached?decode=1"
			if route == "api" {
				url = "http://local/api/play/stream/cached?decode=1"
			}
			req := httptest.NewRequest(http.MethodGet, url, nil)
			req.Header.Set("Range", "bytes=-2")
			rec := httptest.NewRecorder()
			if route == "api" {
				p.handlePlayStream(rec, req)
			} else {
				newPlayOrchestrator(p).ServePlayback(rec, req)
			}
			if rec.Code != 206 || rec.Body.String() != "dy" {
				t.Fatalf("response=%d %q", rec.Code, rec.Body.String())
			}
			p.FlushPlaybackSessions()
			if len(store.records) != 1 {
				t.Fatalf("records=%+v", store.records)
			}
			got := store.records[0]
			if got.BytesServed != 2 || got.TotalBytes != 4 || got.SeekCount != 1 || got.FirstByteLatencyMs <= 0 || got.HeaderLatencyMs != 0 || got.DurationSecs != 0 {
				t.Fatalf("stats=%+v", got)
			}
		})
	}
}

func TestPlaybackFirstByteDirectSuffixStats(t *testing.T) {
	plain := bytes.Repeat([]byte("C"), 4096)
	enc, err := NewLatestContentEncryptor("test", string(EncTypeAESCTR), int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}
	reader, err := enc.EncryptReader(bytes.NewReader(plain), 0)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []bool{false, true} {
		t.Run(fmt.Sprint("suffix=", suffix), func(t *testing.T) {
			p := &ProxyServer{config: &ProxyConfig{StreamEngineVersion: 2}, localStore: &localStore{}}
			p.ensureRuntimeCaches()
			store := &testSessionStore{}
			p.playbackSessionOnce.Do(func() { p.playbackSession = newPlaybackSessionTracker(store) })
			p.streamClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				var start, end int
				switch req.Header.Get("Range") {
				case "bytes=0-47":
					start, end = 0, 47
				case "bytes=32-":
					start, end = 32, len(ciphertext)-1
				case "bytes=4126-4127":
					start, end = 4126, 4127
				default:
					return nil, fmt.Errorf("unexpected range %q", req.Header.Get("Range"))
				}
				return &http.Response{StatusCode: 206, ContentLength: int64(end - start + 1), Header: http.Header{"Content-Range": {fmt.Sprintf("bytes %d-%d/%d", start, end, len(ciphertext))}, "Content-Length": {fmt.Sprint(end - start + 1)}}, Body: io.NopCloser(bytes.NewReader(ciphertext[start : end+1])), Request: req}, nil
			})}
			info := &RedirectInfo{RedirectURL: "http://upstream.local/v2", OriginalURL: "/enc/video.mp4", FileSize: int64(len(ciphertext)), PasswdInfo: &EncryptPath{Password: "test", EncType: EncTypeAESCTR, Enable: true}}
			p.storeRedirectCache("direct", info)
			req := httptest.NewRequest("GET", "http://local/redirect/direct?decode=1", nil)
			want := plain
			wantSeek := 0
			if suffix {
				req.Header.Set("Range", "bytes=-2")
				want = plain[len(plain)-2:]
				wantSeek = 1
			} else {
				req.Header.Set("Range", "bytes=0-")
			}
			rec := httptest.NewRecorder()
			newPlayOrchestrator(p).ServePlayback(rec, req)
			if rec.Code != 206 || !bytes.Equal(rec.Body.Bytes(), want) {
				t.Fatalf("response=%d bytes=%d", rec.Code, rec.Body.Len())
			}
			p.FlushPlaybackSessions()
			if len(store.records) != 1 {
				t.Fatalf("records=%+v", store.records)
			}
			got := store.records[0]
			if got.TotalBytes != 4096 || got.SeekCount != wantSeek || got.BytesServed != int64(len(want)) || got.FirstByteLatencyMs <= 0 {
				t.Fatalf("stats=%+v", got)
			}
		})
	}
}
