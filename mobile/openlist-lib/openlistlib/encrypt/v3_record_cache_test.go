package encrypt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	core "github.com/alist-encrypt-go/shared/encryptcore"
)

func TestV3PlaybackTinySeekCacheAndColdConnectionCount(t *testing.T) {
	plain := []byte("abcdefghijklmnopqrstuvwxyz0123456789!")
	data, meta := v3PlaybackFixture(t, plain, 8, false)
	var calls, sent atomic.Int64
	var ranges []string
	var rangeMu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		rangeMu.Lock()
		ranges = append(ranges, r.Header.Get("Range"))
		rangeMu.Unlock()
		var start, end int64
		fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &start, &end)
		w.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(data)))
		w.WriteHeader(206)
		sent.Add(end - start + 1)
		w.Write(data[start : end+1])
	}))
	defer server.Close()
	p := &ProxyServer{streamClient: server.Client()}
	info := v3PlaybackInfo(server.URL)
	serve := func(interval string, want []byte) *playbackTiming {
		t.Helper()
		request := httptest.NewRequest("GET", "http://client/", nil)
		request.Header.Set("Range", interval)
		recorder := httptest.NewRecorder()
		w, r, timing := withPlaybackTiming(recorder, request)
		if err := p.serveV3Playback(w, r, info, meta); err != nil || recorder.Code != 206 || !bytes.Equal(recorder.Body.Bytes(), want) {
			t.Fatalf("interval=%s err=%v status=%d body=%q", interval, err, recorder.Code, recorder.Body.Bytes())
		}
		if recorder.Header().Get("Content-Length") != strconv.Itoa(len(want)) || timing.bytesWritten != int64(len(want)) {
			t.Fatalf("headers=%v timing=%+v", recorder.Header(), timing)
		}
		return timing
	}
	serve("bytes=0-1", plain[:2])
	timing := serve("bytes=6-7", plain[6:8])
	if calls.Load() != 1 || sent.Load() != 24 || timing.headerLatencyMs != 0 {
		t.Fatalf("calls=%d sent=%d timing=%+v", calls.Load(), sent.Load(), timing)
	}
	// Open range uses the cached record then one precise connection for all tail
	// records; the returned Content-Length still covers the complete interval.
	serve("bytes=0-", plain)
	rangeMu.Lock()
	if calls.Load() != 2 || ranges[1] != "bytes=72-167" {
		t.Fatalf("calls=%d ranges=%v", calls.Load(), ranges)
	}
	rangeMu.Unlock()
	serve("bytes=0-", plain)
	if calls.Load() != 2 {
		t.Fatalf("fully cached requested upstream: %d", calls.Load())
	}
}

func TestV3PlaybackCacheIdentityIsolation(t *testing.T) {
	_, meta := v3PlaybackFixture(t, []byte("abcdefghijklmnop"), 8, false)
	p := &ProxyServer{}
	request := httptest.NewRequest("GET", "http://client/", nil)
	info := v3PlaybackInfo("https://provider.invalid/media?signature=one")
	base, err := p.v3PlaybackCacheKey(request, info, meta)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		change func(*http.Request, *RedirectInfo, *ContentMeta)
	}{
		{"password", func(_ *http.Request, i *RedirectInfo, _ *ContentMeta) { i.PasswdInfo.Password = "different" }},
		{"authorization", func(r *http.Request, _ *RedirectInfo, _ *ContentMeta) { r.Header.Set("Authorization", "Bearer other") }},
		{"cookie", func(r *http.Request, _ *RedirectInfo, _ *ContentMeta) { r.Header.Set("Cookie", "session=other") }},
		{"stored-auth", func(_ *http.Request, i *RedirectInfo, _ *ContentMeta) {
			i.Headers = http.Header{"Authorization": []string{"Bearer stored"}}
		}},
		{"stored-cookie", func(_ *http.Request, i *RedirectInfo, _ *ContentMeta) {
			i.Headers = http.Header{"Cookie": []string{"session=stored"}}
		}},
		{"user-agent", func(r *http.Request, _ *RedirectInfo, _ *ContentMeta) { r.Header.Set("User-Agent", "other") }},
		{"provider", func(_ *http.Request, i *RedirectInfo, _ *ContentMeta) { i.Provider = "other" }},
		{"driver", func(_ *http.Request, i *RedirectInfo, _ *ContentMeta) { i.Driver = "other" }},
		{"object", func(_ *http.Request, i *RedirectInfo, _ *ContentMeta) { i.EncryptedPath = "/different" }},
		{"url", func(_ *http.Request, i *RedirectInfo, _ *ContentMeta) {
			i.RedirectURL = "https://provider.invalid/media?signature=two"
		}},
		{"nonce", func(_ *http.Request, _ *RedirectInfo, m *ContentMeta) { m.NonceField = []byte("fedcba9876543210") }},
		{"kdf", func(_ *http.Request, _ *RedirectInfo, m *ContentMeta) { m.KDFIterations = 2 }},
		{"size", func(_ *http.Request, _ *RedirectInfo, m *ContentMeta) { m.PlainSize-- }},
		{"chunk", func(_ *http.Request, _ *RedirectInfo, m *ContentMeta) { m.ChunkSize = 4; m.CiphertextSize = 48 + 4*20 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := request.Clone(context.Background())
			i := *info
			ep := *info.PasswdInfo
			i.PasswdInfo = &ep
			m := meta
			tc.change(r, &i, &m)
			key, err := p.v3PlaybackCacheKey(r, &i, m)
			if err != nil || key == base {
				t.Fatalf("identity isolation err=%v equal=%v", err, key == base)
			}
		})
	}
	info.RedirectURL = "relative/unknown"
	if _, err := p.v3PlaybackCacheKey(request, info, meta); err == nil {
		t.Fatal("unknown target enabled cache")
	}
}

func TestV3PlaybackTamperedRecordNeverPublished(t *testing.T) {
	data, meta := v3PlaybackFixture(t, []byte("abcdefghijklmnop"), 8, false)
	data[48] ^= 1
	server := v3PlaybackServer(t, data, false, nil)
	defer server.Close()
	p := &ProxyServer{streamClient: server.Client()}
	info := v3PlaybackInfo(server.URL)
	request := httptest.NewRequest("GET", "http://client/", nil)
	request.Header.Set("Range", "bytes=0-1")
	for n := 0; n < 2; n++ {
		w := httptest.NewRecorder()
		if err := p.serveV3Playback(w, request, info, meta); err == nil || w.Code != 502 || w.Body.Len() != 0 {
			t.Fatalf("err=%v status=%d", err, w.Code)
		}
	}
	key, err := p.v3PlaybackCacheKey(request, info, meta)
	if err != nil {
		t.Fatal(err)
	}
	if lease, hit := mobileV3Records.Get(key, 0); hit {
		lease.Release()
		t.Fatal("tampered plaintext published")
	}
}

func TestV3PlaybackCachedPrefixFailureIsPrecommit(t *testing.T) {
	data, meta := v3PlaybackFixture(t, []byte("abcdefghijklmnop"), 8, false)
	var reject atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if reject.Load() {
			w.WriteHeader(200)
			w.Header().Set("Content-Length", strconv.Itoa(len(data)))
			return
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes 48-71/%d", len(data)))
		w.Header().Set("Content-Length", "24")
		w.WriteHeader(206)
		w.Write(data[48:72])
	}))
	defer server.Close()
	p := &ProxyServer{streamClient: server.Client()}
	info := v3PlaybackInfo(server.URL)
	request := httptest.NewRequest("GET", "http://client/", nil)
	request.Header.Set("Range", "bytes=0-1")
	if err := p.serveV3Playback(httptest.NewRecorder(), request, info, meta); err != nil {
		t.Fatal(err)
	}
	reject.Store(true)
	request.Header.Set("Range", "bytes=0-")
	w := httptest.NewRecorder()
	err := p.serveV3Playback(w, request, info, meta)
	var failure *V3PlaybackError
	if !errors.As(err, &failure) || w.Code != 502 || w.Body.Len() != 0 {
		t.Fatalf("err=%v status=%d body=%q", err, w.Code, w.Body.Bytes())
	}
}

func TestV3PlaybackRecordCacheFullStreamsNormally(t *testing.T) {
	// Use the shared public reader with a tiny local cache: the production singleton
	// is deliberately never replaced (other HTTP tests may run concurrently).
	data, meta := v3PlaybackFixture(t, []byte("abcdefghijklmnop"), 8, false)
	cipher, err := core.NewV3ChunkCipher(core.DeriveV3Key("fixture", meta.NonceField, 1), meta.NonceField)
	if err != nil {
		t.Fatal(err)
	}
	p := &ProxyServer{}
	r := httptest.NewRequest("GET", "http://client/", nil)
	key, err := p.v3PlaybackCacheKey(r, v3PlaybackInfo("https://budget.invalid/object"), meta)
	if err != nil {
		t.Fatal(err)
	}
	var calls int
	loader := func(_ context.Context, index uint64) ([]byte, error) {
		calls++
		offset := 48 + int(index)*24
		return data[offset : offset+24], nil
	}
	reader, err := core.NewV3RecordReader(r.Context(), cipher, 8, 0, 0, 16, 16, core.NewV3AuthenticatedRecordCache(1, 0), key, loader)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	got, err := io.ReadAll(reader)
	if err != nil || string(got) != "abcdefghijklmnop" || calls != 2 {
		t.Fatalf("body=%q calls=%d err=%v", got, calls, err)
	}
}
