package encrypt

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	core "github.com/alist-encrypt-go/shared/encryptcore"
)

// Deterministic fixtures use shared header/cipher APIs, never duplicate AEAD.
func v3PlaybackFixture(t *testing.T, plain []byte, chunk int64, trailer bool) ([]byte, ContentMeta) {
	t.Helper()
	nonce := []byte("0123456789abcdef")
	headerSize := int64(len(plain))
	if trailer {
		headerSize = 0
	}
	header, err := core.NewV3Header(headerSize, nonce, chunk, 1)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := core.NewV3ChunkCipher(core.DeriveV3Key("fixture", nonce, 1), nonce)
	if err != nil {
		t.Fatal(err)
	}
	data := append([]byte(nil), header...)
	for offset, index := 0, uint64(0); offset < len(plain); index++ {
		padded := make([]byte, chunk)
		n := copy(padded, plain[offset:])
		offset += n
		record, err := cipher.Seal(index, padded)
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, record...)
	}
	if trailer {
		tail := make([]byte, 16)
		copy(tail, "V3E4")
		binary.BigEndian.PutUint64(tail[8:], uint64(len(plain)))
		data = append(data, tail...)
	}
	meta := ContentMeta{Version: 3, HeaderLen: 48, PlainSize: int64(len(plain)), CiphertextSize: int64(len(data)), NonceField: nonce, ChunkSize: uint32(chunk), KDFIterations: 1}
	return data, meta
}

func v3PlaybackServer(t *testing.T, data []byte, ignore bool, mutate func(http.ResponseWriter)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ignore {
			w.Header().Set("Content-Length", strconv.Itoa(len(data)))
			w.Write(data)
			return
		}
		var start, end int64
		if _, err := fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &start, &end); err != nil || start < 0 || end >= int64(len(data)) {
			t.Errorf("unexpected upstream Range %q", r.Header.Get("Range"))
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(data)))
		if mutate != nil {
			mutate(w)
		}
		w.WriteHeader(206)
		w.Write(data[start : end+1])
	}))
}

func v3PlaybackInfo(url string) *RedirectInfo {
	return &RedirectInfo{RedirectURL: url, PasswdInfo: &EncryptPath{Password: "fixture"}}
}

func TestV3PlaybackPlainRangesAndHead(t *testing.T) {
	plain := []byte("abcdefghijklmnopqrstuvwxyz0123456789!")
	for _, trailer := range []bool{false, true} {
		data, meta := v3PlaybackFixture(t, plain, 8, trailer)
		for _, ignore := range []bool{false, true} {
			server := v3PlaybackServer(t, data, ignore, nil)
			p := &ProxyServer{streamClient: server.Client()}
			for _, tc := range []struct {
				name, method, rangeHeader string
				start, end, status        int
			}{
				{"full", "GET", "", 0, len(plain) - 1, 200}, {"cross", "GET", "bytes=6-18", 6, 18, 206}, {"seek", "GET", "bytes=16-", 16, len(plain) - 1, 206}, {"suffix", "GET", "bytes=-5", len(plain) - 5, len(plain) - 1, 206}, {"one", "GET", "bytes=36-36", 36, 36, 206}, {"head", "HEAD", "", 0, len(plain) - 1, 200}, {"headsuffix", "HEAD", "bytes=-5", len(plain) - 5, len(plain) - 1, 206},
			} {
				t.Run(fmt.Sprintf("trailer=%v/ignore=%v/%s", trailer, ignore, tc.name), func(t *testing.T) {
					req := httptest.NewRequest(tc.method, "http://client/redirect/test", nil)
					req.Header.Set("Range", tc.rangeHeader)
					recorder := httptest.NewRecorder()
					w, r, timing := withPlaybackTiming(recorder, req)
					if err := p.serveV3Playback(w, r, v3PlaybackInfo(server.URL), meta); err != nil {
						t.Fatal(err)
					}
					if recorder.Code != tc.status {
						t.Fatalf("status=%d", recorder.Code)
					}
					expected := plain[tc.start : tc.end+1]
					if recorder.Header().Get("Content-Length") != strconv.Itoa(len(expected)) {
						t.Fatalf("headers=%v", recorder.Header())
					}
					if tc.status == 206 && recorder.Header().Get("Content-Range") != fmt.Sprintf("bytes %d-%d/%d", tc.start, tc.end, len(plain)) {
						t.Fatalf("range=%q", recorder.Header().Get("Content-Range"))
					}
					if tc.method == "HEAD" {
						if recorder.Body.Len() != 0 || timing.bytesWritten != 0 {
							t.Fatal("HEAD body")
						}
					} else if !bytes.Equal(recorder.Body.Bytes(), expected) || timing.bytesWritten != int64(len(expected)) {
						t.Fatalf("body=%q stats=%d", recorder.Body.Bytes(), timing.bytesWritten)
					}
					if timing.rangeStart != int64(tc.start) || timing.totalBytes != int64(len(plain)) {
						t.Fatalf("timing=%+v", timing)
					}
				})
			}
			server.Close()
		}
	}
}

func TestV3PlaybackFailuresAndEmpty(t *testing.T) {
	data, meta := v3PlaybackFixture(t, []byte("abcdefghijklmnopqrst"), 8, false)
	corrupt := append([]byte(nil), data...)
	corrupt[48] ^= 1
	for _, tc := range []struct {
		name        string
		data        []byte
		mutate      func(http.ResponseWriter)
		rangeHeader string
		status      int
	}{
		{"firstauth", corrupt, nil, "", 502},
		{"wrongwindow", data, func(w http.ResponseWriter) { w.Header().Set("Content-Range", "bytes 49-119/120") }, "", 502},
		{"encoded", data, func(w http.ResponseWriter) { w.Header().Set("Content-Encoding", "gzip") }, "", 502},
		{"unknown-total", data, func(w http.ResponseWriter) { w.Header().Set("Content-Range", "bytes 48-119/*") }, "", 502},
		{"multi", data, nil, "bytes=0-1,4-5", 400},
		{"unsatisfiable", data, nil, "bytes=99-", 416},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := v3PlaybackServer(t, tc.data, false, tc.mutate)
			defer server.Close()
			p := &ProxyServer{streamClient: server.Client()}
			req := httptest.NewRequest("GET", "http://client/", nil)
			req.Header.Set("Range", tc.rangeHeader)
			w := httptest.NewRecorder()
			err := p.serveV3Playback(w, req, v3PlaybackInfo(server.URL), meta)
			var failure *V3PlaybackError
			if !errors.As(err, &failure) || !failure.ResponseStarted || !failure.NoLearning || w.Code != tc.status || w.Body.Len() != 0 {
				t.Fatalf("err=%v status=%d body=%q", err, w.Code, w.Body.Bytes())
			}
			if tc.status == 416 && w.Header().Get("Content-Range") != "bytes */20" {
				t.Fatalf("headers=%v", w.Header())
			}
		})
	}
	for _, trailer := range []bool{false, true} {
		_, empty := v3PlaybackFixture(t, nil, 8, trailer)
		w := httptest.NewRecorder()
		p := &ProxyServer{}
		if err := p.serveV3Playback(w, httptest.NewRequest("GET", "http://client/", nil), v3PlaybackInfo("http://unused"), empty); err != nil || w.Code != 200 || w.Body.Len() != 0 || w.Header().Get("Content-Length") != "0" {
			t.Fatalf("empty err=%v headers=%v", err, w.Header())
		}
	}
}

func TestV3PlaybackLaterAuthenticationIsTerminal(t *testing.T) {
	data, meta := v3PlaybackFixture(t, []byte("abcdefghijklmnopqrst"), 8, true)
	data[48+24] ^= 1
	server := v3PlaybackServer(t, data, false, nil)
	defer server.Close()
	p := &ProxyServer{streamClient: server.Client()}
	w := httptest.NewRecorder()
	err := p.serveV3Playback(w, httptest.NewRequest("GET", "http://client/", nil), v3PlaybackInfo(server.URL), meta)
	var failure *V3PlaybackError
	if !errors.As(err, &failure) || !failure.ResponseStarted || w.Code != 200 || w.Body.String() != "abcdefgh" {
		t.Fatalf("err=%v status=%d body=%q", err, w.Code, w.Body.String())
	}
}

type v3PlaybackRoundTripFunc func(*http.Request) (*http.Response, error)

func (f v3PlaybackRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type v3PlaybackCountingBody struct{ reads, closes *atomic.Int64 }

func (b v3PlaybackCountingBody) Read([]byte) (int, error) {
	b.reads.Add(1)
	return 0, errors.New("must not read fallback")
}
func (b v3PlaybackCountingBody) Close() error { b.closes.Add(1); return nil }

func TestV3PlaybackDeepFallbackRefusedBeforeRead(t *testing.T) {
	// No records allocated: authoritative geometry alone describes a deep seek.
	chunk := int64(8)
	plain := int64(16 << 20)
	meta := ContentMeta{Version: 3, HeaderLen: 48, PlainSize: plain, CiphertextSize: 48 + (plain/chunk)*(chunk+16), NonceField: []byte("0123456789abcdef"), ChunkSize: 8, KDFIterations: 1}
	for _, status := range []int{200, 416} {
		var reads, closes, calls atomic.Int64
		client := &http.Client{Transport: v3PlaybackRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls.Add(1)
			return &http.Response{StatusCode: status, Header: make(http.Header), ContentLength: meta.CiphertextSize, Body: v3PlaybackCountingBody{&reads, &closes}}, nil
		})}
		p := &ProxyServer{streamClient: client}
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "http://client/", nil)
		req.Header.Set("Range", "bytes=12582912-12582913")
		err := p.serveV3Playback(w, req, v3PlaybackInfo("http://loopback.invalid/"), meta)
		if err == nil || w.Code != 502 || reads.Load() != 0 || calls.Load() != 1 || closes.Load() == 0 {
			t.Fatalf("status=%d err=%v reads=%d calls=%d closes=%d", w.Code, err, reads.Load(), calls.Load(), closes.Load())
		}
	}
}

func TestV3PlaybackCancelStalledFirstRecord(t *testing.T) {
	_, meta := v3PlaybackFixture(t, []byte("abcdefghijklmnop"), 8, false)
	entered := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "48")
		w.Header().Set("Content-Range", fmt.Sprintf("bytes 48-95/%d", meta.CiphertextSize))
		w.WriteHeader(206)
		w.(http.Flusher).Flush()
		close(entered)
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest("GET", "http://client/", nil).WithContext(ctx)
	p := &ProxyServer{streamClient: server.Client()}
	w := httptest.NewRecorder()
	done := make(chan error, 1)
	go func() { done <- p.serveV3Playback(w, req, v3PlaybackInfo(server.URL), meta) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream not entered")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil || w.Code != 502 || w.Body.Len() != 0 {
			t.Fatalf("err=%v status=%d", err, w.Code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancel did not release stream")
	}
	if !v3PlaybackMemory.TryAcquire(v3PlaybackMemoryBytes) {
		t.Fatal("budget leaked on cancellation")
	}
	v3PlaybackMemory.Release(v3PlaybackMemoryBytes)
}

func TestV3PlaybackExternalCredentialsAndRedirect(t *testing.T) {
	data, meta := v3PlaybackFixture(t, []byte("abcdefghijklmnop"), 8, false)
	var leaked atomic.Bool
	final := v3PlaybackServer(t, data, false, nil)
	defer final.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Proxy-Authorization") != "" {
			leaked.Store(true)
		}
		http.Redirect(w, r, final.URL, 302)
	}))
	defer origin.Close()
	// Assert both the initial target and redirected target with a transport hook.
	base := origin.Client().Transport
	client := &http.Client{Transport: v3PlaybackRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Proxy-Authorization") != "" {
			leaked.Store(true)
		}
		if r.Header.Get("Accept-Encoding") != "identity" {
			t.Errorf("encoding=%q", r.Header.Get("Accept-Encoding"))
		}
		return base.RoundTrip(r)
	})}
	req := httptest.NewRequest("GET", "http://client/", nil)
	req.Header.Set("Authorization", "Bearer private")
	req.Header.Set("Cookie", "private=1")
	info := v3PlaybackInfo(origin.URL)
	info.Headers = http.Header{"Authorization": []string{"Bearer stored"}}
	p := &ProxyServer{streamClient: client}
	w := httptest.NewRecorder()
	if err := p.serveV3Playback(w, req, info, meta); err != nil || leaked.Load() {
		t.Fatalf("err=%v leaked=%v", err, leaked.Load())
	}
}

func TestV3PlaybackSharedWriterTrailer(t *testing.T) {
	// One default-iteration writer fixture exercises the real streaming format.
	plain := []byte(strings.Repeat("writer", 7))
	var data bytes.Buffer
	writer, err := core.NewV3Writer(&data, "fixture", 8)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = writer.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	meta := ContentMeta{Version: 3, HeaderLen: 48, PlainSize: int64(len(plain)), CiphertextSize: int64(data.Len()), NonceField: writer.NonceField(), ChunkSize: 8, KDFIterations: 600000}
	server := v3PlaybackServer(t, data.Bytes(), false, nil)
	defer server.Close()
	p := &ProxyServer{streamClient: server.Client()}
	w := httptest.NewRecorder()
	if err = p.serveV3Playback(w, httptest.NewRequest("GET", "http://client/", nil), v3PlaybackInfo(server.URL), meta); err != nil || !bytes.Equal(w.Body.Bytes(), plain) {
		t.Fatalf("err=%v body=%q", err, w.Body.Bytes())
	}
}

func TestV3PlaybackRefusedRangeFullRetry(t *testing.T) {
	data, meta := v3PlaybackFixture(t, []byte("abcdefghijklmnopqrst"), 8, true)
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Range") != "" {
			w.WriteHeader(416)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.Write(data)
	}))
	defer server.Close()
	p := &ProxyServer{streamClient: server.Client()}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "http://client/", nil)
	r.Header.Set("Range", "bytes=-7")
	if err := p.serveV3Playback(w, r, v3PlaybackInfo(server.URL), meta); err != nil || w.Code != 206 || w.Body.String() != "nopqrst" || requests.Load() != 2 {
		t.Fatalf("err=%v status=%d body=%q calls=%d", err, w.Code, w.Body.String(), requests.Load())
	}
}

func TestV3PlaybackTruncatedFirstRecord(t *testing.T) {
	_, meta := v3PlaybackFixture(t, []byte("abcdefgh"), 8, false)
	var closed atomic.Int64
	body := &v3PlaybackShortBody{Reader: bytes.NewReader([]byte("short")), closed: &closed}
	p := &ProxyServer{streamClient: &http.Client{Transport: v3PlaybackRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 206, Header: http.Header{"Content-Range": []string{"bytes 48-71/72"}}, ContentLength: 24, Body: body}, nil
	})}}
	w := httptest.NewRecorder()
	err := p.serveV3Playback(w, httptest.NewRequest("GET", "http://client/", nil), v3PlaybackInfo("http://unused/"), meta)
	if err == nil || w.Code != 502 || w.Body.Len() != 0 || closed.Load() != 1 {
		t.Fatalf("err=%v status=%d closed=%d", err, w.Code, closed.Load())
	}
}

type v3PlaybackShortBody struct {
	*bytes.Reader
	closed *atomic.Int64
}

func (b *v3PlaybackShortBody) Close() error { b.closed.Add(1); return nil }

func TestV3PlaybackMetadataCapsBeforeUpstream(t *testing.T) {
	_, meta := v3PlaybackFixture(t, []byte("a"), 8, false)
	p := &ProxyServer{streamClient: &http.Client{Transport: v3PlaybackRoundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("invalid metadata reached upstream")
		return nil, io.EOF
	})}}
	meta.KDFIterations = MaxMobileV3KDFIterations + 1
	w := httptest.NewRecorder()
	err := p.serveV3Playback(w, httptest.NewRequest("GET", "http://client/", nil), v3PlaybackInfo("http://unused/"), meta)
	if err == nil || w.Code != 503 {
		t.Fatalf("err=%v status=%d", err, w.Code)
	}
}

func TestV3PlaybackHeaderLatencyExcludesHandlerAndAuthentication(t *testing.T) {
	data, meta := v3PlaybackFixture(t, []byte("abcdefgh"), 8, false)
	timing := &playbackTiming{started: time.Now().Add(-time.Hour)}
	body := &v3PlaybackHeaderTimingBody{Reader: bytes.NewReader(data[48:]), timing: timing, t: t}
	p := &ProxyServer{streamClient: &http.Client{Transport: v3PlaybackRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 206, Header: http.Header{"Content-Range": []string{"bytes 48-71/72"}}, ContentLength: 24, Body: body}, nil
	})}}
	recorder := httptest.NewRecorder()
	w := &playbackTimingWriter{ResponseWriter: recorder, timing: timing}
	r := httptest.NewRequest("GET", "http://client/", nil)
	r = r.WithContext(context.WithValue(r.Context(), playbackTimingKey{}, timing))
	if err := p.serveV3Playback(w, r, v3PlaybackInfo("http://unused/"), meta); err != nil {
		t.Fatal(err)
	}
	if timing.headerLatencyMs >= 60_000 || timing.firstByteLatencyMs < 3_600_000 {
		t.Fatalf("timing=%+v", timing)
	}
}

type v3PlaybackHeaderTimingBody struct {
	*bytes.Reader
	timing   *playbackTiming
	t        *testing.T
	headerMs float64
	read     bool
}

func (b *v3PlaybackHeaderTimingBody) Read(p []byte) (int, error) {
	if !b.read {
		b.read = true
		if b.timing.headerLatencyMs <= 0 || b.timing.headerLatencyMs >= 60_000 {
			b.t.Fatalf("header latency not captured before authentication: %f", b.timing.headerLatencyMs)
		}
		b.headerMs = b.timing.headerLatencyMs
	}
	return b.Reader.Read(p)
}
func (b *v3PlaybackHeaderTimingBody) Close() error {
	if b.read && b.headerMs != b.timing.headerLatencyMs {
		b.t.Errorf("header latency changed during authentication/output: before=%f after=%f", b.headerMs, b.timing.headerLatencyMs)
	}
	return nil
}

func TestV3PlaybackExpiredURLRefreshOnce(t *testing.T) {
	oldData, oldMeta := v3PlaybackFixture(t, []byte("old-object"), 8, false)
	_ = oldData
	freshPlain := []byte("new replacement plaintext with different chunk geometry")
	freshData, freshMeta := v3PlaybackFixture(t, freshPlain, 7, false)
	// Change nonce via shared crypto too, not just geometry: a refreshed object
	// must not inherit the expired URL's cipher metadata.
	freshMeta.NonceField = []byte("fedcba9876543210")
	header, err := core.NewV3Header(freshMeta.PlainSize, freshMeta.NonceField, 7, 1)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := core.NewV3ChunkCipher(core.DeriveV3Key("fixture", freshMeta.NonceField, 1), freshMeta.NonceField)
	if err != nil {
		t.Fatal(err)
	}
	freshData = append([]byte(nil), header...)
	for offset, index := 0, uint64(0); offset < len(freshPlain); index++ {
		padded := make([]byte, 7)
		offset += copy(padded, freshPlain[offset:])
		record, err := cipher.Seal(index, padded)
		if err != nil {
			t.Fatal(err)
		}
		freshData = append(freshData, record...)
	}
	for _, rejectFresh := range []bool{false, true} {
		var expiredCalls, refreshCalls, recordCalls atomic.Int64
		expired := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { expiredCalls.Add(1); w.WriteHeader(403) }))
		fresh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var start, end int64
			if _, err := fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &start, &end); err != nil {
				t.Errorf("range=%q", r.Header.Get("Range"))
				w.WriteHeader(500)
				return
			}
			if start != 0 {
				recordCalls.Add(1)
				if rejectFresh {
					w.WriteHeader(401)
					return
				}
			}
			if start < 0 || end >= int64(len(freshData)) {
				w.WriteHeader(416)
				return
			}
			w.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(freshData)))
			w.WriteHeader(206)
			w.Write(freshData[start : end+1])
		}))
		control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			refreshCalls.Add(1)
			if r.URL.Path != "/api/fs/get" {
				t.Errorf("path=%s", r.URL.Path)
			}
			fmt.Fprintf(w, `{"code":200,"data":{"raw_url":%q,"size":%d}}`, fresh.URL, len(freshData))
		}))
		parsed, _ := url.Parse(control.URL)
		host, portText, _ := net.SplitHostPort(parsed.Host)
		port, _ := strconv.Atoi(portText)
		p := &ProxyServer{config: &ProxyConfig{AlistHost: host, AlistPort: port}, httpClient: control.Client(), streamClient: fresh.Client()}
		info := v3PlaybackInfo(expired.URL)
		info.EncryptedPath = "/dav/encrypted.bin"
		info.PasswdInfo.Enable = true
		req := httptest.NewRequest("GET", "http://client/", nil)
		req.Header.Set("Range", "bytes=-9")
		recorder := httptest.NewRecorder()
		w, r, timing := withPlaybackTiming(recorder, req)
		err := p.serveV3Playback(w, r, info, oldMeta)
		if rejectFresh {
			var failure *V3PlaybackError
			if !errors.As(err, &failure) || !failure.ResponseStarted || recorder.Code != 502 || recorder.Body.Len() != 0 {
				t.Fatalf("retryerr=%v status=%d body=%q", err, recorder.Code, recorder.Body.Bytes())
			}
		} else if err != nil || recorder.Code != 206 || !bytes.Equal(recorder.Body.Bytes(), freshPlain[len(freshPlain)-9:]) || timing.rangeStart != int64(len(freshPlain)-9) || timing.totalBytes != int64(len(freshPlain)) {
			t.Fatalf("refresh err=%v status=%d body=%q timing=%+v", err, recorder.Code, recorder.Body.Bytes(), timing)
		}
		if expiredCalls.Load() != 1 || refreshCalls.Load() != 1 || recordCalls.Load() != 1 {
			t.Fatalf("calls expired=%d refresh=%d records=%d", expiredCalls.Load(), refreshCalls.Load(), recordCalls.Load())
		}
		expired.Close()
		fresh.Close()
		control.Close()
	}
}

func TestV3PlaybackOverloadBeforeUpstream(t *testing.T) {
	_, meta := v3PlaybackFixture(t, []byte("a"), 8, false)
	if !v3PlaybackMemory.TryAcquire(v3PlaybackMemoryBytes) {
		t.Fatal("unexpected active playback")
	}
	defer v3PlaybackMemory.Release(v3PlaybackMemoryBytes)
	p := &ProxyServer{streamClient: &http.Client{Transport: v3PlaybackRoundTripFunc(func(*http.Request) (*http.Response, error) { t.Error("overload reached upstream"); return nil, io.EOF })}}
	w := httptest.NewRecorder()
	err := p.serveV3Playback(w, httptest.NewRequest("GET", "http://client/", nil), v3PlaybackInfo("http://unused/"), meta)
	if err == nil || w.Code != 503 || w.Header().Get("Retry-After") == "" || w.Body.Len() != 0 {
		t.Fatalf("err=%v status=%d headers=%v", err, w.Code, w.Header())
	}
}
