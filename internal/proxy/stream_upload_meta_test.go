package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/encryption"
)

func TestUploadMetaIsPartitionedByFilePathConcurrently(t *testing.T) {
	sp := NewStreamProxy(config.DefaultConfig())
	targetURL := "http://upstream.local/api/fs/put?part=1"
	pathA := "/encrypt/a file.bin"
	pathB := "/encrypt/b file.bin"
	metaA := encryption.ContentMeta{
		EncType:        encryption.EncTypeAESCTR,
		Version:        encryption.ContentVersionV2,
		HeaderLen:      encryption.ContentHeaderSize(),
		PlainSize:      128,
		CiphertextSize: 128 + encryption.ContentHeaderSize(),
		NonceField:     bytes.Repeat([]byte{0xA1}, 16),
	}
	metaB := metaA
	metaB.NonceField = bytes.Repeat([]byte{0xB2}, 16)

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			sp.putUploadMeta(targetURL, url.QueryEscape(pathA), metaA)
		}()
		go func() {
			defer wg.Done()
			sp.putUploadMeta(targetURL, url.QueryEscape(pathB), metaB)
		}()
	}
	wg.Wait()

	gotA, ok := sp.getUploadMeta("http://upstream.local/api/fs/put?part=2", pathA)
	if !ok || !bytes.Equal(gotA.NonceField, metaA.NonceField) {
		t.Fatalf("file A metadata collision: ok=%v nonce=%x", ok, gotA.NonceField)
	}
	gotB, ok := sp.getUploadMeta("http://upstream.local/api/fs/put?part=3", pathB)
	if !ok || !bytes.Equal(gotB.NonceField, metaB.NonceField) {
		t.Fatalf("file B metadata collision: ok=%v nonce=%x", ok, gotB.NonceField)
	}
	if uploadMetaKey(targetURL, pathA) == uploadMetaKey(targetURL, pathB) {
		t.Fatal("different File-Path values produced the same upload metadata key")
	}
}

func TestGetUploadMetaRefreshesTTL(t *testing.T) {
	sp := NewStreamProxy(config.DefaultConfig())
	targetURL := "http://upstream.local/api/fs/put"
	filePath := "/encrypt/refresh.bin"
	meta := encryption.ContentMeta{
		EncType:    encryption.EncTypeAESCTR,
		Version:    encryption.ContentVersionV2,
		HeaderLen:  encryption.ContentHeaderSize(),
		PlainSize:  64,
		NonceField: bytes.Repeat([]byte{0x42}, 16),
	}
	sp.putUploadMeta(targetURL, filePath, meta)

	key := uploadMetaKey(targetURL, filePath)
	soon := time.Now().Add(time.Second)
	sp.uploadMetaMu.Lock()
	entry := sp.uploadMeta[key]
	entry.ExpiresAt = soon
	sp.uploadMeta[key] = entry
	sp.uploadMetaMu.Unlock()

	if _, ok := sp.getUploadMeta(targetURL, filePath); !ok {
		t.Fatal("expected upload metadata before its original expiry")
	}
	sp.uploadMetaMu.Lock()
	refreshed := sp.uploadMeta[key].ExpiresAt
	sp.uploadMetaMu.Unlock()
	if !refreshed.After(soon.Add(uploadMetaTTL / 2)) {
		t.Fatalf("metadata TTL was not refreshed: old=%v new=%v", soon, refreshed)
	}
}

func TestResumedAPIUploadFailsClosedWithoutV2Metadata(t *testing.T) {
	for _, tc := range []struct {
		name       string
		seedExpiry bool
	}{
		{name: "missing"},
		{name: "expired", seedExpiry: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sp := NewStreamProxy(config.DefaultConfig())
			targetURL := "http://upstream.local/api/fs/put"
			filePath := "/encrypt/resume.bin"
			if tc.seedExpiry {
				meta := encryption.ContentMeta{
					EncType:    encryption.EncTypeAESCTR,
					Version:    encryption.ContentVersionV2,
					HeaderLen:  encryption.ContentHeaderSize(),
					PlainSize:  64,
					NonceField: bytes.Repeat([]byte{0x33}, 16),
				}
				sp.putUploadMeta(targetURL, filePath, meta)
				key := uploadMetaKey(targetURL, filePath)
				sp.uploadMetaMu.Lock()
				entry := sp.uploadMeta[key]
				entry.ExpiresAt = time.Now().Add(-time.Second)
				sp.uploadMeta[key] = entry
				sp.uploadMetaMu.Unlock()
			}

			var upstreamCalls atomic.Int32
			sp.client = newTestClient(func(r *http.Request) (*http.Response, error) {
				upstreamCalls.Add(1)
				return nil, nil
			})
			req := httptest.NewRequest(http.MethodPut, "/api/fs/put", strings.NewReader("second chunk"))
			req.Header.Set("File-Path", url.QueryEscape(filePath))
			req.Header.Set("Content-Range", "bytes 32-43/64")
			err := sp.ProxyUploadEncrypt(
				httptest.NewRecorder(),
				req,
				targetURL,
				&config.PasswdInfo{Password: "123456", EncType: "aesctr", Enable: true},
				64,
				32,
			)
			if err == nil || !strings.Contains(err.Error(), "missing V2 upload metadata") {
				t.Fatalf("error=%v, want missing V2 upload metadata", err)
			}
			if calls := upstreamCalls.Load(); calls != 0 {
				t.Fatalf("unsafe resumed upload reached upstream %d times", calls)
			}
		})
	}
}

func TestResumedWebDAVUploadFailsClosedWhenMetadataProbeIsInconclusive(t *testing.T) {
	sp := NewStreamProxy(config.DefaultConfig())
	var getCalls atomic.Int32
	var putCalls atomic.Int32
	sp.client = newTestClient(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodGet {
			getCalls.Add(1)
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("probe failed")),
				Request:    r,
			}, nil
		}
		putCalls.Add(1)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("{}")),
			Request:    r,
		}, nil
	})

	req := httptest.NewRequest(http.MethodPut, "/dav/resume.bin", strings.NewReader("second chunk"))
	req.Header.Set("Content-Range", "bytes 32-43/64")
	err := sp.ProxyUploadEncrypt(
		httptest.NewRecorder(),
		req,
		"http://upstream.local/dav/resume.bin",
		&config.PasswdInfo{Password: "123456", EncType: "aesctr", Enable: true},
		64,
		32,
	)
	if err == nil || !strings.Contains(err.Error(), "cannot determine encryption metadata") {
		t.Fatalf("error=%v, want inconclusive metadata failure", err)
	}
	if getCalls.Load() != 1 || putCalls.Load() != 0 {
		t.Fatalf("probe/upload calls=%d/%d, want 1/0", getCalls.Load(), putCalls.Load())
	}
}

func TestCompletedResumedUploadDeletesCachedV2Metadata(t *testing.T) {
	sp := NewStreamProxy(config.DefaultConfig())
	targetURL := "http://upstream.local/api/fs/put"
	filePath := "/encrypt/complete.bin"
	meta := encryption.ContentMeta{
		EncType:        encryption.EncTypeAESCTR,
		Version:        encryption.ContentVersionV2,
		HeaderLen:      encryption.ContentHeaderSize(),
		PlainSize:      64,
		CiphertextSize: 64 + encryption.ContentHeaderSize(),
		NonceField:     bytes.Repeat([]byte{0x51}, 16),
	}
	sp.putUploadMeta(targetURL, filePath, meta)
	sp.client = newTestClient(func(r *http.Request) (*http.Response, error) {
		_, _ = io.Copy(io.Discard, r.Body)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("{}")),
			Request:    r,
		}, nil
	})

	req := httptest.NewRequest(http.MethodPut, "/api/fs/put", strings.NewReader(strings.Repeat("x", 32)))
	req.Header.Set("File-Path", url.QueryEscape(filePath))
	req.Header.Set("Content-Range", "bytes 32-63/64")
	err := sp.ProxyUploadEncrypt(
		httptest.NewRecorder(),
		req,
		targetURL,
		&config.PasswdInfo{Password: "123456", EncType: "aesctr", Enable: true},
		64,
		32,
	)
	if err != nil {
		t.Fatalf("complete resumed upload: %v", err)
	}
	if _, ok := sp.getUploadMeta(targetURL, filePath); ok {
		t.Fatal("completed upload retained V2 metadata and nonce")
	}
}

func TestUploadRejectsContentRangeBodyLengthMismatchBeforeUpstream(t *testing.T) {
	sp := NewStreamProxy(config.DefaultConfig())
	var upstreamCalls atomic.Int32
	sp.client = newTestClient(func(r *http.Request) (*http.Response, error) {
		upstreamCalls.Add(1)
		return nil, nil
	})
	req := httptest.NewRequest(http.MethodPut, "/api/fs/put", strings.NewReader("short"))
	req.Header.Set("Content-Range", "bytes 0-9/64")
	err := sp.ProxyUploadEncrypt(
		httptest.NewRecorder(),
		req,
		"http://upstream.local/api/fs/put",
		&config.PasswdInfo{Password: "123456", EncType: "aesctr", Enable: true},
		64,
		0,
	)
	if err == nil || !strings.Contains(err.Error(), "length does not match") {
		t.Fatalf("error=%v, want content range length rejection", err)
	}
	if upstreamCalls.Load() != 0 {
		t.Fatalf("invalid upload reached upstream %d times", upstreamCalls.Load())
	}
}
