package proxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

func TestMediaIdentityPrefixV1V2AndNegative(t *testing.T) {
	for _, version := range []int{1, 2} {
		for _, brand := range []string{"mp42", "M4A "} {
			t.Run(fmt.Sprintf("v%d-%s", version, brand), func(t *testing.T) {
				pw := &config.PasswdInfo{Password: "media-prefix-test", EncType: "aesctr", Enable: true}
				plain := make([]byte, 20000)
				binary.BigEndian.PutUint32(plain, 20)
				copy(plain[4:], "ftyp")
				copy(plain[8:], brand)
				copy(plain[16:], "isom")
				cipher := mediaIdentityCipherFixture(t, pw, plain, version)
				var calls atomic.Int32
				origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					if r.Header.Get("Authorization") != "Basic test" || r.Header.Get("Accept-Encoding") != "identity" {
						t.Error("missing identity/auth headers")
					}
					w.Header().Set("ETag", "\"media-test\"")
					http.ServeContent(w, r, "encrypted", time.Time{}, bytes.NewReader(cipher))
				}))
				defer origin.Close()
				sp := NewStreamProxy(config.DefaultConfig())
				sp.client = &Client{Client: origin.Client()}
				out, err := sp.InspectDecryptedMediaPrefix(context.Background(), origin.URL+"/cipher?secret=token", http.Header{"Authorization": {"Basic test"}}, pw, int64(len(cipher)))
				if brand == "M4A " {
					if err == nil || out.Ext != "" {
						t.Fatalf("audio admitted: %+v %v", out, err)
					}
				} else if err != nil || out.Ext != ".mp4" || out.MIME != "video/mp4" || !out.Reusable || strings.Contains(out.ValidatorScope, "token") {
					t.Fatalf("result=%+v err=%v", out, err)
				}
				// One strict 48-byte V3 sniff, one legacy 32-byte metadata
				// probe, and one bounded payload probe (including the V2 header).
				if calls.Load() != 3 {
					t.Fatalf("requests=%d want3", calls.Load())
				}
			})
		}
	}
}

func mediaIdentityCipherFixture(t *testing.T, pw *config.PasswdInfo, plain []byte, version int) []byte {
	t.Helper()
	if version == 2 {
		enc, err := encryption.NewLatestContentEncryptor(pw.Password, pw.EncType, int64(len(plain)))
		if err != nil {
			t.Fatal(err)
		}
		r, err := enc.EncryptReader(bytes.NewReader(plain), 0)
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	c, err := encryption.NewCipher(encryption.EncTypeAESCTR, pw.Password, int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}
	b := append([]byte(nil), plain...)
	c.Encrypt(b)
	return b
}

func TestMediaIdentityRejectsChangedRangeAndBoundsIgnoredRange(t *testing.T) {
	pw := &config.PasswdInfo{Password: "media-prefix-test", EncType: "aesctr", Enable: true}
	plain := make([]byte, 20000)
	binary.BigEndian.PutUint32(plain, 20)
	copy(plain[4:], "ftypmp42")
	copy(plain[16:], "isom")
	blob := mediaIdentityCipherFixture(t, pw, plain, 2)
	for _, bad := range []bool{false, true} {
		t.Run(fmt.Sprint(bad), func(t *testing.T) {
			sp := NewStreamProxy(config.DefaultConfig())
			var readBytes atomic.Int64
			sp.client = newTestClient(func(r *http.Request) (*http.Response, error) {
				if r.Header.Get("Range") == "bytes=0-47" {
					return &http.Response{StatusCode: 206, Header: http.Header{"Content-Range": {fmt.Sprintf("bytes 0-47/%d", len(blob))}}, ContentLength: 48, Body: io.NopCloser(&mediaIdentityCountReader{Reader: bytes.NewReader(blob[:48]), count: &readBytes}), Request: r}, nil
				}
				if r.Header.Get("Range") == "bytes=0-31" {
					return &http.Response{StatusCode: 206, Header: http.Header{"Content-Range": {fmt.Sprintf("bytes 0-31/%d", len(blob))}}, ContentLength: 32, Body: io.NopCloser(bytes.NewReader(blob[:32])), Request: r}, nil
				}
				if r.Header.Get("Range") != "bytes=0-4127" {
					t.Fatalf("payload range=%q", r.Header.Get("Range"))
				}
				if bad {
					return &http.Response{StatusCode: 206, Header: http.Header{"Content-Range": {fmt.Sprintf("bytes 0-4127/%d", len(blob)+1)}}, ContentLength: 4128, Body: io.NopCloser(bytes.NewReader(blob[:4128])), Request: r}, nil
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), ContentLength: int64(len(blob)), Body: io.NopCloser(&mediaIdentityCountReader{Reader: bytes.NewReader(blob), count: &readBytes}), Request: r}, nil
			})
			out, err := sp.InspectDecryptedMediaPrefix(context.Background(), "http://example.test/video", nil, pw, int64(len(blob)))
			if bad {
				if err == nil {
					t.Fatal("changed total accepted")
				}
			} else {
				if err != nil || out.Ext != ".mp4" {
					t.Fatalf("%+v %v", out, err)
				}
				if readBytes.Load() != 4176 {
					t.Fatalf("read=%d want4176 (48-byte sniff + 4128-byte ignored-Range prefix)", readBytes.Load())
				}
			}
		})
	}
}

type mediaIdentityCountReader struct {
	io.Reader
	count *atomic.Int64
}

func (r *mediaIdentityCountReader) Read(b []byte) (int, error) {
	n, err := r.Reader.Read(b)
	r.count.Add(int64(n))
	return n, err
}

func TestMediaIdentityRejectsSameSizeNonceReplacement(t *testing.T) {
	pw := &config.PasswdInfo{Password: "media-prefix-test", EncType: "aesctr", Enable: true}
	plain := make([]byte, 5000)
	binary.BigEndian.PutUint32(plain, 20)
	copy(plain[4:], "ftypmp42")
	copy(plain[16:], "isom")
	first := mediaIdentityCipherFixture(t, pw, plain, 2)
	second := mediaIdentityCipherFixture(t, pw, plain, 2)
	if bytes.Equal(first[8:24], second[8:24]) {
		t.Fatal("fixture reused nonce")
	}
	sp := NewStreamProxy(config.DefaultConfig())
	sp.client = newTestClient(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Range") == "bytes=0-47" {
			return &http.Response{StatusCode: 206, Header: http.Header{"Content-Range": {fmt.Sprintf("bytes 0-47/%d", len(first))}}, ContentLength: 48, Body: io.NopCloser(bytes.NewReader(first[:48])), Request: r}, nil
		}
		if r.Header.Get("Range") == "bytes=0-31" {
			return &http.Response{StatusCode: 206, Header: http.Header{"Content-Range": {fmt.Sprintf("bytes 0-31/%d", len(first))}}, ContentLength: 32, Body: io.NopCloser(bytes.NewReader(first[:32])), Request: r}, nil
		}
		if r.Header.Get("Range") != "bytes=0-4127" {
			t.Fatalf("payload range=%q", r.Header.Get("Range"))
		}
		return &http.Response{StatusCode: 206, Header: http.Header{"Content-Range": {fmt.Sprintf("bytes 0-4127/%d", len(second))}}, ContentLength: 4128, Body: io.NopCloser(bytes.NewReader(second[:4128])), Request: r}, nil
	})
	if out, err := sp.InspectDecryptedMediaPrefix(context.Background(), "http://example.test/video", nil, pw, int64(len(first))); err == nil || out.Ext != "" {
		t.Fatalf("replacement admitted: %+v %v", out, err)
	}
}

func TestMediaIdentityCrossOriginRedirectAndCancellation(t *testing.T) {
	pw := &config.PasswdInfo{Password: "media-prefix-test", EncType: "aesctr", Enable: true}
	plain := make([]byte, 5000)
	binary.BigEndian.PutUint32(plain, 20)
	copy(plain[4:], "ftypmp42")
	copy(plain[16:], "isom")
	blob := mediaIdentityCipherFixture(t, pw, plain, 2)
	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("credentials leaked")
		}
		http.ServeContent(w, r, "video", time.Time{}, bytes.NewReader(blob))
	}))
	defer cdn.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, cdn.URL+"/video", 302) }))
	defer origin.Close()
	sp := NewStreamProxy(config.DefaultConfig())
	sp.client = &Client{Client: origin.Client()}
	headers := http.Header{"Authorization": {"Basic secret"}, "Cookie": {"session=secret"}}
	out, err := sp.InspectDecryptedMediaPrefix(context.Background(), origin.URL, headers, pw, int64(len(blob)))
	if err != nil || out.Ext != ".mp4" {
		t.Fatalf("out=%+v err=%v", out, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := sp.InspectDecryptedMediaPrefix(ctx, origin.URL, headers, pw, int64(len(blob))); err == nil {
		t.Fatal("cancelled inspection succeeded")
	}
}
