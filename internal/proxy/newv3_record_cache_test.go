package proxy

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/playbacktest"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

func v3VerifiedRequest(meta encryption.ContentMeta, interval, auth, cookie string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/file", nil)
	req.Header.Set("Range", interval)
	req = req.WithContext(WithContentMeta(req.Context(), meta))
	return req.WithContext(WithV3CacheAuthorization(req.Context(), auth, cookie))
}

func TestRootV3TinyRangesReuseAuthenticatedRecord(t *testing.T) {
	plain := bytes.Repeat([]byte("authenticated-record"), 20)
	container, meta := buildV3Container(t, "cache-pw", 64, plain)
	up := playbacktest.New(container, playbacktest.Behavior{Range: playbacktest.RangeAccept}, nil)
	defer up.Close()
	sp := NewStreamProxy(config.DefaultConfig())
	passwd := &config.PasswdInfo{Enable: true, Password: "cache-pw", EncType: "aesctr"}
	for _, r := range []struct {
		header     string
		start, end int
	}{{"bytes=0-1", 0, 2}, {"bytes=62-63", 62, 64}} {
		rr := httptest.NewRecorder()
		out := sp.ProxyDownloadDecryptWithStrategy(rr, v3VerifiedRequest(meta, r.header, "", ""), up.URL("/file"), passwd, meta.PlainSize, StreamStrategyRange)
		if out.Err != nil || rr.Code != 206 || !bytes.Equal(rr.Body.Bytes(), plain[r.start:r.end]) {
			t.Fatalf("%s: %+v body=%x", r.header, out, rr.Body.Bytes())
		}
	}
	if snap := up.Snapshot(); snap.RequestCount != 1 {
		t.Fatalf("same record refetched: %+v", snap)
	}
}

func TestRootV3CachedPrefixExactTailAndFirstAuthFailure(t *testing.T) {
	for _, tamper := range []bool{false, true} {
		t.Run(fmt.Sprint(tamper), func(t *testing.T) {
			plain := bytes.Repeat([]byte("prefix-tail"), 30)
			container, meta := buildV3Container(t, "prefix-pw", 64, plain)
			bad := append([]byte(nil), container...)
			if tamper {
				bad[meta.HeaderLen+80] ^= 1
			}
			sp := NewStreamProxy(config.DefaultConfig())
			passwd := &config.PasswdInfo{Enable: true, Password: "prefix-pw", EncType: "aesctr"}
			fetches := 0
			var lastRange string
			sp.client = newTestClient(func(req *http.Request) (*http.Response, error) {
				fetches++
				lastRange = req.Header.Get("Range")
				data := container
				if fetches > 1 {
					data = bad
				}
				return rangeAwareRoundTripper(data)(req)
			})
			target := "http://prefix.test/" + fmt.Sprint(tamper)
			rr := httptest.NewRecorder()
			out := sp.ProxyDownloadDecryptWithStrategy(rr, v3VerifiedRequest(meta, "bytes=0-1", "", ""), target, passwd, meta.PlainSize, StreamStrategyRange)
			if out.Err != nil {
				t.Fatal(out.Err)
			}
			rr = httptest.NewRecorder()
			out = sp.ProxyDownloadDecryptWithStrategy(rr, v3VerifiedRequest(meta, "bytes=0-", "", ""), target, passwd, meta.PlainSize, StreamStrategyRange)
			if fetches != 2 || lastRange != buildUpstreamRangeHeader(fmt.Sprintf("bytes=64-%d", len(plain)-1), meta) {
				t.Fatalf("fetches=%d tail=%s", fetches, lastRange)
			}
			if tamper {
				if out.Err == nil || out.ResponseStarted || rr.Body.Len() != 0 {
					t.Fatalf("prefix committed before tail authentication: %+v", out)
				}
				key, ok := v3CacheIdentity(v3VerifiedRequest(meta, "bytes=0-", "", ""), target, passwd, meta, "")
				if !ok {
					t.Fatal("identity missing")
				}
				if l, hit := rootV3RecordCache.Get(key, 1); hit {
					l.Release()
					t.Fatal("tampered record cached")
				}
			} else if out.Err != nil || rr.Code != 206 || !bytes.Equal(rr.Body.Bytes(), plain) || out.ExpectedBytes != int64(len(plain)) {
				t.Fatalf("tail mismatch: %+v body=%x", out, rr.Body.Bytes())
			}
		})
	}
}

func TestRootV3RecordIdentityAuthorizationAndGeometryIsolation(t *testing.T) {
	_, meta := buildV3Container(t, "identity-pw", 64, bytes.Repeat([]byte("x"), 100))
	passwd := &config.PasswdInfo{Enable: true, Password: "identity-pw"}
	req := v3VerifiedRequest(meta, "bytes=0-1", "Bearer alice", "cookie")
	base, ok := v3CacheIdentity(req, "https://provider.test/signed?token=a", passwd, meta, "object")
	if !ok {
		t.Fatal("valid identity disabled")
	}
	changes := []struct {
		name  string
		apply func(*http.Request, *config.PasswdInfo, *encryption.ContentMeta) (string, string)
	}{
		{"url", func(*http.Request, *config.PasswdInfo, *encryption.ContentMeta) (string, string) {
			return "https://provider.test/signed?token=b", "object"
		}},
		{"provider", func(*http.Request, *config.PasswdInfo, *encryption.ContentMeta) (string, string) {
			return "https://other.test/signed?token=a", "object"
		}},
		{"object", func(*http.Request, *config.PasswdInfo, *encryption.ContentMeta) (string, string) {
			return "https://provider.test/signed?token=a", "other"
		}},
		{"password", func(_ *http.Request, p *config.PasswdInfo, _ *encryption.ContentMeta) (string, string) {
			p.Password = "different"
			return "https://provider.test/signed?token=a", "object"
		}},
		{"nonce", func(_ *http.Request, _ *config.PasswdInfo, m *encryption.ContentMeta) (string, string) {
			m.NonceField = append([]byte(nil), m.NonceField...)
			m.NonceField[0] ^= 1
			return "https://provider.test/signed?token=a", "object"
		}},
		{"kdf", func(_ *http.Request, _ *config.PasswdInfo, m *encryption.ContentMeta) (string, string) {
			m.KDFIterations++
			return "https://provider.test/signed?token=a", "object"
		}},
		{"chunk", func(_ *http.Request, _ *config.PasswdInfo, m *encryption.ContentMeta) (string, string) {
			m.ChunkSize = 32
			m.CiphertextSize = m.HeaderLen + 4*(32+16) + 16
			return "https://provider.test/signed?token=a", "object"
		}},
		{"plain-size", func(_ *http.Request, _ *config.PasswdInfo, m *encryption.ContentMeta) (string, string) {
			m.PlainSize--
			return "https://provider.test/signed?token=a", "object"
		}},
		{"provider-header", func(r *http.Request, _ *config.PasswdInfo, _ *encryption.ContentMeta) (string, string) {
			r.Header.Set("X-Provider-Token", "other")
			return "https://provider.test/signed?token=a", "object"
		}},
	}
	for _, tc := range changes {
		t.Run(tc.name, func(t *testing.T) {
			r := req.Clone(req.Context())
			p := *passwd
			m := meta
			target, object := tc.apply(r, &p, &m)
			key, ok := v3CacheIdentity(r, target, &p, m, object)
			if !ok || key == base {
				t.Fatalf("identity not isolated: ok=%v", ok)
			}
		})
	}
	for _, auth := range []string{"Bearer bob", ""} {
		r := v3VerifiedRequest(meta, "bytes=0-1", auth, "cookie")
		key, ok := v3CacheIdentity(r, "https://provider.test/signed?token=a", passwd, meta, "object")
		if !ok || key == base {
			t.Fatal("originating authorization leaked")
		}
	}
	unknown := httptest.NewRequest("GET", "/file", nil)
	if _, ok := v3CacheIdentity(unknown, "https://provider.test/signed?token=a", passwd, meta, "object"); ok {
		t.Fatal("unknown authorization scope enabled cache")
	}
}

// Measures actual loopback ciphertext body bytes, not a chunk-size arithmetic
// estimate or response-header latency. Existing files retain their own geometry.
func TestRootV3TinySeekActualByteAmplificationOneVersusSixteenMiB(t *testing.T) {
	for _, chunk := range []int64{1 << 20, 16 << 20} {
		t.Run(fmt.Sprint(chunk), func(t *testing.T) {
			plain := []byte("tiny seek amplification")
			container, meta := buildV3Container(t, "amplification-pw", chunk, plain)
			up := playbacktest.New(container, playbacktest.Behavior{Range: playbacktest.RangeAccept}, nil)
			defer up.Close()
			sp := NewStreamProxy(config.DefaultConfig())
			passwd := &config.PasswdInfo{Enable: true, Password: "amplification-pw"}
			for i := 0; i < 2; i++ {
				rr := httptest.NewRecorder()
				out := sp.ProxyDownloadDecryptWithStrategy(rr, v3VerifiedRequest(meta, "bytes=0-1", "", ""), up.URL("/file"), passwd, meta.PlainSize, StreamStrategyRange)
				if out.Err != nil || !bytes.Equal(rr.Body.Bytes(), plain[:2]) {
					t.Fatalf("tiny seek: %+v", out)
				}
			}
			snap := up.Snapshot()
			if snap.RequestCount != 1 || snap.BodyBytes != chunk+16 {
				t.Fatalf("actual amplification: chunk=%d snapshot=%+v", chunk, snap)
			}
			t.Logf("chunk_bytes=%d requested_plain_bytes=2 cold_cipher_body_bytes=%d warm_cipher_body_bytes=0", chunk, snap.BodyBytes)
		})
	}
}

func TestRootV3RecordLoaderAlignsPastCachedRecords(t *testing.T) {
	raw := bytes.Repeat([]byte{1}, 80)
	raw = append(raw, bytes.Repeat([]byte{2}, 80)...)
	raw = append(raw, bytes.Repeat([]byte{3}, 80)...)
	req := httptest.NewRequest("GET", "/file", nil)
	loader := sequentialV3Loader(bytes.NewReader(raw), 0, 64)
	first, err := loader(req.Context(), 0)
	if err != nil || first[0] != 1 {
		t.Fatal("first", err)
	}
	third, err := loader(req.Context(), 2)
	if err != nil || third[0] != 3 {
		t.Fatal("cached middle alignment", err)
	}
	if _, err := loader(req.Context(), 1); err == nil {
		t.Fatal("backward load accepted")
	}
}
