package encrypt

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	core "github.com/alist-encrypt-go/shared/encryptcore"
)

// Use only the shared writer/AEAD implementation, never a mobile crypto copy.
func legacyV3Fixture(t *testing.T, plain []byte, fixed bool) []byte {
	t.Helper()
	var b bytes.Buffer
	writer, err := core.NewV3Writer(&b, "legacy-test-password", 64)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = writer.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	data := b.Bytes()
	if fixed {
		header, err := core.NewV3Header(int64(len(plain)), writer.NonceField(), 64, 600000)
		if err != nil {
			t.Fatal(err)
		}
		data = append(header, data[48:len(data)-16]...)
	}
	return data
}

func legacyV3Proxy(t *testing.T, upstream *httptest.Server) *ProxyServer {
	t.Helper()
	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, portText, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ProxyConfig{AlistHost: host, AlistPort: port, PlayFirstFallback: true,
		EncryptPaths: []*EncryptPath{{Path: "/enc/*", Enable: true, EncType: EncTypeAESCTR, Password: "legacy-test-password", regex: regexp.MustCompile(`^/enc/`)}}}
	// No constructor: these route tests must not start background workers/SQLite.
	return &ProxyServer{config: cfg, httpClient: upstream.Client(), probeClient: upstream.Client(), streamClient: upstream.Client()}
}

func legacyV3Route(p *ProxyServer, route string) http.HandlerFunc {
	switch route {
	case "/dav2":
		return p.handleWebDAVV2
	case "/dav":
		return p.handleWebDAV
	default:
		return p.handleDownload
	}
}

func TestV3LegacyRoutesPlaintext(t *testing.T) {
	plain := bytes.Repeat([]byte("legacy-v3-content!"), 13)
	for _, fixed := range []bool{false, true} {
		fixture := legacyV3Fixture(t, plain, fixed)
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer route-test" {
				http.Error(w, "unauthorized", 401)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			http.ServeContent(w, r, "object", time.Time{}, bytes.NewReader(fixture))
		}))
		for _, route := range []string{"/d", "/p", "/dav", "/dav2"} {
			cases := []struct {
				method, rangeText string
				start, end        int
				status            int
			}{
				{"GET", "", 0, len(plain) - 1, 200},
				{"GET", "bytes=60-140", 60, 140, 206},
				{"GET", "bytes=64-", 64, len(plain) - 1, 206},
				{"GET", "bytes=-9", len(plain) - 9, len(plain) - 1, 206},
				{"HEAD", "", 0, len(plain) - 1, 200},
				{"HEAD", "bytes=60-140", 60, 140, 206},
				{"GET", "bytes=9999-", 0, -1, 416},
			}
			for _, tc := range cases {
				t.Run(fmt.Sprintf("fixed=%v%s/%s/%s", fixed, route, tc.method, tc.rangeText), func(t *testing.T) {
					p := legacyV3Proxy(t, upstream)
					// A stale partial cache must not cause ciphertext-size plaintext headers.
					p.storeFileCache("/enc/object", &FileInfo{Size: int64(len(fixture)), ContentVersion: ContentVersionV1})
					r := httptest.NewRequest(tc.method, "http://proxy.local"+route+"/enc/object", nil)
					r.Header.Set("Authorization", "Bearer route-test")
					if tc.rangeText != "" {
						r.Header.Set("Range", tc.rangeText)
					}
					w := httptest.NewRecorder()
					legacyV3Route(p, route)(w, r)
					if w.Code != tc.status {
						t.Fatalf("status=%d headers=%v body=%q", w.Code, w.Header(), w.Body.String())
					}
					if tc.status == 416 {
						if got := w.Header().Get("Content-Range"); got != fmt.Sprintf("bytes */%d", len(plain)) {
							t.Fatalf("Content-Range=%q", got)
						}
						return
					}
					if got := w.Header().Get("Content-Length"); got != strconv.Itoa(tc.end-tc.start+1) {
						t.Fatalf("Content-Length=%q", got)
					}
					if tc.status == 206 {
						want := fmt.Sprintf("bytes %d-%d/%d", tc.start, tc.end, len(plain))
						if got := w.Header().Get("Content-Range"); got != want {
							t.Fatalf("Content-Range=%q want=%q", got, want)
						}
					}
					if tc.method == "HEAD" {
						if w.Body.Len() != 0 {
							t.Fatal("HEAD emitted body")
						}
					} else if !bytes.Equal(w.Body.Bytes(), plain[tc.start:tc.end+1]) {
						t.Fatalf("not exact plaintext: %q", w.Body.Bytes())
					}
				})
			}
		}
		upstream.Close()
	}
}

func TestV3LegacyRedirectEngineDisabled(t *testing.T) {
	plain := []byte("redirect legacy authenticated plaintext")
	fixture := legacyV3Fixture(t, plain, false)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer route-test" {
			http.Error(w, "unauthorized", 401)
			return
		}
		http.ServeContent(w, r, "object", time.Time{}, bytes.NewReader(fixture))
	}))
	defer upstream.Close()
	p := legacyV3Proxy(t, upstream)
	p.storeRedirectCache("legacy-v3", &RedirectInfo{RedirectURL: upstream.URL + "/object", OriginalURL: "/enc/object", EncryptedPath: "/enc/object", PasswdInfo: p.config.EncryptPaths[0], Headers: http.Header{"Authorization": {"Bearer route-test"}}})
	w := httptest.NewRecorder()
	p.handleRedirectLegacy(w, httptest.NewRequest("GET", "http://proxy.local/redirect/legacy-v3?decode=1", nil))
	if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), plain) {
		t.Fatalf("legacy redirect status=%d body=%q", w.Code, w.Body.String())
	}
}

func TestV3LegacyRoutesCachedV3ProbeFailureIsTerminal(t *testing.T) {
	for _, route := range []string{"/d", "/p", "/dav", "/dav2"} {
		t.Run(route, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "probe unavailable", http.StatusServiceUnavailable)
			}))
			defer upstream.Close()
			p := legacyV3Proxy(t, upstream)
			p.storeFileCache("/enc/object", &FileInfo{ContentVersion: ContentVersionV3})
			w := httptest.NewRecorder()
			legacyV3Route(p, route)(w, httptest.NewRequest("GET", "http://proxy.local"+route+"/enc/object", nil))
			if w.Code != http.StatusBadGateway || w.Body.Len() != 0 {
				t.Fatalf("cached V3 was not terminal: status=%d body=%q", w.Code, w.Body.String())
			}
		})
	}
}

func TestV3LegacyRoutesUnconfirmedPrefixIsTerminal(t *testing.T) {
	for _, route := range []string{"/d", "/p", "/dav", "/dav2"} {
		for _, mode := range []string{"unauthorized", "encoded", "short"} {
			t.Run(route+"/"+mode, func(t *testing.T) {
				calls := 0
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls++
					if mode == "unauthorized" {
						http.Error(w, "unauthorized", http.StatusUnauthorized)
						return
					}
					if mode == "encoded" {
						w.Header().Set("Content-Encoding", "gzip")
					}
					w.Header().Set("Content-Range", "bytes 0-47/1024")
					w.WriteHeader(http.StatusPartialContent)
					if mode == "short" {
						_, _ = w.Write([]byte("V3G"))
					} else {
						_, _ = w.Write(bytes.Repeat([]byte{0xa5}, 48))
					}
				}))
				defer upstream.Close()
				p := legacyV3Proxy(t, upstream)
				w := httptest.NewRecorder()
				legacyV3Route(p, route)(w, httptest.NewRequest("GET", "http://proxy.local"+route+"/enc/object", nil))
				if w.Code != http.StatusBadGateway || w.Body.Len() != 0 || calls != 1 {
					t.Fatalf("unconfirmed prefix escaped: status=%d body=%q calls=%d", w.Code, w.Body.String(), calls)
				}
			})
		}
	}
}

func TestV3LegacyRoutesEmptyInvalidAndRaw(t *testing.T) {
	empty := legacyV3Fixture(t, nil, false)
	valid := legacyV3Fixture(t, []byte("raw representation"), false)
	bad := append([]byte(nil), valid...)
	bad[36] = 1 // Invalid raw tag size remains recognized V3.
	for _, route := range []string{"/d", "/p", "/dav", "/dav2"} {
		for _, tc := range []struct {
			name   string
			data   []byte
			query  string
			status int
		}{
			{"empty", empty, "", 200}, {"invalid", bad, "", 502}, {"raw", valid, "?decode=0", 200},
		} {
			t.Run(route+"/"+tc.name, func(t *testing.T) {
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/octet-stream")
					http.ServeContent(w, r, "object", time.Time{}, bytes.NewReader(tc.data))
				}))
				defer upstream.Close()
				p := legacyV3Proxy(t, upstream)
				w := httptest.NewRecorder()
				legacyV3Route(p, route)(w, httptest.NewRequest("GET", "http://proxy.local"+route+"/enc/object"+tc.query, nil))
				if w.Code != tc.status {
					t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
				}
				switch tc.name {
				case "empty":
					if w.Body.Len() != 0 || w.Header().Get("Content-Length") != "0" {
						t.Fatalf("empty response: %v %q", w.Header(), w.Body.String())
					}
				case "invalid":
					if strings.Contains(w.Body.String(), "V3GCM3") {
						t.Fatal("invalid V3 escaped as ciphertext")
					}
				case "raw":
					if !bytes.Equal(w.Body.Bytes(), valid) {
						t.Fatal("decode=0 changed ciphertext")
					}
				}
			})
		}
	}
}
