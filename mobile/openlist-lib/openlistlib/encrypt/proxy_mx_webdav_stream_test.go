package encrypt

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func mxWebDAVFixture(t *testing.T, plain []byte, version int) []byte {
	t.Helper()
	var enc FlowEncryptor
	var header []byte
	var err error
	if version == ContentVersionV2 {
		nonce := bytes.Repeat([]byte{7}, 16)
		header, err = BuildV2Header(EncTypeAESCTR, int64(len(plain)), nonce)
		if err == nil {
			enc, err = NewCipherV2(EncTypeAESCTR, "legacy-test-password", int64(len(plain)), nonce)
		}
	} else {
		enc, err = NewFlowEncryptor("legacy-test-password", EncTypeAESCTR, int64(len(plain)))
	}
	if err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(NewEncryptReader(bytes.NewReader(plain), enc))
	if err != nil {
		t.Fatal(err)
	}
	return append(header, payload...)
}

// Real net/http clients enforce Content-Length. A recorder alone misses the
// former full V2 GET's unexpected EOF after its 32-byte container header was cut.
func TestMXWebDAVHTTPFraming(t *testing.T) {
	plain := []byte("small-MX-video-fixture-for-bounded-ranges")
	for _, version := range []int{ContentVersionV1, ContentVersionV2} {
		for _, redirect := range []bool{false, true} {
			for _, ignored := range []bool{false, true} {
				t.Run(fmt.Sprintf("v%d/redirect=%v/ignored=%v", version, redirect, ignored), func(t *testing.T) {
					fixture := mxWebDAVFixture(t, plain, version)
					upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if redirect && strings.HasPrefix(r.URL.Path, "/dav/") {
							w.Header().Set("Location", "/cipher")
							w.WriteHeader(http.StatusFound)
							return
						}
						w.Header().Set("Content-Type", "application/octet-stream")
						if ignored {
							w.Header().Set("Content-Length", strconv.Itoa(len(fixture)))
							if r.Method != http.MethodHead {
								_, _ = w.Write(fixture)
							}
							return
						}
						http.ServeContent(w, r, "cipher", time.Time{}, bytes.NewReader(fixture))
					}))
					defer upstream.Close()
					p := legacyV3Proxy(t, upstream)
					noRedirect := *upstream.Client()
					noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
					p.httpClient, p.streamClient, p.probeClient = &noRedirect, &noRedirect, &noRedirect
					p.storeFileCache("/enc/object", &FileInfo{Size: 99999, ContentVersion: ContentVersionV2, HeaderLen: 32, CiphertextSize: 100031, NonceField: bytes.Repeat([]byte{8}, 16)})
					proxy := httptest.NewServer(http.HandlerFunc(p.handleWebDAV))
					defer proxy.Close()
					client := proxy.Client()
					client.Timeout = 3 * time.Second
					client.CheckRedirect = noRedirect.CheckRedirect
					cases := []struct {
						method, rangeHeader string
						start, end, status  int
					}{
						{"GET", "", 0, len(plain) - 1, 200},
						{"HEAD", "", 0, len(plain) - 1, 200},
						{"GET", "bytes=0-3", 0, 3, 206},
						{"GET", "bytes=5-9", 5, 9, 206},
						{"GET", "bytes=5-", 5, len(plain) - 1, 206},
						{"GET", "bytes=-999", 0, len(plain) - 1, 206},
						{"GET", "bytes=-3", len(plain) - 3, len(plain) - 1, 206},
						{"HEAD", "bytes=-3", len(plain) - 3, len(plain) - 1, 206},
					}
					for _, tc := range cases {
						req, _ := http.NewRequest(tc.method, proxy.URL+"/dav/enc/object", nil)
						req.Header.Set("Range", tc.rangeHeader)
						resp, err := client.Do(req)
						if err != nil {
							t.Fatal(err)
						}
						got, readErr := io.ReadAll(resp.Body)
						resp.Body.Close()
						if readErr != nil {
							t.Fatalf("%s %q EOF framing: %v", tc.method, tc.rangeHeader, readErr)
						}
						if resp.StatusCode != tc.status || resp.ContentLength != int64(tc.end-tc.start+1) || resp.Header.Get("Location") != "" {
							t.Fatalf("%s %q status=%d CL=%d headers=%v body=%q", tc.method, tc.rangeHeader, resp.StatusCode, resp.ContentLength, resp.Header, got)
						}
						if tc.method == "HEAD" {
							if len(got) != 0 {
								t.Fatal("HEAD body")
							}
						} else if !bytes.Equal(got, plain[tc.start:tc.end+1]) {
							t.Fatalf("%q not exact plaintext: %q", tc.rangeHeader, got)
						}
						if tc.status == 206 && resp.Header.Get("Content-Range") != fmt.Sprintf("bytes %d-%d/%d", tc.start, tc.end, len(plain)) {
							t.Fatal(resp.Header)
						}
					}
				})
			}
		}
	}
}

func TestMXWebDAVIgnoredRangePrefixBudget(t *testing.T) {
	plain := []byte("bounded-prefix-budget-video")
	fixture := mxWebDAVFixture(t, plain, ContentVersionV2)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(fixture)))
		if r.Method != http.MethodHead {
			_, _ = w.Write(fixture)
		}
	}))
	defer upstream.Close()
	p := legacyV3Proxy(t, upstream)
	p.config.RangeSkipMaxBytes = 4
	proxy := httptest.NewServer(http.HandlerFunc(p.handleWebDAV))
	defer proxy.Close()
	req, _ := http.NewRequest("GET", proxy.URL+"/dav/enc/object", nil)
	req.Header.Set("Range", "bytes=5-9")
	resp, err := proxy.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	got, readErr := io.ReadAll(resp.Body)
	resp.Body.Close()
	if readErr != nil || resp.StatusCode != 416 || resp.Header.Get("Content-Range") != fmt.Sprintf("bytes */%d", len(plain)) {
		t.Fatalf("budget status=%d header=%v body=%q EOF=%v", resp.StatusCode, resp.Header, got, readErr)
	}
}

func TestMXWebDAVDecodeZeroPreservesFilenameMapping(t *testing.T) {
	plain := []byte("raw-read-fixture")
	fixture := mxWebDAVFixture(t, plain, ContentVersionV2)
	var expected string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != expected {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeContent(w, r, "cipher", time.Time{}, bytes.NewReader(fixture))
	}))
	defer upstream.Close()
	p := legacyV3Proxy(t, upstream)
	p.config.EncryptPaths[0].EncName = true
	expected = "/dav/enc/" + convertRealNameByRule(p.config.EncryptPaths[0], "/dav/enc/object")
	proxy := httptest.NewServer(http.HandlerFunc(p.handleWebDAV))
	defer proxy.Close()
	for _, method := range []string{"GET", "HEAD"} {
		req, _ := http.NewRequest(method, proxy.URL+"/dav/enc/object?decode=0", nil)
		resp, err := proxy.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		got, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil || resp.StatusCode != 200 || resp.ContentLength != int64(len(fixture)) {
			t.Fatalf("raw %s status=%d CL=%d err=%v", method, resp.StatusCode, resp.ContentLength, readErr)
		}
		if method == "GET" && !bytes.Equal(got, fixture) {
			t.Fatal("raw ciphertext changed")
		}
	}
}
