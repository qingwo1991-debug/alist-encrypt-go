package encrypt

import (
	"bytes"
	"context"
	"encoding/xml"
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
)

func mxPropfindXML(href string, size int64, collection bool) string {
	resource := ""
	if collection {
		resource = "<D:resourcetype><D:collection/></D:resourcetype>"
	}
	// Intentionally put href after getcontentlength.
	return fmt.Sprintf(`<D:multistatus xmlns:D="DAV:"><D:response><D:propstat><D:prop><D:getcontentlength>%d</D:getcontentlength>%s</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat><D:href>%s</D:href></D:response></D:multistatus>`, size, resource, href)
}
func mxXMLLength(t *testing.T, body []byte) int64 {
	t.Helper()
	var result struct {
		Response struct {
			Propstat struct {
				Prop struct {
					Length int64 `xml:"getcontentlength"`
				} `xml:"prop"`
			} `xml:"propstat"`
		} `xml:"response"`
	}
	if err := xml.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	return result.Response.Propstat.Prop.Length
}
func mxV2Data(t *testing.T, plain []byte) ([]byte, ContentMeta) {
	t.Helper()
	enc, err := NewLatestContentEncryptor("mx-password", string(EncTypeAESCTR), int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}
	reader, err := enc.EncryptReader(bytes.NewReader(plain), 0)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return data, enc.Meta
}

func TestMXWebDAVPropfindColdDepthZeroTailRoundTrip(t *testing.T) {
	plain := bytes.Repeat([]byte("real-tail-payload"), 64)
	data, _ := mxV2Data(t, plain)
	var probes, fileGETs atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dav/enc/movie.mp4" {
			http.NotFound(w, r)
			return
		}
		if r.Method == "PROPFIND" {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(207)
			io.WriteString(w, mxPropfindXML("/dav/enc/movie.mp4", int64(len(data)), false))
			return
		}
		if r.Method != http.MethodGet {
			t.Errorf("unexpected file method: %s", r.Method)
			http.Error(w, "unexpected file method", http.StatusMethodNotAllowed)
			return
		}
		fileGETs.Add(1)
		if r.Header.Get("Range") == "bytes=0-47" {
			probes.Add(1)
		}
		http.ServeContent(w, r, "movie.mp4", time.Time{}, bytes.NewReader(data))
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	host, port, _ := net.SplitHostPort(u.Host)
	portNum, _ := strconv.Atoi(port)
	p, err := NewProxyServer(&ProxyConfig{
		AlistHost: host, AlistPort: portNum,
		ProviderCatalogEnabled: false, ProviderCatalogTTLMinutes: 1, ProviderCatalogBootstrapOnStart: false,
		EncryptPaths: []*EncryptPath{{Path: "/enc/*", Password: "mx-password", EncType: EncTypeAESCTR, Enable: true, EncName: false}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	proxy := httptest.NewServer(http.HandlerFunc(p.handleWebDAVLegacy))
	defer proxy.Close()
	request, _ := http.NewRequest("PROPFIND", proxy.URL+"/dav/enc/movie.mp4", nil)
	request.Header.Set("Depth", "0")
	response, err := proxy.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 207 {
		t.Fatalf("status=%d body=%s", response.StatusCode, body)
	}
	length := mxXMLLength(t, body)
	if length != int64(len(plain)) || probes.Load() != 1 || fileGETs.Load() != 1 {
		t.Fatalf("length=%d want=%d headerProbes=%d fileGETs=%d", length, len(plain), probes.Load(), fileGETs.Load())
	}
	// MX's suffix-start derived from the actual advertised XML must return real
	// plaintext tail, not cipherEOF-12 (which is beyond plainEOF).
	request, _ = http.NewRequest("GET", proxy.URL+"/dav/enc/movie.mp4", nil)
	request.Header.Set("Range", fmt.Sprintf("bytes=%d-", length-12))
	response, err = proxy.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err = io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 206 || !bytes.Equal(body, plain[len(plain)-12:]) {
		t.Fatalf("tail status=%d body=%q", response.StatusCode, body)
	}
}

// mxPropfindTrustedFixture explicitly seeds a unit-test validated-inspection
// record. It is not a claim that a legacy FileInfo/listing proves the format.
func mxPropfindTrustedFixture(t *testing.T, p *ProxyServer, r *http.Request, href string, info *FileInfo, expired bool) {
	t.Helper()
	holder := confirmedMetadataRequestFromContext(r.Context())
	if holder == nil {
		t.Fatal("missing scoped directory identity")
	}
	id := holder.identity
	id.ObjectID = p.confirmedMetadataObjectID(href)
	now := time.Now()
	confirmedAt := now
	if expired {
		confirmedAt = now.Add(-confirmedMetadataMaxAge - time.Second)
	}
	rec := confirmedMetadataRecord{
		Identity: id, Provenance: confirmedMetadataProvenanceInspection,
		ConfirmedAt: confirmedAt.Unix(), ValidatedAt: confirmedAt.Unix(), Generation: 1,
		Meta: ContentMeta{EncType: EncTypeAESCTR, Version: info.ContentVersion,
			PlainSize: info.Size, CiphertextSize: info.CiphertextSize, HeaderLen: info.HeaderLen,
			NonceField: cloneNonceField(info.NonceField), ChunkSize: info.ChunkSize, KDFIterations: info.KDFIterations},
	}
	if !validConfirmedMetadataRecord(rec) {
		t.Fatal("trusted fixture must have valid complete geometry and provenance")
	}
	p.confirmedMetadata.mu.Lock()
	defer p.confirmedMetadata.mu.Unlock()
	entry := p.confirmedMetadata.ensureEntry(id, now)
	entry.record, entry.generation, entry.loaded = rec, 1, true
}

func TestMXWebDAVPropfindKnownAndUnknownMetadata(t *testing.T) {
	ep := &EncryptPath{Enable: true, EncType: EncTypeAESCTR}
	v2 := &FileInfo{Name: "movie.mp4", Path: "/dav/enc/movie.mp4", Size: 100, CiphertextSize: 132, ContentVersion: 2, HeaderLen: 32, NonceField: []byte("0123456789abcdef")}
	tests := []struct {
		name, href                   string
		raw, want                    int64
		info                         *FileInfo
		collection, expired, trusted bool
	}{
		{"confirmed v2", "/dav/enc/movie.mp4", 132, 100, v2, false, false, true},
		{"legacy v2 tuple untrusted", "/dav/enc/movie.mp4", 132, 132, v2, false, false, false},
		{"unknown no guessing", "/dav/enc/movie.mp4", 132, 132, nil, false, false, false},
		{"changed size", "/dav/enc/movie.mp4", 164, 164, v2, false, false, true},
		{"expired", "/dav/enc/movie.mp4", 132, 132, v2, false, true, true},
		{"collection", "/dav/enc/movie.mp4", 132, 132, v2, true, false, true},
		{"orig", "/dav/enc/orig_movie.mp4", 132, 132, v2, false, false, true},
		{"v1", "/dav/enc/movie.mp4", 100, 100, &FileInfo{Size: 100, CiphertextSize: 100, ContentVersion: 1}, false, false, true},
		{"unenc", "/dav/enc/movie.mp4", 132, 132, nil, false, false, false},
		{"incomplete tuple", "/dav/enc/movie.mp4", 132, 132, &FileInfo{Size: 100, CiphertextSize: 132, ContentVersion: 2, NonceField: []byte("0123456789abcdef")}, false, false, false},
		{"v3", "/dav/enc/movie.mp4", 112, 17, &FileInfo{Size: 17, CiphertextSize: 112, ContentVersion: 3, HeaderLen: 48, NonceField: []byte("0123456789abcdef"), ChunkSize: 16, KDFIterations: 1}, false, false, true},
		{"legacy v3 tuple untrusted", "/dav/enc/movie.mp4", 112, 112, &FileInfo{Size: 17, CiphertextSize: 112, ContentVersion: 3, HeaderLen: 48, NonceField: []byte("0123456789abcdef"), ChunkSize: 16, KDFIterations: 1}, false, false, false},
		{"invalid v3 tuple", "/dav/enc/movie.mp4", 112, 112, &FileInfo{Size: 17, CiphertextSize: 112, ContentVersion: 3, HeaderLen: 48, NonceField: []byte("0123456789abcdef"), ChunkSize: 0, KDFIterations: 1}, false, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &ProxyServer{config: &ProxyConfig{AlistHost: "upstream", AlistPort: 5244}}
			r := p.withConfirmedMetadataIdentity(httptest.NewRequest("PROPFIND", "http://proxy/dav/enc", nil), "/dav/enc", ep)
			if tc.trusted {
				mxPropfindTrustedFixture(t, p, r, tc.href, tc.info, tc.expired)
			}
			p.streamClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				t.Errorf("directory issued network request: %s", r.URL)
				return nil, fmt.Errorf("forbidden directory probe")
			})}
			if tc.info != nil {
				copy := *tc.info
				p.storeFileCacheList(tc.href, &copy)
				if tc.expired {
					key := normalizeCacheKey(tc.href)
					p.fileCache.Set(key, &CachedFileInfo{Info: &copy, ExpireAt: time.Now().Add(-time.Second)})
				}
			}
			var out bytes.Buffer
			if err := p.processPropfindMetadata(strings.NewReader(mxPropfindXML(tc.href, tc.raw, tc.collection)), &out, ep, nil, &propfindSizeProbe{ctx: r.Context()}); err != nil {
				t.Fatal(err)
			}
			if got := mxXMLLength(t, out.Bytes()); got != tc.want {
				t.Fatalf("length=%d want=%d XML=%s", got, tc.want, out.String())
			}
			if tc.name == "changed size" {
				info, _ := p.loadFileCacheInMem(tc.href)
				if info.ContentVersion != 0 || info.Size != tc.raw {
					t.Fatalf("stale tuple survived: %+v", info)
				}
			}
		})
	}
}

func TestMXWebDAVPropfindConfirmedMetadataRequiresRequestScope(t *testing.T) {
	ep := &EncryptPath{Enable: true, EncType: EncTypeAESCTR}
	p := &ProxyServer{config: &ProxyConfig{AlistHost: "upstream", AlistPort: 5244}}
	r := httptest.NewRequest("PROPFIND", "http://proxy/dav/enc", nil)
	r.Header.Set("Authorization", "Bearer fixture-owner")
	r = p.withConfirmedMetadataIdentity(r, "/dav/enc", ep)
	info := &FileInfo{Size: 100, CiphertextSize: 132, ContentVersion: 2, HeaderLen: 32, NonceField: []byte("0123456789abcdef")}
	mxPropfindTrustedFixture(t, p, r, "/dav/enc/movie.mp4", info, false)
	other := httptest.NewRequest("PROPFIND", "http://proxy/dav/enc", nil)
	other.Header.Set("Authorization", "Bearer fixture-other")
	other = p.withConfirmedMetadataIdentity(other, "/dav/enc", ep)
	for _, ctx := range []context.Context{context.Background(), other.Context()} {
		var out bytes.Buffer
		if err := p.processPropfindMetadata(strings.NewReader(mxPropfindXML("/dav/enc/movie.mp4", 132, false)), &out, ep, nil, &propfindSizeProbe{ctx: ctx}); err != nil {
			t.Fatal(err)
		}
		if got := mxXMLLength(t, out.Bytes()); got != 132 {
			t.Fatalf("missing/mismatched scope reused trusted size: %d", got)
		}
	}
}

func TestMXWebDAVPropfindDisabledContentDoesNotRewriteKnownSize(t *testing.T) {
	p := &ProxyServer{config: &ProxyConfig{}}
	ep := &EncryptPath{Enable: false, EncType: EncTypeAESCTR}
	p.storeFileCacheList("/dav/enc/movie.mp4", &FileInfo{Name: "movie.mp4", Size: 100, CiphertextSize: 132, ContentVersion: 2, HeaderLen: 32, NonceField: []byte("0123456789abcdef")})
	var out bytes.Buffer
	if err := p.processPropfindResponseBudget(strings.NewReader(mxPropfindXML("/dav/enc/movie.mp4", 132, false)), &out, ep, nil); err != nil {
		t.Fatal(err)
	}
	if got := mxXMLLength(t, out.Bytes()); got != 132 {
		t.Fatalf("disabled content changed raw length: %d", got)
	}
}

func TestMXWebDAVPropfindDirectoryNoNetworkAndSnapshotNoDoubleSubtract(t *testing.T) {
	ep := &EncryptPath{Enable: true, EncType: EncTypeAESCTR, EncName: true}
	p := &ProxyServer{config: &ProxyConfig{AlistHost: "upstream", AlistPort: 5244}}
	r := p.withConfirmedMetadataIdentity(httptest.NewRequest("PROPFIND", "http://proxy/dav/enc", nil), "/dav/enc", ep)
	p.streamClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		t.Errorf("directory issued network request: %s", r.URL)
		return nil, fmt.Errorf("forbidden directory probe")
	})}
	info := &FileInfo{Name: "movie.mp4", Size: 100, CiphertextSize: 132, ContentVersion: 2, HeaderLen: 32, NonceField: []byte("0123456789abcdef")}
	p.storeFileCacheList("/dav/enc/movie.mp4", info)
	mxPropfindTrustedFixture(t, p, r, "/dav/enc/movie.mp4", info, false)
	var first, second bytes.Buffer
	if err := p.processPropfindMetadata(strings.NewReader(mxPropfindXML("/dav/enc/movie.mp4", 132, false)), &first, ep, nil, &propfindSizeProbe{ctx: r.Context()}); err != nil {
		t.Fatal(err)
	}
	if err := p.processPropfindResponseSnapshot(bytes.NewReader(first.Bytes()), &second, ep, nil); err != nil {
		t.Fatal(err)
	}
	if mxXMLLength(t, first.Bytes()) != 100 || mxXMLLength(t, second.Bytes()) != 100 {
		t.Fatalf("double transformation: %s", second.String())
	}
	cached, _ := p.loadFileCacheInMem("/dav/enc/movie.mp4")
	if cached.CiphertextSize != 132 || cached.Size != 100 {
		t.Fatalf("snapshot destroyed tuple: %+v", cached)
	}
}

func TestMXWebDAVPropfindProbeCancellationAndExactObject(t *testing.T) {
	p := &ProxyServer{config: &ProxyConfig{}}
	var calls atomic.Int32
	p.streamClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})}
	ep := &EncryptPath{Enable: true, EncType: EncTypeAESCTR}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	probe := &propfindSizeProbe{ctx: ctx, target: "http://upstream/dav/enc/movie.mp4", headers: make(http.Header)}
	var out bytes.Buffer
	if err := p.processPropfindMetadata(strings.NewReader(mxPropfindXML("/dav/enc/other.mp4", 132, false)), &out, ep, nil, probe); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("probed href different from requested object")
	}
	out.Reset()
	p.storeFileCacheList("/dav/enc/movie.mp4", &FileInfo{Name: "movie.mp4", Size: 100, CiphertextSize: 132, ContentVersion: 2, HeaderLen: 32, NonceField: []byte("0123456789abcdef")})
	if err := p.processPropfindMetadata(strings.NewReader(mxPropfindXML("/dav/enc/movie.mp4", 132, false)), &out, ep, nil, probe); err != nil {
		t.Fatal(err)
	}
	if mxXMLLength(t, out.Bytes()) != 132 || !probe.used {
		t.Fatal("canceled probe guessed plaintext size")
	}
	cached, _ := p.loadFileCacheInMem("/dav/enc/movie.mp4")
	if cached.ContentVersion != 0 || len(cached.NonceField) != 0 || cached.Size != 132 {
		t.Fatalf("failed fresh proof resurrected old tuple: %+v", cached)
	}
	out.Reset()
	if err := p.processPropfindResponseBudget(strings.NewReader(mxPropfindXML("/dav/enc/movie.mp4", 132, false)), &out, ep, nil); err != nil {
		t.Fatal(err)
	}
	if mxXMLLength(t, out.Bytes()) != 132 {
		t.Fatal("directory reused failed same-size proof")
	}
}
