package encrypt

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	core "github.com/alist-encrypt-go/shared/encryptcore"
)

// Fixtures are emitted by shared crypto; fixed fixtures reuse its records and
// replace only the front matter via the shared header builder.
func v3InspectFixtures(t *testing.T) (stream, fixed, emptyHeader, emptyStream []byte) {
	t.Helper()
	var container bytes.Buffer
	writer, err := core.NewV3Writer(&container, "probe-fixture", 64)
	if err != nil {
		t.Fatal(err)
	}
	plain := bytes.Repeat([]byte("probe"), 19)
	if _, err = writer.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	stream = append([]byte(nil), container.Bytes()...)
	header, err := core.NewV3Header(int64(len(plain)), writer.NonceField(), 64, 600000)
	if err != nil {
		t.Fatal(err)
	}
	fixed = append(header, stream[V3HeaderSize:len(stream)-V3TrailerSize]...)
	emptyHeader, err = core.NewV3Header(0, writer.NonceField(), 64, 600000)
	if err != nil {
		t.Fatal(err)
	}
	// The shared writer supplies the empty streaming trailer too.
	var empty bytes.Buffer
	emptyWriter, err := core.NewV3Writer(&empty, "probe-fixture", 64)
	if err != nil {
		t.Fatal(err)
	}
	if err = emptyWriter.Close(); err != nil {
		t.Fatal(err)
	}
	emptyStream = append([]byte(nil), empty.Bytes()...)
	return
}

func v3InspectServeRange(w http.ResponseWriter, r *http.Request, body []byte) {
	if r.Header.Get("Accept-Encoding") != "identity" {
		panic("probe omitted identity encoding")
	}
	if r.Header.Get("Range") == "" {
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Write(body)
		return
	}
	var start, end int64
	if _, err := fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &start, &end); err != nil {
		panic(err)
	}
	if end >= int64(len(body)) {
		end = int64(len(body)) - 1
	}
	if start < 0 || end < start {
		w.WriteHeader(416)
		return
	}
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(body)))
	w.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
	w.WriteHeader(206)
	w.Write(body[start : end+1])
}

func v3InspectProxy(server *httptest.Server) *ProxyServer {
	return &ProxyServer{config: &ProxyConfig{AlistHost: "alist.local", AlistPort: 5244}, streamClient: server.Client()}
}

func TestV3InspectFullMetadata(t *testing.T) {
	stream, fixed, emptyHeader, emptyStream := v3InspectFixtures(t)
	for _, tc := range []struct {
		name  string
		body  []byte
		plain int64
		calls int32
	}{
		{"stream", stream, 95, 2}, {"fixed", fixed, 95, 1},
		{"empty-header", emptyHeader, 0, 1}, {"empty-stream", emptyStream, 0, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				v3InspectServeRange(w, r, tc.body)
			}))
			defer server.Close()
			// The advertised size is stale: a valid Content-Range is authoritative.
			meta, confirmed := v3InspectProxy(server).inspectEncryptedContentConfirmed(context.Background(), server.URL, nil, &EncryptPath{Enable: true, EncType: EncTypeAESCTR}, 123)
			if !confirmed || !meta.IsV3() || meta.PlainSize != tc.plain || meta.CiphertextSize != int64(len(tc.body)) || meta.HeaderLen != V3HeaderSize || meta.ChunkSize != 64 || len(meta.NonceField) != 16 || meta.KDFIterations != 600000 || ValidateV3ContentMeta(meta) != nil || calls.Load() != tc.calls {
				t.Fatalf("meta=%+v confirmed=%v calls=%d", meta, confirmed, calls.Load())
			}
		})
	}
}

func TestV3InspectKeepsLegacyAndV2(t *testing.T) {
	for _, encType := range []EncryptionType{EncTypeAESCTR, EncTypeChaCha20, EncTypeRC4} {
		for _, version := range []int{ContentVersionV1, ContentVersionV2} {
			t.Run(fmt.Sprintf("%s/v%d", encType, version), func(t *testing.T) {
				body := bytes.Repeat([]byte{0x6c}, 96)
				plainSize := int64(len(body))
				if version == ContentVersionV2 {
					header, err := BuildV2Header(encType, 64, bytes.Repeat([]byte{1}, 16))
					if err != nil {
						t.Fatal(err)
					}
					body = append(header, bytes.Repeat([]byte{0x6c}, 64)...)
					plainSize = 64
				}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { v3InspectServeRange(w, r, body) }))
				defer server.Close()
				meta, confirmed := v3InspectProxy(server).inspectEncryptedContentConfirmed(context.Background(), server.URL, nil, &EncryptPath{Enable: true, EncType: encType}, int64(len(body)))
				if !confirmed || meta.Version != version || meta.PlainSize != plainSize || ContentHeaderSize() != 32 {
					t.Fatalf("meta=%+v confirmed=%v", meta, confirmed)
				}
			})
		}
	}
}

func TestV3InspectFailuresStayRecognized(t *testing.T) {
	stream, fixed, _, _ := v3InspectFixtures(t)
	for _, name := range []string{"truncated-header", "header-short", "header-long", "header-offset", "header-end", "unknown-total", "header-encoding", "header-version", "header-tag", "header-chunk", "header-reserved", "fixed-geometry", "trailer-short", "trailer-long", "trailer-offset", "trailer-total", "trailer-encoding", "trailer-magic", "trailer-reserved", "trailer-geometry", "tail-auth", "tail-redirect", "spool-short", "spool-changed"} {
		t.Run(name, func(t *testing.T) {
			body := append([]byte(nil), stream...)
			switch name {
			case "truncated-header":
				body = body[:32]
			case "header-version":
				body[6] = 4
			case "header-tag":
				binary.BigEndian.PutUint32(body[36:40], 15)
			case "header-chunk":
				binary.BigEndian.PutUint32(body[32:36], 0)
			case "header-reserved":
				body[44] = 1
			case "fixed-geometry":
				body = append(append([]byte(nil), fixed...), 0)
			case "trailer-magic":
				body[len(body)-16] = 'X'
			case "trailer-reserved":
				body[len(body)-12] = 1
			case "trailer-geometry":
				binary.BigEndian.PutUint64(body[len(body)-8:], 1)
			}
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.Path != "/object" {
					t.Errorf("recognized V3 tried fallback %s", r.URL)
					w.WriteHeader(404)
					return
				}
				first := r.Header.Get("Range") == "bytes=0-47"
				if first {
					switch name {
					case "header-short":
						w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-47/%d", len(body)))
						w.WriteHeader(206)
						w.Write(body[:32])
						return
					case "header-long":
						w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-47/%d", len(body)))
						w.WriteHeader(206)
						w.Write(body[:49])
						return
					case "header-offset":
						w.Header().Set("Content-Range", fmt.Sprintf("bytes 1-48/%d", len(body)))
						w.WriteHeader(206)
						w.Write(body[:48])
						return
					case "header-end":
						w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-46/%d", len(body)))
						w.WriteHeader(206)
						w.Write(body[:47])
						return
					case "unknown-total":
						w.Header().Set("Content-Range", "bytes 0-47/*")
						w.WriteHeader(206)
						w.Write(body[:48])
						return
					case "header-encoding":
						w.Header().Set("Content-Encoding", "gzip")
					}
				} else {
					tail := body[len(body)-16:]
					switch name {
					case "tail-auth":
						w.WriteHeader(403)
						return
					case "tail-redirect":
						w.Header().Set("Location", "/unexpected")
						w.WriteHeader(302)
						return
					case "spool-short", "spool-changed":
						if r.Header.Get("Range") != "" {
							w.WriteHeader(200)
							w.Write(body)
							return
						}
						if name == "spool-short" {
							w.Write(body[:len(body)-1])
							return
						}
						changed := append([]byte(nil), body...)
						changed[8] ^= 1
						w.Write(changed)
						return
					case "trailer-short":
						w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", len(body)-16, len(body)-1, len(body)))
						w.WriteHeader(206)
						w.Write(tail[:15])
						return
					case "trailer-long":
						w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", len(body)-16, len(body)-1, len(body)))
						w.WriteHeader(206)
						w.Write(append(tail, 0))
						return
					case "trailer-offset":
						w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", len(body)-17, len(body)-2, len(body)))
						w.WriteHeader(206)
						w.Write(tail)
						return
					case "trailer-total":
						w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", len(body)-16, len(body)-1, len(body)+1))
						w.WriteHeader(206)
						w.Write(tail)
						return
					case "trailer-encoding":
						w.Header().Set("Content-Encoding", "br")
					}
				}
				v3InspectServeRange(w, r, body)
			}))
			defer server.Close()
			meta, confirmed := v3InspectProxy(server).inspectEncryptedContentWithFallbackConfirmed(context.Background(), server.URL+"/object", nil, &EncryptPath{Enable: true, EncType: EncTypeAESCTR}, int64(len(body)), "/object")
			if !confirmed || !meta.IsV3() || ValidateV3ContentMeta(meta) == nil {
				t.Fatalf("meta=%+v confirmed=%v calls=%d", meta, confirmed, calls.Load())
			}
		})
	}
}

func TestV3InspectRangeRefusedBoundedFallback(t *testing.T) {
	stream, fixed, _, empty := v3InspectFixtures(t)
	for _, tc := range []struct {
		name       string
		body       []byte
		tailStatus int
		wantCalls  int32
		valid      bool
	}{
		{"fixed-ignore", fixed, 200, 1, true}, {"stream-ignore", stream, 200, 3, true},
		{"empty-ignore", empty, 200, 3, true}, {"tail-416", stream, 416, 3, true},
		{"large-refusal", nil, 200, 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := tc.body
			total := len(body)
			if body == nil {
				header, err := core.NewV3Header(0, bytes.Repeat([]byte{1}, 16), 64, 1)
				if err != nil {
					t.Fatal(err)
				}
				body = header
				total = V3HeaderSize + V3TrailerSize + (64+16)*110000
			}
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Header.Get("Range") == "bytes=0-47" && tc.name == "tail-416" {
					v3InspectServeRange(w, r, body)
					return
				}
				if r.Header.Get("Range") != "bytes=0-47" && r.Header.Get("Range") != "" && tc.tailStatus == 416 {
					w.WriteHeader(416)
					return
				}
				w.Header().Set("Content-Length", strconv.Itoa(total))
				w.WriteHeader(200)
				w.Write(body)
			}))
			defer server.Close()
			meta, confirmed := v3InspectProxy(server).inspectEncryptedContentConfirmed(context.Background(), server.URL, nil, &EncryptPath{Enable: true, EncType: EncTypeAESCTR}, int64(total))
			if !confirmed || !meta.IsV3() || (ValidateV3ContentMeta(meta) == nil) != tc.valid || calls.Load() != tc.wantCalls {
				t.Fatalf("meta=%+v confirmed=%v calls=%d", meta, confirmed, calls.Load())
			}
		})
	}
}

func TestV3InspectResourcePolicyBeforeTail(t *testing.T) {
	for _, field := range []string{"chunk", "kdf"} {
		t.Run(field, func(t *testing.T) {
			header, err := core.NewV3Header(0, bytes.Repeat([]byte{1}, 16), 64, 1)
			if err != nil {
				t.Fatal(err)
			}
			if field == "chunk" {
				binary.BigEndian.PutUint32(header[32:36], MaxMobileV3ChunkSize+1)
			} else {
				binary.BigEndian.PutUint32(header[40:44], MaxMobileV3KDFIterations+1)
			}
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); v3InspectServeRange(w, r, header) }))
			defer server.Close()
			meta, confirmed := v3InspectProxy(server).inspectEncryptedContentConfirmed(context.Background(), server.URL, nil, &EncryptPath{Enable: true, EncType: EncTypeAESCTR}, 48)
			if !confirmed || !meta.IsV3() || !errors.Is(ValidateV3ContentMeta(meta), ErrV3ResourceLimit) || calls.Load() != 1 {
				t.Fatalf("meta=%+v confirmed=%v calls=%d", meta, confirmed, calls.Load())
			}
		})
	}
}

func TestV3InspectTailCancellationGated(t *testing.T) {
	stream, _, _, _ := v3InspectFixtures(t)
	entered := make(chan struct{})
	canceled := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") == "bytes=0-47" {
			v3InspectServeRange(w, r, stream)
			return
		}
		close(entered)
		<-r.Context().Done()
		close(canceled)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	var meta ContentMeta
	var confirmed bool
	go func() {
		meta, confirmed = v3InspectProxy(server).inspectEncryptedContentWithFallbackConfirmed(ctx, server.URL, nil, &EncryptPath{Enable: true, EncType: EncTypeAESCTR}, int64(len(stream)), "/object")
		close(done)
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("tail request not reached")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("probe ignored cancellation")
	}
	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream not canceled")
	}
	if !confirmed || !meta.IsV3() || ValidateV3ContentMeta(meta) == nil {
		t.Fatalf("meta=%+v confirmed=%v", meta, confirmed)
	}
}

func TestV3InspectRedirectTailCredentials(t *testing.T) {
	stream, _, _, _ := v3InspectFixtures(t)
	var cdnCalls atomic.Int32
	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cdnCalls.Add(1)
		for _, key := range sensitivePlaybackHeaders {
			if r.Header.Get(key) != "" {
				t.Errorf("CDN leaked %s", key)
			}
		}
		if r.Header.Get("User-Agent") != "probe-agent" {
			t.Error("lost user-agent")
		}
		v3InspectServeRange(w, r, stream)
	}))
	defer cdn.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer origin" || r.Header.Get("Cookie") != "session=origin" {
			t.Error("lost origin credentials")
		}
		w.Header().Set("Location", cdn.URL+"/signed-object")
		w.WriteHeader(302)
	}))
	defer origin.Close()
	parsed, _ := url.Parse(origin.URL)
	port, _ := strconv.Atoi(parsed.Port())
	p := &ProxyServer{config: &ProxyConfig{AlistHost: parsed.Hostname(), AlistPort: port}, streamClient: origin.Client()}
	auth := http.Header{"Authorization": {"Bearer origin"}, "Cookie": {"session=origin"}, "Proxy-Authorization": {"secret"}, "User-Agent": {"probe-agent"}}
	meta, confirmed := p.inspectEncryptedContentConfirmed(context.Background(), origin.URL, auth, &EncryptPath{Enable: true, EncType: EncTypeAESCTR}, int64(len(stream)))
	if !confirmed || ValidateV3ContentMeta(meta) != nil || cdnCalls.Load() != 2 {
		t.Fatalf("meta=%+v confirmed=%v cdnCalls=%d", meta, confirmed, cdnCalls.Load())
	}
}
