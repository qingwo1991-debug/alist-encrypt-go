package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/playbacktest"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

// These are HTTP handler Write / response Body.Read counters, NOT packet-level
// network traffic, renderer timings, or a production-KDF CPU benchmark.
type v3AmplificationCase struct {
	ChunkSize           int64 `json:"chunkSize"`
	RequestedPlainBytes int64 `json:"requestedPlainBytes"`
	ColdRequests        int64 `json:"coldRequests"`
	ColdWrittenBytes    int64 `json:"coldWrittenBytes"`
	ColdBodyReadBytes   int64 `json:"coldBodyReadBytes"`
	WarmRequests        int64 `json:"warmRequests"`
	WarmWrittenBytes    int64 `json:"warmWrittenBytes"`
	WarmBodyReadBytes   int64 `json:"warmBodyReadBytes"`
}

type v3AmplificationCountingBody struct {
	io.ReadCloser
	read *atomic.Int64
}

func (b *v3AmplificationCountingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.read.Add(int64(n))
	return n, err
}

// Build a real shared-codec container with a deliberately cheap fixture-only
// KDF. Using zero would normalize to the production KDF, defeating this byte-
// amplification test's purpose. The final record is padded exactly as V3Writer.
func v3AmplificationContainer(t *testing.T, plain []byte, chunk int64) ([]byte, encryption.ContentMeta) {
	t.Helper()
	const password = "amplification-fixture-only"
	nonce := bytes.Repeat([]byte{0x37}, encryption.V3NonceFieldLen())
	header, err := encryption.NewV3Header(int64(len(plain)), nonce, chunk, 1)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := encryption.NewV3ChunkCipher(encryption.DeriveV3Key(password, nonce, 1), nonce)
	if err != nil {
		t.Fatal(err)
	}
	container := make([]byte, 0, encryption.V3CiphertextSize(int64(len(plain)), chunk))
	container = append(container, header...)
	padded := make([]byte, chunk)
	for start, index := int64(0), uint64(0); start < int64(len(plain)); start, index = start+chunk, index+1 {
		clear(padded)
		copy(padded, plain[start:min(start+chunk, int64(len(plain)))])
		record, err := cipher.Seal(index, padded)
		if err != nil {
			t.Fatal(err)
		}
		container = append(container, record...)
	}
	meta, ok, err := encryption.ParseV3Header(header, int64(len(container)))
	if err != nil || !ok || meta.KDFIterations != 1 {
		t.Fatalf("fixture metadata: recognized=%v iterations=%d err=%v", ok, meta.KDFIterations, err)
	}
	return container, meta
}

func TestV3AmplificationAcceptance(t *testing.T) {
	plain := make([]byte, 17<<20)
	for i := range plain {
		plain[i] = byte(i*31 + i/251 + 7)
	}
	var cases []v3AmplificationCase
	for _, chunk := range []int64{1 << 20, 16 << 20} {
		t.Run(fmt.Sprintf("chunk_%d", chunk), func(t *testing.T) {
			container, meta := v3AmplificationContainer(t, plain, chunk)
			up := playbacktest.New(container, playbacktest.Behavior{Range: playbacktest.RangeAccept}, nil)
			t.Cleanup(up.Close)
			transport := &http.Transport{Proxy: nil}
			t.Cleanup(transport.CloseIdleConnections)
			var requests, bodyRead atomic.Int64
			sp := NewStreamProxy(config.DefaultConfig())
			// Delegate to a real HTTP transport; the wrapper only counts requests
			// and bytes actually returned by Body.Read, not advertised lengths.
			sp.client = newTestClient(func(req *http.Request) (*http.Response, error) {
				requests.Add(1)
				resp, err := transport.RoundTrip(req)
				if err == nil {
					resp.Body = &v3AmplificationCountingBody{ReadCloser: resp.Body, read: &bodyRead}
				}
				return resp, err
			})
			passwd := &config.PasswdInfo{Enable: true, Password: "amplification-fixture-only", EncType: "aesctr"}
			seek := func(start, end int64) {
				t.Helper()
				req := httptest.NewRequest(http.MethodGet, "/file", nil)
				req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
				req = req.WithContext(WithContentMeta(req.Context(), meta))
				// This hook models completed route authorization (verified anonymous).
				// It is intentionally present on BOTH cold and warm requests.
				req = req.WithContext(WithV3CacheAuthorization(req.Context(), "", ""))
				rr := httptest.NewRecorder()
				out := sp.ProxyDownloadDecryptWithStrategy(rr, req, up.URL("/file"), passwd, meta.PlainSize, StreamStrategyRange)
				if out.Err != nil || out.StatusCode != http.StatusPartialContent || rr.Code != http.StatusPartialContent || !out.ResponseStarted {
					t.Fatalf("seek outcome: %+v code=%d", out, rr.Code)
				}
				wantLength := end - start + 1
				if rr.Header().Get("Content-Length") != fmt.Sprint(wantLength) || rr.Body.Len() != int(wantLength) || out.BytesWritten != wantLength || out.ExpectedBytes != wantLength {
					t.Fatalf("plaintext length: header=%s body=%d outcome=%+v", rr.Header().Get("Content-Length"), rr.Body.Len(), out)
				}
				if rr.Header().Get("Content-Range") != fmt.Sprintf("bytes %d-%d/%d", start, end, len(plain)) || rr.Header().Get("Accept-Ranges") != "bytes" {
					t.Fatalf("plaintext headers: %v", rr.Header())
				}
				if !bytes.Equal(rr.Body.Bytes(), plain[start:end+1]) {
					t.Fatal("plaintext bytes differ")
				}
			}
			seek(1024, 5119)
			coldRequests, coldRead := requests.Load(), bodyRead.Load()
			if coldRequests != 1 || coldRead != chunk+16 {
				t.Fatalf("cold authenticated record: requests=%d Body.Read=%d want=%d", coldRequests, coldRead, chunk+16)
			}
			seek(8192, 12287) // distinct tiny interval in the SAME authenticated record
			warmRequests, warmRead := requests.Load()-coldRequests, bodyRead.Load()-coldRead
			if warmRequests != 0 || warmRead != 0 {
				t.Fatalf("warm record refetched: requests=%d Body.Read=%d", warmRequests, warmRead)
			}
			// Joining handlers avoids observing the final Write before its fixture
			// counter update. Warm made no HTTP request, so all server writes are
			// attributable to the one cold request, and warm Write bytes are zero.
			up.Close()
			snap := up.Snapshot()
			if snap.RequestCount != 1 || len(snap.Requests) != 1 || snap.BodyBytes != chunk+16 {
				t.Fatalf("server actual writes: %+v want=%d", snap, chunk+16)
			}
			r := snap.Requests[0]
			cipherStart, cipherEnd := encryption.V3ChunkWindow(1024, 5119, chunk)
			if r.Status != http.StatusPartialContent || r.Method != http.MethodGet || r.Range != fmt.Sprintf("bytes=%d-%d", cipherStart, cipherEnd) || r.BodyBytes != chunk+16 {
				t.Fatalf("cold HTTP window: %+v", r)
			}
			cases = append(cases, v3AmplificationCase{
				ChunkSize: chunk, RequestedPlainBytes: 4096,
				ColdRequests: coldRequests, ColdWrittenBytes: snap.BodyBytes, ColdBodyReadBytes: coldRead,
				WarmRequests: warmRequests, WarmWrittenBytes: 0, WarmBodyReadBytes: warmRead,
			})
		})
	}
	if len(cases) != 2 {
		t.Fatal("both chunk geometries must pass before producing a report")
	}
	if cases[0].ColdWrittenBytes >= cases[1].ColdWrittenBytes || (cases[0].ColdWrittenBytes-16)*16 != cases[1].ColdWrittenBytes-16 {
		t.Fatalf("chunk-plus-tag byte comparison: %+v", cases)
	}
	report := struct {
		SchemaVersion          int                   `json:"schemaVersion"`
		Measurement            string                `json:"measurement"`
		PlainSize              int64                 `json:"plainSize"`
		FixtureKDFIterations   int                   `json:"fixtureKdfIterations"`
		RendererTimingVerified bool                  `json:"rendererTimingVerified"`
		Cases                  []v3AmplificationCase `json:"cases"`
	}{1, "loopback HTTP server Write and client Body.Read bytes; not network-wire bytes or playback latency", int64(len(plain)), 1, false, cases}
	path := os.Getenv("PLAYBACK_V3_AMPLIFICATION_REPORT")
	if path == "" {
		path = filepath.Join(t.TempDir(), "v3-amplification.json")
	}
	if !filepath.IsAbs(path) {
		t.Fatal("PLAYBACK_V3_AMPLIFICATION_REPORT must be an absolute path")
	}
	if err := playbacktest.WriteJSON(path, report); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	// Never include authorized target URLs, passwords, or request credentials.
	t.Logf("V3 amplification acceptance: %s", encoded)
}
