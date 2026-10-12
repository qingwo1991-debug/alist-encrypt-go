package handler

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	interr "github.com/alist-encrypt-go/internal/errors"
	"github.com/alist-encrypt-go/internal/ports"
	"github.com/alist-encrypt-go/internal/proxy"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

type startedPlaybackRepository struct {
	ports.FileRepository
	reads int
}

func (s *startedPlaybackRepository) Get(string) (*dao.FileInfo, bool) {
	s.reads++
	return nil, false
}
func (s *startedPlaybackRepository) InvalidateDisplayPath(string) {}

type startedPlaybackRecorder struct{ events []PlaybackEvent }

func (s *startedPlaybackRecorder) RecordPlayback(ev PlaybackEvent) { s.events = append(s.events, ev) }
func (s *startedPlaybackRecorder) RecordDeletion(string)           {}

// Embedding the port keeps unrelated operations unavailable: unexpected fresh
// inspection or passthrough calls fail the test instead of silently succeeding.
type startedPlaybackStreamer struct {
	ports.Streamer
	outcomes []*proxy.StreamOutcome
	calls    int
	hints    int
	strategy proxy.StreamStrategy
	payload  []byte
}

func (s *startedPlaybackStreamer) AcquireStream() (func(), bool) { return func() {}, true }
func (s *startedPlaybackStreamer) SelectOptimalStrategy(string, string, string, string) proxy.StreamStrategy {
	return s.strategy
}
func (s *startedPlaybackStreamer) RecordPlaybackHint(string, string, proxy.StreamStrategy) { s.hints++ }
func (s *startedPlaybackStreamer) ProxyDownloadDecryptWithStrategyForStorage(w http.ResponseWriter, r *http.Request, target string, passwd *config.PasswdInfo, size int64, strategy proxy.StreamStrategy, compat string) *proxy.StreamOutcome {
	if s.calls >= len(s.outcomes) {
		panic("unexpected retry after response started")
	}
	result := s.outcomes[s.calls]
	s.calls++
	if result.ResponseStarted {
		w.Header().Set("Content-Type", "video/mp4")
		w.WriteHeader(http.StatusPartialContent)
		if result.BytesWritten > 0 {
			_, _ = w.Write(s.payload)
		}
	}
	return result
}

func TestExecuteDecryptPlaybackResponseStartedIsTerminalFailure(t *testing.T) {
	cases := []struct {
		name     string
		initial  interr.FailureReason
		terminal interr.FailureReason
		strategy proxy.StreamStrategy
		scenario string
	}{
		{"initial-truncated", "", "upstream_truncated", proxy.StreamStrategyRange, consumerScenarioRedirect},
		{"initial-unclassified", "", "", proxy.StreamStrategyRange, consumerScenarioRedirect},
		{"initial-validation", "", "decrypt_validation_failed", proxy.StreamStrategyRange, consumerScenarioRedirect},
		{"initial-disconnect", "", "client_disconnect", proxy.StreamStrategyRange, consumerScenarioRedirect},
		{"webdav-fallback", "upstream_4xx", "upstream_truncated", proxy.StreamStrategyRange, consumerScenarioWebDAV},
		{"range-chunked-fallback", "range_unsupported", "upstream_truncated", proxy.StreamStrategyRange, consumerScenarioRedirect},
		{"chunked-full-must-not-run", "range_unsupported", "chunked_seek_too_large", proxy.StreamStrategyRange, consumerScenarioRedirect},
		{"range-full-fallback", "range_unsatisfiable", "upstream_truncated", proxy.StreamStrategyRange, consumerScenarioRedirect},
		{"chunked-full-fallback", "chunked_seek_too_large", "upstream_truncated", proxy.StreamStrategyChunked, consumerScenarioRedirect},
	}
	for _, tc := range cases {
		for _, written := range []int64{0, 7} {
			t.Run(fmt.Sprintf("%s/bytes=%d", tc.name, written), func(t *testing.T) {
				// Cancellation with bytes remains an intentional player handoff.
				if tc.terminal == "client_disconnect" && written > 0 {
					return
				}
				cfg := config.DefaultConfig()
				terminal := &proxy.StreamOutcome{ResponseStarted: true, BytesWritten: written, ExpectedBytes: 1024, Retryable: true, Err: fmt.Errorf("stream failed"), FailureReason: tc.terminal}
				sp := &startedPlaybackStreamer{strategy: tc.strategy, payload: []byte("partial"), outcomes: []*proxy.StreamOutcome{terminal}}
				if tc.initial != "" {
					sp.outcomes = append([]*proxy.StreamOutcome{{Err: fmt.Errorf("initial failure"), FailureReason: tc.initial, Retryable: true}}, terminal)
				}
				stats := &startedPlaybackRecorder{}
				repository := &startedPlaybackRepository{}
				selector, err := NewStrategySelector(cfg, nil)
				if err != nil {
					t.Fatal(err)
				}
				rr := httptest.NewRecorder()
				executeDecryptPlayback(decryptPlaybackRequest{
					ResponseWriter: rr, Request: httptest.NewRequest(http.MethodGet, "/demo.mp4", nil),
					Config: cfg, StreamProxy: sp, StrategySel: selector, FileDAO: repository, PasswdInfo: &config.PasswdInfo{},
					InitialSize: 1024, TargetURL: "https://cdn.example/demo", ProviderKey: "cdn.example",
					ConsumerScenario: tc.scenario, FileItem: FileItem{DisplayPath: "/demo.mp4", EncryptedPath: "/enc/demo"},
					StatsRecorder: stats,
				})
				if repository.reads != 1 {
					t.Fatalf("metadata reads=%d, fresh recovery must not run after response start", repository.reads)
				}
				if sp.calls != len(sp.outcomes) || sp.hints != 0 {
					t.Fatalf("calls=%d hints=%d, want calls=%d and no success hint", sp.calls, sp.hints, len(sp.outcomes))
				}
				want := []byte(nil)
				if written > 0 {
					want = sp.payload
				}
				if rr.Code != http.StatusPartialContent || !bytes.Equal(rr.Body.Bytes(), want) {
					t.Fatalf("response changed after start: status=%d body=%q", rr.Code, rr.Body.Bytes())
				}
				if len(stats.events) != 1 || stats.events[0].Completed || stats.events[0].BytesServed != written {
					t.Fatalf("partial playback stats=%+v", stats.events)
				}
				// Only an initial pre-response failure may have trained the selector.
				if tc.initial == "" && selector.Stats()["providers"] != 0 {
					t.Fatalf("started failure trained selector: %+v", selector.Stats())
				}
			})
		}
	}
}

type startedPassthroughStreamer struct{ startedPlaybackStreamer }

func (s *startedPassthroughStreamer) ProxyRequest(w http.ResponseWriter, r *http.Request, target string) error {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("partial"))
	return fmt.Errorf("upstream truncated")
}

func TestExecuteDecryptPlaybackStartedPassthroughDoesNotAppendError(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AlistServer.SizeUnknownStrict = false
	rr := httptest.NewRecorder()
	executeDecryptPlayback(decryptPlaybackRequest{
		ResponseWriter: rr, Request: httptest.NewRequest(http.MethodGet, "/demo", nil), Config: cfg,
		StreamProxy: &startedPassthroughStreamer{}, PasswdInfo: &config.PasswdInfo{},
	})
	if rr.Code != http.StatusOK || rr.Body.String() != "partial" {
		t.Fatalf("started passthrough changed: status=%d body=%q", rr.Code, rr.Body.String())
	}
}

func TestExecuteDecryptPlaybackV3MidstreamFailureIsTerminal(t *testing.T) {
	const chunkSize = int64(64)
	plain := bytes.Repeat([]byte("v3-data!"), 24)
	var container bytes.Buffer
	writer, err := encryption.NewV3Writer(&container, "pw", chunkSize)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	meta := encryption.ContentMeta{
		EncType: encryption.EncTypeAESCTR, Version: encryption.ContentVersionV3,
		HeaderLen: encryption.V3HeaderSize, PlainSize: int64(len(plain)), CiphertextSize: int64(container.Len()),
		NonceField: writer.NonceField(), ChunkSize: uint32(chunkSize), KDFIterations: 600000,
	}
	// Corrupt the second authenticated record, leaving the first record valid.
	secondStart, _ := encryption.V3ChunkWindow(chunkSize, chunkSize, chunkSize)
	container.Bytes()[int(secondStart)+8] ^= 0xff
	var hits int
	srv := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(container.Len()))
		_, _ = w.Write(container.Bytes())
	}))
	defer srv.Close()
	cfg := config.DefaultConfig()
	cfg.AlistServer.EnableSniff = false
	req := httptest.NewRequest(http.MethodGet, "/demo.bin", nil)
	req = req.WithContext(proxy.WithContentMeta(req.Context(), meta))
	rr := httptest.NewRecorder()
	stats := &startedPlaybackRecorder{}
	executeDecryptPlayback(decryptPlaybackRequest{
		ResponseWriter: rr, Request: req, Config: cfg, StreamProxy: proxy.NewStreamProxy(cfg),
		InitialSize: int64(len(plain)), TargetURL: srv.URL,
		PasswdInfo: &config.PasswdInfo{Password: "pw", EncType: "aesctr", Enable: true}, StatsRecorder: stats,
	})
	if hits != 1 || rr.Code != http.StatusOK || !bytes.Equal(rr.Body.Bytes(), plain[:chunkSize]) {
		t.Fatalf("V3 failure response: hits=%d status=%d body=%q", hits, rr.Code, rr.Body.Bytes())
	}
	if len(stats.events) != 1 || stats.events[0].Completed || stats.events[0].BytesServed != chunkSize {
		t.Fatalf("V3 failure stats=%+v", stats.events)
	}
}

func TestExecuteDecryptPlaybackTruncatedStreamDoesNotAppendError(t *testing.T) {
	for _, written := range []int{0, 1024} {
		t.Run(strconv.Itoa(written), func(t *testing.T) {
			const size = int64(4096)
			plain := bytes.Repeat([]byte("A"), int(size))
			ciphertext := append([]byte(nil), plain...)
			flow, err := encryption.NewFlowEnc("pw", "aesctr", size)
			if err != nil {
				t.Fatal(err)
			}
			flow.Encrypt(ciphertext)
			var hits int
			srv := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits++
				w.Header().Set("Content-Type", "application/octet-stream")
				w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(ciphertext[:written])
			}))
			defer srv.Close()
			cfg := config.DefaultConfig()
			cfg.AlistServer.EnableSniff = false
			stats := &startedPlaybackRecorder{}
			rr := httptest.NewRecorder()
			executeDecryptPlayback(decryptPlaybackRequest{
				ResponseWriter: rr, Request: httptest.NewRequest(http.MethodGet, "/demo.bin", nil),
				Config: cfg, StreamProxy: proxy.NewStreamProxy(cfg), InitialSize: size, TargetURL: srv.URL,
				PasswdInfo: &config.PasswdInfo{Password: "pw", EncType: "aesctr", Enable: true}, StatsRecorder: stats,
			})
			if hits != 1 || rr.Code != http.StatusOK || !bytes.Equal(rr.Body.Bytes(), plain[:written]) {
				t.Fatalf("hits=%d status=%d body length=%d, want one request and exact %d-byte prefix", hits, rr.Code, rr.Body.Len(), written)
			}
			if len(stats.events) != 1 || stats.events[0].Completed {
				t.Fatalf("truncation not recorded as failure: %+v", stats.events)
			}
		})
	}
}
