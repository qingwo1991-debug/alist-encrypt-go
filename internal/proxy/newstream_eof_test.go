package proxy

import (
	"bytes"
	"context"
	stderrors "errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/playbacktest"
)

// Return bytes and an error from the same Read: io.Copy must still give a
// simultaneous writer failure precedence, including identical EOF sentinels.
type focusedEOFReader struct {
	data   []byte
	err    error
	onRead func()
}

func (r *focusedEOFReader) Read(p []byte) (int, error) {
	if r.onRead != nil {
		r.onRead()
		r.onRead = nil
	}
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		return n, r.err
	}
	return n, nil
}

// These optional fast paths must not bypass source tracking.
func (*focusedEOFReader) WriteTo(io.Writer) (int64, error) {
	panic("copy must use the tracked Read boundary")
}

type focusedEOFWriter struct {
	*httptest.ResponseRecorder
	err error
}

func (w focusedEOFWriter) Write(p []byte) (int, error) {
	n := len(p) / 2
	_, _ = w.ResponseRecorder.Write(p[:n])
	return n, w.err
}
func (focusedEOFWriter) ReadFrom(io.Reader) (int64, error) {
	panic("copy must use the Write boundary")
}

func TestFocusedEOFCopySourceAndContext(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	deadline, cancelDeadline := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelDeadline()
	for _, tc := range []struct {
		name              string
		ctx               context.Context
		readErr, writeErr error
		failWrite         bool
		data              string
		expected          int64
		wantErr           error
		wantReason        string
		wantReadSource    bool
	}{
		{"upstream unexpected EOF", context.Background(), io.ErrUnexpectedEOF, nil, false, "prefix", 10, io.ErrUnexpectedEOF, "upstream_truncated", true},
		{"wrapped upstream EOF", context.Background(), fmt.Errorf("body: %w", io.ErrUnexpectedEOF), nil, false, "prefix", 10, io.ErrUnexpectedEOF, "upstream_truncated", true},
		{"downstream unexpected EOF wins", context.Background(), io.ErrUnexpectedEOF, io.ErrUnexpectedEOF, true, "prefix", 10, io.ErrUnexpectedEOF, "network_error", false},
		{"downstream short write wins", context.Background(), io.ErrUnexpectedEOF, nil, true, "prefix", 10, io.ErrShortWrite, "network_error", false},
		{"downstream explicit short write", context.Background(), io.EOF, io.ErrShortWrite, true, "prefix", 10, io.ErrShortWrite, "network_error", false},
		{"cancel race", canceled, io.ErrUnexpectedEOF, nil, false, "prefix", 10, io.ErrUnexpectedEOF, "client_disconnect", true},
		{"deadline race", deadline, io.ErrUnexpectedEOF, nil, false, "prefix", 10, io.ErrUnexpectedEOF, "timeout", true},
		{"upstream deadline", context.Background(), context.DeadlineExceeded, nil, false, "prefix", 10, context.DeadlineExceeded, "timeout", true},
		{"live context network failure", context.Background(), fmt.Errorf("upstream failed"), nil, false, "prefix", 10, nil, "network_error", true},
		{"synthetic short read", context.Background(), io.EOF, nil, false, "prefix", 10, io.ErrUnexpectedEOF, "upstream_truncated", true},
		{"synthetic short read cancel race", canceled, io.EOF, nil, false, "prefix", 10, io.ErrUnexpectedEOF, "client_disconnect", true},
		{"complete bytes still preserve read error", context.Background(), io.ErrUnexpectedEOF, nil, false, "complete", 8, io.ErrUnexpectedEOF, "upstream_truncated", true},
		{"complete success", context.Background(), io.EOF, nil, false, "complete", 8, nil, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			var dst io.Writer = rec
			if tc.failWrite {
				dst = focusedEOFWriter{rec, tc.writeErr}
			}
			n, err := copyStreamBody(dst, &focusedEOFReader{data: []byte(tc.data), err: tc.readErr}, make([]byte, 32), tc.expected)
			if n != int64(rec.Body.Len()) {
				t.Fatalf("written=%d body=%d", n, rec.Body.Len())
			}
			if tc.wantErr != nil && !stderrors.Is(err, tc.wantErr) {
				t.Fatalf("err=%v want %v", err, tc.wantErr)
			}
			if (err == nil) != (tc.wantReason == "") {
				t.Fatalf("err=%v reason=%q", err, tc.wantReason)
			}
			var readErr *streamReadError
			if got := stderrors.As(err, &readErr); got != tc.wantReadSource {
				t.Fatalf("read source=%v want %v: %v", got, tc.wantReadSource, err)
			}
			if reason := classifyStreamCopyError(tc.ctx, err); string(reason) != tc.wantReason {
				t.Fatalf("reason=%q want %q", reason, tc.wantReason)
			}
		})
	}
	// EOF outside this source-fenced body-copy path must not become retryable.
	if reason, retry := classifyStreamError(io.ErrUnexpectedEOF); reason != "network_error" || retry {
		t.Fatalf("generic EOF classification changed: reason=%s retry=%v", reason, retry)
	}
}

func TestFocusedEOFDecryptCancellationRace(t *testing.T) {
	plain := []byte("0123456789abcdef")
	container := acceptanceContainers(t, plain)[0]
	for _, canceled := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancel=%v", canceled), func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.AlistServer.EnableSniff = false
			sp := NewStreamProxy(cfg)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			sp.client = newTestClient(func(r *http.Request) (*http.Response, error) {
				calls++
				body := &focusedEOFReader{data: container.body[:5], err: io.ErrUnexpectedEOF}
				if canceled {
					body.onRead = cancel
				}
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{
					"Content-Type": {"video/mp4"}, "Content-Length": {strconv.Itoa(len(container.body))},
				}, Body: io.NopCloser(body), Request: r}, nil
			})
			r := httptest.NewRequest(http.MethodGet, "/d/eof.mp4", nil).WithContext(ctx)
			r = r.WithContext(WithContentMeta(r.Context(), container.meta))
			rr := httptest.NewRecorder()
			out := sp.ProxyDownloadDecryptWithStrategy(rr, r, "http://upstream.local/object", &config.PasswdInfo{Enable: true, Password: "pw", EncType: "aesctr"}, int64(len(plain)), StreamStrategyFull)
			wantReason := "upstream_truncated"
			if canceled {
				wantReason = "client_disconnect"
			}
			if !stderrors.Is(out.Err, io.ErrUnexpectedEOF) || string(out.FailureReason) != wantReason || !out.ResponseStarted || out.Retryable || !out.NoLearning {
				t.Fatalf("outcome=%+v", out)
			}
			if calls != 1 || !bytes.Equal(rr.Body.Bytes(), plain[:5]) || out.BytesWritten != 5 || out.ExpectedBytes != int64(len(plain)) {
				t.Fatalf("calls=%d body=%q outcome=%+v", calls, rr.Body.Bytes(), out)
			}
		})
	}
}

// Real loopback net/http supplies ErrUnexpectedEOF for an advertised body that
// ends early. V3 must emit only whole authenticated records, never failed bytes.
func TestFocusedEOFLoopbackPlaintextAndTerminalFailure(t *testing.T) {
	plain := bytes.Repeat([]byte("exact-plaintext-"), 32)
	for _, container := range acceptanceContainers(t, plain) {
		for _, fail := range []string{"healthy", "upstream", "writerEOF", "writerShort"} {
			t.Run(container.name+"/"+fail, func(t *testing.T) {
				behavior := playbacktest.Behavior{Range: playbacktest.RangeAccept}
				prefix := 5
				if container.meta.IsV2() {
					prefix += int(container.meta.HeaderLen)
				}
				if container.meta.IsV3() {
					prefix = int(container.meta.HeaderLen) + int(container.meta.ChunkSize) + 16 + 5
				}
				if fail == "upstream" {
					behavior.TruncateAfter = prefix
				}
				u := playbacktest.New(container.body, behavior, nil)
				defer u.Close()
				sp := acceptanceProxy(u)
				r := httptest.NewRequest(http.MethodGet, "/d/eof.mp4", nil)
				r = r.WithContext(WithContentMeta(r.Context(), container.meta))
				rr := httptest.NewRecorder()
				var w http.ResponseWriter = rr
				if fail == "writerEOF" {
					w = focusedEOFWriter{rr, io.ErrUnexpectedEOF}
				}
				if fail == "writerShort" {
					w = focusedEOFWriter{rr, nil}
				}
				out := sp.ProxyDownloadDecryptWithStrategy(w, r, u.URL("/object"), &config.PasswdInfo{Enable: true, Password: "pw", EncType: "aesctr"}, int64(len(plain)), StreamStrategyFull)
				u.Close()
				if got := u.Snapshot().RequestCount; got != 1 {
					t.Fatalf("requests=%d: body must not retry", got)
				}
				if !out.ResponseStarted || out.ExpectedBytes != int64(len(plain)) {
					t.Fatalf("outcome=%+v", out)
				}
				if fail == "healthy" {
					if out.Err != nil || out.FailureReason != "" || !bytes.Equal(rr.Body.Bytes(), plain) || out.BytesWritten != int64(len(plain)) {
						t.Fatalf("healthy outcome=%+v body=%q", out, rr.Body.Bytes())
					}
					return
				}
				wantReason, wantErr := "network_error", io.ErrShortWrite
				if fail == "upstream" {
					wantReason, wantErr = "upstream_truncated", io.ErrUnexpectedEOF
				}
				if fail == "writerEOF" {
					wantErr = io.ErrUnexpectedEOF
				}
				if !stderrors.Is(out.Err, wantErr) || string(out.FailureReason) != wantReason || out.Retryable || !out.NoLearning {
					t.Fatalf("failed outcome=%+v", out)
				}
				if fail == "upstream" {
					wantLen := 5
					if container.meta.IsV3() {
						wantLen = int(container.meta.ChunkSize)
					}
					if !bytes.Equal(rr.Body.Bytes(), plain[:wantLen]) {
						t.Fatalf("partial body=%q want exactly %d authenticated/plain bytes", rr.Body.Bytes(), wantLen)
					}
				}
				if !bytes.Equal(rr.Body.Bytes(), plain[:rr.Body.Len()]) || out.BytesWritten != int64(rr.Body.Len()) {
					t.Fatalf("partial body corrupted: outcome=%+v body=%q", out, rr.Body.Bytes())
				}
			})
		}
	}
}
