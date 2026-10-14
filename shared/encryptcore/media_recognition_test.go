package encryption

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Fixtures derive a one-iteration key directly, not via the upload writer or
// production KDF scheduler. Large records are allocated only by cloud tests.
func recognitionFixture(t *testing.T, chunk int64, trailer bool) []byte {
	t.Helper()
	nonce := bytes.Repeat([]byte{71}, 16)
	headerPlain := int64(100)
	if trailer {
		headerPlain = 0
	}
	h, err := NewV3Header(headerPlain, nonce, chunk, 1)
	if err != nil {
		t.Fatal(err)
	}
	key, err := DeriveV3KeyContext(context.Background(), "recognition-fixture", nonce, 1, V3KDFSpeculative)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewV3ChunkCipher(key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]byte, chunk)
	binary.BigEndian.PutUint32(plain[:4], 16)
	copy(plain[4:8], "ftyp")
	copy(plain[8:12], "mp42")
	sealed, err := c.Seal(0, plain)
	if err != nil {
		t.Fatal(err)
	}
	data := append(h, sealed...)
	if trailer {
		tail := make([]byte, 16)
		copy(tail, []byte{'V', '3', 'E', '4', 0, 0, 0, 0})
		binary.BigEndian.PutUint64(tail[8:], 100)
		data = append(data, tail...)
	}
	return data
}

func recognitionRange(w http.ResponseWriter, r *http.Request, data []byte) {
	var start, end int64
	if _, err := fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &start, &end); err != nil || start < 0 || end < start || end >= int64(len(data)) {
		w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		return
	}
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(data)))
	w.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
	w.Header().Set("ETag", `"fixture"`)
	w.WriteHeader(http.StatusPartialContent)
	_, _ = w.Write(data[start : end+1])
}

func TestMediaRecognitionRecordBudgets(t *testing.T) {
	for _, chunk := range []int64{1 << 20, 16 << 20, 32 << 20} {
		for _, trailer := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/trailer=%v", chunk, trailer), func(t *testing.T) {
				data := recognitionFixture(t, chunk, trailer)
				var requests atomic.Int64
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); recognitionRange(w, r, data) }))
				defer srv.Close()
				for _, optIn := range []bool{false, true} {
					m := NewMediaRecognizer(MediaRecognitionConfig{LargeRecordOptIn: optIn})
					before := V3KDFServiceStats()
					out, err := m.RecognizeV3(context.Background(), srv.Client(), srv.URL, "recognition-fixture", nil, int64(len(data)))
					after := V3KDFServiceStats()
					t.Logf("fixture chunk=%d trailer=%v optin=%v actual_read=%d record=%d lease_after=%d KDF_before=%+v KDF_after=%+v reason=%s", chunk, trailer, optIn, out.BytesRead, out.RecordBytes, m.LeasedBytes(), before, after, out.Reason)
					m.Stop()
					if m.LeasedBytes() != 0 {
						t.Fatal("record lease leaked")
					}
					if chunk > MediaRecognitionDefaultChunk && !optIn {
						if err == nil || !strings.HasPrefix(out.Reason, "budget_rejected") || out.BytesRead != 48 || out.RecordAuthenticated {
							t.Fatalf("default budget: %+v %v", out, err)
						}
						continue
					}
					wantBytes := chunk + 16 + 96
					layout := "fixed"
					if trailer {
						wantBytes += 16
						layout = "trailer"
					}
					if err != nil || !out.RecordAuthenticated || out.Ext != ".mp4" || out.MIME != "video/mp4" || out.Layout != layout || out.BytesRead != wantBytes || out.RecordBytes != chunk+16 {
						t.Fatalf("recognition evidence/actual bytes: %+v %v want=%d", out, err, wantBytes)
					}
				}
				if requests.Load() == 0 {
					t.Fatal("fixture did not exercise HTTP")
				}
			})
		}
	}
}

func TestMediaRecognitionRejectsUntrustedEvidence(t *testing.T) {
	base := recognitionFixture(t, 1<<20, false)
	for _, tc := range []struct {
		name     string
		trailer  bool
		password string
		mutate   func([]byte)
	}{
		{name: "tag", mutate: func(b []byte) { b[len(b)-1] ^= 1 }},
		{name: "password", password: "wrong"},
		{name: "chunk-zero", mutate: func(b []byte) { binary.BigEndian.PutUint32(b[32:36], 0) }},
		{name: "kdf-zero", mutate: func(b []byte) { binary.BigEndian.PutUint32(b[40:44], 0) }},
		{name: "kdf-over-budget", mutate: func(b []byte) { binary.BigEndian.PutUint32(b[40:44], 600001) }},
		{name: "reserved", mutate: func(b []byte) { b[7] = 1 }},
		{name: "tag-width", mutate: func(b []byte) { binary.BigEndian.PutUint32(b[36:40], 15) }},
		{name: "extra-record-geometry", mutate: func(b []byte) { binary.BigEndian.PutUint64(b[24:32], 1<<20+1) }},
		{name: "empty", trailer: true, mutate: func(b []byte) { binary.BigEndian.PutUint64(b[len(b)-8:], 0) }},
		{name: "tail-magic", trailer: true, mutate: func(b []byte) { b[len(b)-16] ^= 1 }},
		{name: "tail-record-count", trailer: true, mutate: func(b []byte) { binary.BigEndian.PutUint64(b[len(b)-8:], 1<<20+1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := append([]byte(nil), base...)
			if tc.trailer {
				data = recognitionFixture(t, 1<<20, true)
			}
			if tc.mutate != nil {
				tc.mutate(data)
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { recognitionRange(w, r, data) }))
			defer srv.Close()
			m := NewMediaRecognizer(MediaRecognitionConfig{})
			defer m.Stop()
			password := tc.password
			if password == "" {
				password = "recognition-fixture"
			}
			out, err := m.RecognizeV3(context.Background(), srv.Client(), srv.URL, password, nil, int64(len(data)))
			if err == nil || out.Ext != "" || out.RecordAuthenticated || m.LeasedBytes() != 0 {
				t.Fatalf("untrusted alias: %+v %v", out, err)
			}
		})
	}
}

// Empty AAD cannot authenticate PlainSize changes within the same record count.
// Persisted results describe geometry checks, never authenticated metadata.
func TestMediaRecognitionSameRecordPlainSizeBoundary(t *testing.T) {
	for _, trailer := range []bool{false, true} {
		data := recognitionFixture(t, 1<<20, trailer)
		if trailer {
			binary.BigEndian.PutUint64(data[len(data)-8:], 101)
		} else {
			binary.BigEndian.PutUint64(data[24:32], 101)
		}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { recognitionRange(w, r, data) }))
		m := NewMediaRecognizer(MediaRecognitionConfig{})
		out, err := m.RecognizeV3(context.Background(), srv.Client(), srv.URL, "recognition-fixture", nil, int64(len(data)))
		m.Stop()
		srv.Close()
		if err != nil || !out.RecordAuthenticated || out.Meta.PlainSize != 101 || out.Reason != "record_authenticated_geometry_checked_video_signature" {
			t.Fatalf("empty-AAD boundary: %+v %v", out, err)
		}
	}
}

func TestMediaRecognitionHTTPAdversaries(t *testing.T) {
	data := recognitionFixture(t, 1<<20, false)
	for _, mode := range []string{"bad-range", "compressed", "truncated", "changed-validator", "changed-header", "ignored-range", "redirect-loop"} {
		t.Run(mode, func(t *testing.T) {
			var requests atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := requests.Add(1)
				switch mode {
				case "bad-range":
					w.Header().Set("Content-Range", "bytes 0-47/999")
					w.Header().Set("Content-Length", "48")
					w.WriteHeader(206)
					_, _ = w.Write(data[:48])
				case "compressed":
					w.Header().Set("Content-Encoding", "gzip")
					recognitionRange(w, r, data)
				case "truncated":
					w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-47/%d", len(data)))
					w.Header().Set("Content-Length", "48")
					w.WriteHeader(206)
					_, _ = w.Write(data[:10])
				case "changed-validator":
					if n > 1 {
						w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-%d/%d", 48+(1<<20)+15, len(data)))
						w.Header().Set("Content-Length", strconv.Itoa(48+(1<<20)+16))
						w.Header().Set("ETag", `"other"`)
						w.WriteHeader(206)
						_, _ = w.Write(data[:48+(1<<20)+16])
						return
					}
					recognitionRange(w, r, data)
				case "changed-header":
					b := data
					if n > 1 {
						b = append([]byte(nil), data...)
						b[8] ^= 1
					}
					recognitionRange(w, r, b)
				case "ignored-range":
					w.Header().Set("Content-Length", strconv.Itoa(len(data)))
					_, _ = w.Write(data)
				case "redirect-loop":
					http.Redirect(w, r, "/loop", http.StatusFound)
				}
			}))
			defer srv.Close()
			m := NewMediaRecognizer(MediaRecognitionConfig{})
			defer m.Stop()
			out, err := m.RecognizeV3(context.Background(), srv.Client(), srv.URL, "recognition-fixture", nil, int64(len(data)))
			if mode == "ignored-range" { // Full 200 is bounded prefix reading, not a full download.
				if err != nil || out.BytesRead != 96+(1<<20)+16 || !out.RecordAuthenticated {
					t.Fatalf("bounded 200: %+v %v", out, err)
				}
			} else if err == nil || out.Ext != "" || out.RecordAuthenticated {
				t.Fatalf("HTTP adversary admitted: %+v %v", out, err)
			}
			if m.LeasedBytes() != 0 {
				t.Fatal("HTTP failure leaked lease")
			}
		})
	}
}

func TestMediaRecognitionCancellationAndStop(t *testing.T) {
	for _, stop := range []bool{false, true} {
		t.Run(fmt.Sprintf("stop=%v", stop), func(t *testing.T) {
			data := recognitionFixture(t, 1<<20, false)
			entered := make(chan struct{})
			exited := make(chan struct{})
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Range") == "bytes=0-47" {
					recognitionRange(w, r, data)
					return
				}
				close(entered)
				<-r.Context().Done()
				close(exited)
			}))
			defer srv.Close()
			m := NewMediaRecognizer(MediaRecognitionConfig{})
			defer m.Stop()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan MediaRecognitionResult, 1)
			go func() {
				out, _ := m.RecognizeV3(ctx, srv.Client(), srv.URL, "recognition-fixture", nil, int64(len(data)))
				done <- out
			}()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("record request not entered")
			}
			if m.LeasedBytes() == 0 {
				t.Fatal("missing active record lease")
			}
			if stop {
				m.Stop()
			} else {
				cancel()
			}
			select {
			case out := <-done:
				if out.RecordAuthenticated || out.Ext != "" {
					t.Fatalf("cancel published evidence: %+v", out)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("cancellation did not join")
			}
			select {
			case <-exited:
			case <-time.After(3 * time.Second):
				t.Fatal("HTTP work not cancelled")
			}
			if m.LeasedBytes() != 0 {
				t.Fatal("cancelled work retained lease")
			}
			if stop {
				out, err := m.RecognizeV3(context.Background(), srv.Client(), srv.URL, "recognition-fixture", nil, int64(len(data)))
				if err == nil || !strings.HasPrefix(out.Reason, "budget_rejected") {
					t.Fatal("Stop reopened admission")
				}
			}
		})
	}
}
