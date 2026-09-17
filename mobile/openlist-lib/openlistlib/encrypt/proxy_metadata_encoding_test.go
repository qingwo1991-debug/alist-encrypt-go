package encrypt

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type metadataRoundTripFunc func(*http.Request) (*http.Response, error)

func (f metadataRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type metadataTrackedBody struct {
	io.Reader
	closed bool
}

func (b *metadataTrackedBody) Close() error { b.closed = true; return nil }

func metadataGzip(t *testing.T, text string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write([]byte(text)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestMetadataEncoding(t *testing.T) {
	const document = `{"code":200,"data":{"content":[]}}`
	for _, tc := range []struct {
		name, encoding string
		body           []byte
		wantErr        bool
	}{
		{"plain", "", []byte(document), false},
		{"identity", "identity", []byte(document), false},
		{"gzip", "gzip", metadataGzip(t, document), false},
		{"case", " GZip ", metadataGzip(t, document), false},
		{"unsupported", "br", []byte("not decoded"), true},
		{"stacked", "gzip, br", []byte("not decoded"), true},
		{"invalid gzip", "gzip", []byte("plain document"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &metadataTrackedBody{Reader: bytes.NewReader(tc.body)}
			client := &http.Client{Transport: metadataRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				if got := req.Header.Values("Accept-Encoding"); len(got) != 1 || got[0] != "identity" {
					t.Fatalf("negotiation = %v", got)
				}
				return &http.Response{StatusCode: 200, Body: body, Header: http.Header{"Content-Encoding": {tc.encoding}, "Content-Length": {"999"}, "Etag": {"obsolete"}}, ContentLength: 999}, nil
			})}
			req, err := http.NewRequest("POST", "http://metadata.invalid/api/fs/list", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Add("Accept-Encoding", "gzip")
			req.Header.Add("Accept-Encoding", "br")
			resp, err := doMetadataRequest(client, req)
			if tc.wantErr {
				if err == nil || !body.closed {
					t.Fatalf("err=%v closed=%v", err, body.closed)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(resp.Body)
			if err != nil || string(got) != document {
				t.Fatalf("body=%q err=%v", got, err)
			}
			for _, key := range []string{"Content-Encoding", "Content-Length", "ETag"} {
				if resp.Header.Get(key) != "" {
					t.Errorf("retained %s", key)
				}
			}
			if resp.ContentLength != -1 {
				t.Fatal("retained upstream length")
			}
			resp.Body.Close()
			if !body.closed {
				t.Fatal("upstream not closed")
			}
		})
	}
}

func TestMetadataGzipChecksumError(t *testing.T) {
	compressed := metadataGzip(t, "valid text")
	compressed[len(compressed)-8] ^= 1 // Benign damaged gzip checksum fixture.
	resp := &http.Response{Header: http.Header{"Content-Encoding": {"gzip"}}, Body: io.NopCloser(bytes.NewReader(compressed))}
	if err := decodeMetadataResponse(resp); err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if _, err := io.ReadAll(resp.Body); err == nil {
		t.Fatal("checksum error lost")
	}
}

func TestMetadataDoesNotChangeMediaRange(t *testing.T) {
	client := &http.Client{Transport: metadataRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Range") != "bytes=100-199" || req.Header.Get("Accept-Encoding") != "gzip" {
			t.Fatal("media headers changed")
		}
		return &http.Response{StatusCode: 206, Header: http.Header{"Content-Encoding": {"gzip"}, "Content-Range": {"bytes 100-199/1000"}}, Body: io.NopCloser(strings.NewReader("opaque media"))}, nil
	})}
	req, err := http.NewRequest("GET", "http://media.invalid/file", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Range", "bytes=100-199")
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := doWebDAVRequest(client, req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 206 || resp.Header.Get("Content-Encoding") != "gzip" || resp.Header.Get("Content-Range") == "" {
		t.Fatal("media response changed")
	}
}

func TestMetadataResponseCommit(t *testing.T) {
	t.Run("early error", func(t *testing.T) {
		rec := httptest.NewRecorder()
		rec.Header().Set("Content-Encoding", "gzip")
		rec.Header().Set("Content-Length", "999")
		w := &metadataResponseWriter{ResponseWriter: rec, status: 207}
		w.fail()
		if rec.Code != 502 || rec.Header().Get("Content-Encoding") != "" || rec.Header().Get("Content-Length") != "" {
			t.Fatalf("response=%v", rec.Result())
		}
	})
	t.Run("late error aborts", func(t *testing.T) {
		rec := httptest.NewRecorder()
		w := &metadataResponseWriter{ResponseWriter: rec, status: 207}
		_, _ = w.Write([]byte("partial"))
		defer func() {
			if recover() != http.ErrAbortHandler {
				t.Error("late error did not abort stream")
			}
			if rec.Code != 207 || rec.Body.String() != "partial" {
				t.Error("error appended to committed body")
			}
		}()
		w.fail()
	})
}
