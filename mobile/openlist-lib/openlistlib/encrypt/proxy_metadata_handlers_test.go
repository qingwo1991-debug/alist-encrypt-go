package encrypt

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFsMetadataHandlersEncoding(t *testing.T) {
	for _, endpoint := range []string{"list", "get", "link"} {
		for _, mode := range []string{"plain", "gzip", "unsupported", "malformed", "truncated gzip"} {
			t.Run(endpoint+"/"+mode, func(t *testing.T) {
				text := `{"code":200,"data":{"content":[],"raw_url":""}}`
				body := []byte(text)
				encoding := ""
				want := http.StatusOK
				switch mode {
				case "gzip":
					encoding, body = "gzip", metadataGzip(t, text)
				case "unsupported":
					encoding, want = "br", http.StatusBadGateway
				case "malformed":
					body, want = []byte(`{"code":`), http.StatusBadGateway
				case "truncated gzip":
					encoding, body, want = "gzip", metadataGzip(t, text), http.StatusBadGateway
					body = body[:len(body)-4]
				}
				p := &ProxyServer{config: &ProxyConfig{AlistHost: "metadata.invalid", AlistPort: 5244}}
				p.httpClient = &http.Client{Transport: metadataRoundTripFunc(func(req *http.Request) (*http.Response, error) {
					if req.Header.Get("Accept-Encoding") != "identity" {
						t.Fatal("client encoding forwarded")
					}
					return &http.Response{StatusCode: 200, Header: http.Header{"Content-Encoding": {encoding}, "Content-Length": {"999"}}, Body: io.NopCloser(bytes.NewReader(body))}, nil
				})}
				req := httptest.NewRequest("POST", "http://proxy.invalid/api/fs/"+endpoint, strings.NewReader(`{"path":"/"}`))
				req.Header.Set("Accept-Encoding", "gzip, br")
				rec := httptest.NewRecorder()
				switch endpoint {
				case "list":
					p.handleFsList(rec, req)
				case "get":
					p.handleFsGet(rec, req)
				case "link":
					p.handleFsLink(rec, req)
				}
				if rec.Code != want {
					t.Fatalf("status=%d want=%d body=%q", rec.Code, want, rec.Body.String())
				}
				if rec.Header().Get("Content-Encoding") != "" || rec.Header().Get("Content-Length") != "" {
					t.Fatal("obsolete representation headers")
				}
				if want == 200 && !json.Valid(rec.Body.Bytes()) {
					t.Fatalf("invalid output: %s", rec.Body.String())
				}
			})
		}
	}
}

func TestMetadataRewriteInitialValidation(t *testing.T) {
	p := &ProxyServer{}
	for _, input := range []string{"", "ordinary text", "<html/>", "<multistatus>", "<multistatus/>trailing", "<multistatus/><multistatus/>"} {
		t.Run(input, func(t *testing.T) {
			rec := httptest.NewRecorder()
			w := &metadataResponseWriter{ResponseWriter: rec, status: 207}
			if err := p.processPropfindResponse(strings.NewReader(input), w, nil); err == nil {
				t.Fatal("malformed XML accepted")
			}
			if w.committed {
				t.Fatal("small malformed XML committed success")
			}
			w.fail()
			if rec.Code != 502 {
				t.Fatalf("status=%d", rec.Code)
			}
		})
	}
	for _, input := range []string{`[]`, `{"data":`, `{"data":{"content":[]}} {}`, `{"data":[]}`, `{"data":{"content":{}}}`} {
		rec := httptest.NewRecorder()
		w := &metadataResponseWriter{ResponseWriter: rec, status: 200}
		if _, err := p.streamRewriteFsListResponse(w, strings.NewReader(input), "/", nil); err == nil {
			t.Fatalf("malformed listing accepted: %s", input)
		}
		if w.committed {
			t.Fatalf("malformed listing committed: %s", input)
		}
	}
}

func TestMetadataXMLGzipRewrite(t *testing.T) {
	resp := &http.Response{Header: http.Header{"Content-Encoding": {"gzip"}}, Body: io.NopCloser(bytes.NewReader(metadataGzip(t, `<D:multistatus xmlns:D="DAV:"></D:multistatus>`)))}
	if err := decodeMetadataResponse(resp); err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	rec := httptest.NewRecorder()
	w := &metadataResponseWriter{ResponseWriter: rec, status: 207}
	if err := (&ProxyServer{}).processPropfindResponse(resp.Body, w, nil); err != nil {
		t.Fatal(err)
	}
	if rec.Code != 207 || !strings.Contains(rec.Body.String(), "multistatus") {
		t.Fatalf("response=%s", rec.Body.String())
	}
}
