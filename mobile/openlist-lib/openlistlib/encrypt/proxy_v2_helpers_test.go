package encrypt

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"testing"
)

type v2ProbeRoundTripper func(*http.Request) (*http.Response, error)

func (f v2ProbeRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func v1ProbeResponse(req *http.Request, bodyLen int) *http.Response {
	body := bytes.Repeat([]byte{0x6c}, bodyLen)
	return &http.Response{
		StatusCode: http.StatusPartialContent,
		Header: http.Header{
			"Content-Range":  []string{"bytes 0-31/4096"},
			"Content-Length": []string{"32"},
		},
		Body:    io.NopCloser(bytes.NewReader(body)),
		Request: req,
	}
}

func TestInspectEncryptedContentFallbackOnlyForUnconfirmedProbe(t *testing.T) {
	tests := []struct {
		name      string
		initial   func(*http.Request) (*http.Response, error)
		wantCalls []string
	}{
		{
			name: "confirmed V1 stops immediately",
			initial: func(req *http.Request) (*http.Response, error) {
				return v1ProbeResponse(req, int(ContentHeaderSize())), nil
			},
			wantCalls: []string{"initial:/raw/video.bin"},
		},
		{
			name: "short prefix falls back",
			initial: func(req *http.Request) (*http.Response, error) {
				return v1ProbeResponse(req, int(ContentHeaderSize())-1), nil
			},
			wantCalls: []string{"initial:/raw/video.bin", "alist:/dav/video.bin"},
		},
		{
			name: "authorization failure falls back",
			initial: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusUnauthorized,
					Header:     make(http.Header),
					Body:       io.NopCloser(bytes.NewReader(nil)),
					Request:    req,
				}, nil
			},
			wantCalls: []string{"initial:/raw/video.bin", "alist:/dav/video.bin"},
		},
		{
			name: "network failure falls back",
			initial: func(_ *http.Request) (*http.Response, error) {
				return nil, errors.New("network unavailable")
			},
			wantCalls: []string{"initial:/raw/video.bin", "alist:/dav/video.bin"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := make([]string, 0, 3)
			client := &http.Client{Transport: v2ProbeRoundTripper(func(req *http.Request) (*http.Response, error) {
				switch req.URL.Host {
				case "initial.local":
					calls = append(calls, "initial:"+req.URL.Path)
					return tt.initial(req)
				case "alist.local:5244":
					calls = append(calls, "alist:"+req.URL.Path)
					if req.URL.Path == "/dav/video.bin" {
						return v1ProbeResponse(req, int(ContentHeaderSize())), nil
					}
					return &http.Response{
						StatusCode: http.StatusNotFound,
						Header:     make(http.Header),
						Body:       io.NopCloser(bytes.NewReader(nil)),
						Request:    req,
					}, nil
				default:
					return nil, errors.New("unexpected probe host: " + req.URL.Host)
				}
			})}
			p := &ProxyServer{
				config: &ProxyConfig{
					AlistHost: "alist.local",
					AlistPort: 5244,
				},
				streamClient: client,
			}
			encPath := &EncryptPath{Password: "test", EncType: EncTypeAESCTR, Enable: true}

			meta := p.inspectEncryptedContentWithFallback(
				context.Background(),
				"http://initial.local/raw/video.bin",
				make(http.Header),
				encPath,
				4096,
				"/video.bin",
			)
			if meta.Version != ContentVersionV1 || meta.PlainSize != 4096 {
				t.Fatalf("meta=%+v, want confirmed V1", meta)
			}
			if !reflect.DeepEqual(calls, tt.wantCalls) {
				t.Fatalf("probe calls=%v, want %v", calls, tt.wantCalls)
			}
		})
	}
}
