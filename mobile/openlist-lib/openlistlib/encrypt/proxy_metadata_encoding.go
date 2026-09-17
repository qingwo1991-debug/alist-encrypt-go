package encrypt

import (
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"strings"
)

// Metadata is parsed/re-encoded locally, unlike byte-range media streams.
// Request identity even when the transport has DisableCompression set: that
// flag disables automatic decoding, not an explicitly forwarded negotiation.
func doMetadataRequest(client *http.Client, req *http.Request) (*http.Response, error) {
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := client.Do(req)
	if err != nil {
		return resp, err
	}
	if err := decodeMetadataResponse(resp); err != nil {
		resp.Body.Close()
		return nil, err
	}
	return resp, nil
}

// doWebDAVRequest deliberately leaves GET/HEAD Range responses unchanged.
func doWebDAVRequest(client *http.Client, req *http.Request) (*http.Response, error) {
	if req.Method == "PROPFIND" {
		return doMetadataRequest(client, req)
	}
	return client.Do(req)
}

type metadataGzipBody struct {
	*gzip.Reader
	upstream io.Closer
}

func (b *metadataGzipBody) Close() error {
	_ = b.Reader.Close()
	return b.upstream.Close()
}

func decodeMetadataResponse(resp *http.Response) error {
	// Joining all field values also rejects stacked/multiple encodings rather
	// than silently treating an undecoded outer layer as JSON/XML.
	encoding := strings.ToLower(strings.TrimSpace(strings.Join(resp.Header.Values("Content-Encoding"), ",")))
	switch encoding {
	case "", "identity":
	case "gzip":
		reader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return errors.New("invalid gzip metadata response")
		}
		resp.Body = &metadataGzipBody{Reader: reader, upstream: resp.Body}
		resp.Uncompressed = true
	default:
		return errors.New("unsupported metadata content encoding")
	}
	clearMetadataRepresentationHeaders(resp.Header)
	resp.ContentLength = -1
	return nil
}

func clearMetadataRepresentationHeaders(h http.Header) {
	h.Del("Content-Encoding")
	h.Del("Content-Length")
	// Validators/digests describe the upstream representation, not our rewrite.
	h.Del("ETag")
	h.Del("Content-MD5")
	h.Del("Digest")
}

// metadataResponseWriter commits the upstream success code only on the first
// validated output chunk. Existing JSON/XML encoder buffers bound the delay;
// large listings still stream. Late parse errors must terminate the stream,
// never append a second HTTP error document to a partial JSON/XML response.
type metadataResponseWriter struct {
	http.ResponseWriter
	status    int
	committed bool
}

func (w *metadataResponseWriter) Write(b []byte) (int, error) {
	if !w.committed {
		clearMetadataRepresentationHeaders(w.Header())
		w.ResponseWriter.WriteHeader(w.status)
		w.committed = true
	}
	return w.ResponseWriter.Write(b)
}

func (w *metadataResponseWriter) fail() {
	if w.committed {
		// net/http closes the connection (or resets the HTTP/2 stream) without
		// logging a stack trace. The client must not accept a truncated listing.
		panic(http.ErrAbortHandler)
	}
	clearMetadataRepresentationHeaders(w.Header())
	http.Error(w.ResponseWriter, "invalid upstream metadata response", http.StatusBadGateway)
}
