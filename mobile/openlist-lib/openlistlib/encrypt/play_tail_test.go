package encrypt

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// TestTryServeEmptyTailRange covers the tail-probe class of media clients that
// seek to the end of an encrypted file using the *ciphertext* size they saw in
// the listing. Their open-ended requests fall just past the plaintext EOF
// (within the V2 header delta). Regression: these must be answered with an
// empty 200 instead of a 416, which made players abort and spin forever.
func TestTryServeEmptyTailRange(t *testing.T) {
	const plainSize = 791550551
	const headerLen = 32 // V2 ciphertext header delta (matches real deploy)

	tests := []struct {
		name           string
		header         string
		size           int64
		headerLen      int64
		want           bool // handled by empty tail?
		wantStatusCode int
	}{
		{
			name:      "no range header",
			header:    "",
			size:      plainSize,
			headerLen: headerLen,
			want:      false,
		},
		{
			name:      "regular bounded range untouched",
			header:    "bytes=0-1023",
			size:      plainSize,
			headerLen: headerLen,
			want:      false,
		},
		{
			name:      "suffix range untouched",
			header:    "bytes=-1024",
			size:      plainSize,
			headerLen: headerLen,
			want:      false,
		},
		{
			name:      "open started well before EOF untouched",
			header:    "bytes=1234-",
			size:      plainSize,
			headerLen: headerLen,
			want:      false,
		},
		{
			name:      "open end exactly at plaintext EOF",
			header:    "bytes=791550551-",
			size:      plainSize,
			headerLen: headerLen,
			want:      true,
		},
		{
			name:      "open end within header delta past EOF",
			header:    "bytes=791550571-",
			size:      plainSize,
			headerLen: headerLen,
			want:      true,
		},
		{
			name:      "open end exactly at ciphertext EOF",
			header:    "bytes=791550583-",
			size:      plainSize,
			headerLen: headerLen,
			want:      true,
		},
		{
			name:      "open end truly past ciphertext EOF still rejected",
			header:    "bytes=791550584-",
			size:      plainSize,
			headerLen: headerLen,
			want:      false,
		},
		{
			name:      "open end past EOF rejects with zero header delta",
			header:    "bytes=791550552-",
			size:      plainSize,
			headerLen: 0,
			want:      false,
		},
		{
			name:      "bounded range starting past EOF not an empty tail",
			header:    "bytes=791550551-791550583",
			size:      plainSize,
			headerLen: headerLen,
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			got := tryServeEmptyTailRange(rec, tt.header, tt.size, tt.headerLen)
			if got != tt.want {
				t.Fatalf("tryServeEmptyTailRange(%q, size=%d, headerLen=%d)=%v, want %v",
					tt.header, tt.size, tt.headerLen, got, tt.want)
			}
			if !tt.want {
				return
			}
			if rec.Code != http.StatusOK {
				t.Fatalf("empty tail status=%d, want 200", rec.Code)
			}
			if rec.Body.Len() != 0 {
				t.Fatalf("empty tail body has %d bytes, want 0", rec.Body.Len())
			}
			if gotCL := rec.Header().Get("Content-Length"); gotCL != "0" {
				t.Fatalf("Content-Length=%q, want \"0\"", gotCL)
			}
			if rec.Header().Get("Accept-Ranges") != "bytes" {
				t.Fatalf("Accept-Ranges missing, headers=%v", rec.Header())
			}
		})
	}
}

// TestTryServeEmptyTailRangeIsNotHitForOrdinaryPlayback confirms the helper is
// a no-op for the normal first-segment seek that players use to start media —
// we must never swallow a valid in-file range request.
func TestTryServeEmptyTailRangeIsNotHitForOrdinaryPlayback(t *testing.T) {
	header := "bytes=0-"
	if tryServeEmptyTailRange(httptest.NewRecorder(), header, 1000, 32) {
		t.Fatalf("open range 0- must not be treated as empty tail")
	}
	if tryServeEmptyTailRange(httptest.NewRecorder(), "bytes=0-999", 1000, 32) {
		t.Fatalf("bounded in-file range must not be swallowed")
	}
}

var _ = strconv.FormatInt // keep import stable across edits
