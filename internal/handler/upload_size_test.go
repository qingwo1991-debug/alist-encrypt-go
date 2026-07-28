package handler

import (
	"net/http/httptest"
	"testing"
)

func TestResolveUploadFileSizeByContentLength(t *testing.T) {
	req := httptest.NewRequest("PUT", "/dav/encrypt/a.bin", nil)
	req.Header.Set("Content-Length", "1234")

	size, err := resolveUploadFileSize(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if size != 1234 {
		t.Fatalf("size=%d, want 1234", size)
	}
}

func TestResolveUploadFileSizeByContentRange(t *testing.T) {
	req := httptest.NewRequest("PUT", "/dav/encrypt/a.bin", nil)
	req.Header.Set("Content-Range", "bytes 0-1023/4096")

	size, err := resolveUploadFileSize(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if size != 4096 {
		t.Fatalf("size=%d, want 4096", size)
	}
}

func TestResolveUploadFileSizePrefersContentRangeTotalOverChunkLength(t *testing.T) {
	req := httptest.NewRequest("PUT", "/dav/encrypt/a.bin", nil)
	req.Header.Set("Content-Length", "1024")
	req.Header.Set("Content-Range", "bytes 1024-2047/4096")

	size, err := resolveUploadFileSize(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if size != 4096 {
		t.Fatalf("size=%d, want Content-Range total 4096", size)
	}
}

func TestResolveUploadFileSizePrefersExplicitTotalOverChunkLength(t *testing.T) {
	req := httptest.NewRequest("PUT", "/dav/encrypt/a.bin", nil)
	req.Header.Set("Content-Length", "1024")
	req.Header.Set("X-File-Size", "4096")

	size, err := resolveUploadFileSize(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if size != 4096 {
		t.Fatalf("size=%d, want explicit total 4096", size)
	}
}

func TestResolveUploadFileSizeMissing(t *testing.T) {
	req := httptest.NewRequest("PUT", "/dav/encrypt/a.bin", nil)

	if _, err := resolveUploadFileSize(req); err == nil {
		t.Fatal("expected error when upload size is unknown")
	}
}

func TestResolveUploadFileSizeByExpectedEntityLength(t *testing.T) {
	req := httptest.NewRequest("PUT", "/dav/encrypt/a.bin", nil)
	req.Header.Set("X-Expected-Entity-Length", "8192")

	size, err := resolveUploadFileSize(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if size != 8192 {
		t.Fatalf("size=%d, want 8192", size)
	}
}

func TestParseContentRangeStart(t *testing.T) {
	start, ok, err := parseContentRangeStart("bytes 1024-2047/4096")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected ok=true")
	}
	if start != 1024 {
		t.Fatalf("start=%d, want 1024", start)
	}
}

func TestParseContentRangeStartInvalid(t *testing.T) {
	_, ok, err := parseContentRangeStart("bytes abc-2047/4096")
	if err == nil {
		t.Fatal("expected error for invalid range start")
	}
	if !ok {
		t.Fatal("expected ok=true when header is present")
	}
}

func TestParseContentRangeRejectsInvalidEndAndTotal(t *testing.T) {
	for _, value := range []string{
		"bytes 10-9/20",
		"bytes 0-nope/20",
		"bytes 0-20/20",
		"bytes 0-9/nope",
		"bytes 0-9/20/extra",
	} {
		t.Run(value, func(t *testing.T) {
			if _, ok, err := parseContentRangeStart(value); err == nil || !ok {
				t.Fatalf("parseContentRangeStart(%q)=(ok=%v, err=%v), want present error", value, ok, err)
			}
		})
	}
}

func TestValidateUploadContentRangeChecksSizeAndBodyLength(t *testing.T) {
	if _, _, err := validateUploadContentRange("bytes 0-9/20", 19, 10); err == nil {
		t.Fatal("expected total/file size mismatch")
	}
	if _, _, err := validateUploadContentRange("bytes 0-9/20", 20, 9); err == nil {
		t.Fatal("expected body length mismatch")
	}
	start, ok, err := validateUploadContentRange("bytes 10-19/*", 20, 10)
	if err != nil || !ok || start != 10 {
		t.Fatalf("wildcard total with explicit file size: start=%d ok=%v err=%v", start, ok, err)
	}
}
