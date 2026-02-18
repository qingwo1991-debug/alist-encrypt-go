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
