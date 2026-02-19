package handler

import (
	"testing"

	"github.com/alist-encrypt-go/internal/config"
)

func TestBuildRangeCompatStorageKey(t *testing.T) {
	passwd := &config.PasswdInfo{
		Enable:  true,
		EncPath: []string{"/encrypt/*", "/media/4k/*", "/misc"},
	}

	got := buildRangeCompatStorageKey(passwd, "/media/4k/movie.mkv")
	if got != "/media/4k" {
		t.Fatalf("storage key=%q, want %q", got, "/media/4k")
	}

	got = buildRangeCompatStorageKey(passwd, "/unknown/path.mp4")
	if got != "/media/4k" {
		t.Fatalf("fallback storage key=%q, want %q", got, "/media/4k")
	}
}
