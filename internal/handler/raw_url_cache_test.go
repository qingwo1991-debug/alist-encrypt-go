package handler

import (
	"net/http"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/dao"
)

func TestCachedRawURLFreshHonorsSignedURLExpiry(t *testing.T) {
	signedAt := time.Now().UTC().Add(-20 * time.Minute)
	expiredURL := "https://cdn.example/movie.bin?X-Amz-Date=" + signedAt.Format("20060102T150405Z") + "&X-Amz-Expires=900"
	info := &dao.FileInfo{
		RawURL:            expiredURL,
		RawURLAuthScope:   "anon",
		UpstreamFetchedAt: time.Now().Add(-20 * time.Minute),
	}
	if cachedRawURLFresh(info, 30*time.Minute, "anon") {
		t.Fatal("expected expired signed URL to be treated as stale")
	}

	freshSignedAt := time.Now().UTC().Add(-5 * time.Minute)
	freshURL := "https://cdn.example/movie.bin?X-Amz-Date=" + freshSignedAt.Format("20060102T150405Z") + "&X-Amz-Expires=900"
	info.RawURL = freshURL
	info.UpstreamFetchedAt = time.Now().Add(-5 * time.Minute)
	if !cachedRawURLFresh(info, 30*time.Minute, "anon") {
		t.Fatal("expected signed URL within expiry window to stay fresh")
	}
}

func TestCachedRawURLFreshRequiresExactAuthScope(t *testing.T) {
	userA := make(http.Header)
	userA.Set("Authorization", "Bearer user-a")
	userA.Set("Cookie", "session=a")
	userB := make(http.Header)
	userB.Set("Authorization", "Bearer user-b")
	userB.Set("Cookie", "session=b")
	info := &dao.FileInfo{
		RawURL:            "https://cdn.example/file",
		RawURLAuthScope:   rawURLAuthScope(userA),
		UpstreamFetchedAt: time.Now(),
	}

	if !cachedRawURLFresh(info, 30*time.Minute, rawURLAuthScope(userA)) {
		t.Fatal("same auth scope should reuse a fresh raw URL")
	}
	if cachedRawURLFresh(info, 30*time.Minute, rawURLAuthScope(userB)) {
		t.Fatal("user B reused user A raw URL")
	}
	if cachedRawURLFresh(info, 30*time.Minute, rawURLAuthScope(nil)) {
		t.Fatal("anonymous caller reused user A raw URL")
	}
	info.RawURLAuthScope = ""
	if cachedRawURLFresh(info, 30*time.Minute, rawURLAuthScope(userA)) {
		t.Fatal("legacy empty-scope raw URL was reused")
	}
}
