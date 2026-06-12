package handler

import (
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/dao"
)

func TestCachedRawURLFreshHonorsSignedURLExpiry(t *testing.T) {
	signedAt := time.Now().UTC().Add(-20 * time.Minute)
	expiredURL := "https://cdn.example/movie.bin?X-Amz-Date=" + signedAt.Format("20060102T150405Z") + "&X-Amz-Expires=900"
	info := &dao.FileInfo{
		RawURL:            expiredURL,
		UpstreamFetchedAt: time.Now().Add(-20 * time.Minute),
	}
	if cachedRawURLFresh(info, 30*time.Minute) {
		t.Fatal("expected expired signed URL to be treated as stale")
	}

	freshSignedAt := time.Now().UTC().Add(-5 * time.Minute)
	freshURL := "https://cdn.example/movie.bin?X-Amz-Date=" + freshSignedAt.Format("20060102T150405Z") + "&X-Amz-Expires=900"
	info.RawURL = freshURL
	info.UpstreamFetchedAt = time.Now().Add(-5 * time.Minute)
	if !cachedRawURLFresh(info, 30*time.Minute) {
		t.Fatal("expected signed URL within expiry window to stay fresh")
	}
}
