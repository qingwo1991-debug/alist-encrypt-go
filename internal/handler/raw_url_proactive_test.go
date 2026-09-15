package handler

import (
	"strconv"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/dao"
)

func signedURL(signedAt time.Time, expiresSec int64) string {
	return "https://cdn.example/movie.bin?X-Amz-Date=" + signedAt.UTC().Format("20060102T150405Z") +
		"&X-Amz-Expires=" + strconv.FormatInt(expiresSec, 10)
}

func TestRawURLNeedsProactiveRefresh(t *testing.T) {
	now := time.Now().UTC()
	makeInfo := func(raw string, fetchedAgo time.Duration) *dao.FileInfo {
		return &dao.FileInfo{
			RawURL:            raw,
			RawURLAuthScope:   "anon",
			UpstreamFetchedAt: now.Add(-fetchedAgo),
		}
	}

	// Signed URL with 5 min of life left, UpstreamFetchedAt fresh: refresh now.
	expiringSoon := signedURL(now.Add(-55*time.Minute), 3600)
	if !rawURLNeedsProactiveRefresh(makeInfo(expiringSoon, 2*time.Minute), now) {
		t.Fatal("expected proactive refresh for URL expiring within the window")
	}

	// URL with hours of life left: no early refresh.
	freshFuture := signedURL(now.Add(-5*time.Minute), 8*3600)
	if rawURLNeedsProactiveRefresh(makeInfo(freshFuture, 2*time.Minute), now) {
		t.Fatal("did not expect proactive refresh for a long-lived URL")
	}

	// Already-expired URL: the sync hot path owns refresh; never background it.
	alreadyExpired := signedURL(now.Add(-2*time.Hour), 3600)
	if rawURLNeedsProactiveRefresh(makeInfo(alreadyExpired, 2*time.Minute), now) {
		t.Fatal("expected NO proactive refresh for an already-expired URL")
	}

	// Unparseable URL (no SigV4/Expires in query): refresh only genuinely old rows.
	stale := makeInfo("https://cdn.example.com/baidu-link", 30*time.Minute)
	if !rawURLNeedsProactiveRefresh(stale, now) {
		t.Fatal("expected proactive refresh for stale unparseable-URL row")
	}
	fresh := makeInfo("https://cdn.example.com/baidu-link", 2*time.Minute)
	if rawURLNeedsProactiveRefresh(fresh, now) {
		t.Fatal("did not expect proactive refresh for a barely-old unparseable row")
	}

	if rawURLNeedsProactiveRefresh(nil, now) {
		t.Fatal("nil info must return false")
	}
	if rawURLNeedsProactiveRefresh(&dao.FileInfo{}, now) {
		t.Fatal("empty info must return false")
	}
}
