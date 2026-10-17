package handler

import (
	"fmt"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
)

type negativeEpochFixture struct{ epoch uint64 }

func (e *negativeEpochFixture) PlaybackEpoch(string) uint64 { return e.epoch }

func TestTrustedNegativeCacheDynamicTTLAndEpoch(t *testing.T) {
	cfg := config.LoadFromBaseDir(t.TempDir())
	settings := cfg.AlistServerSnapshot()
	settings.NegativeCacheMinutes = 120
	settings.PlaybackProfile = config.PlaybackProfileStandard
	if err := cfg.UpdateAlistServer(settings); err != nil {
		t.Fatal(err)
	}
	epoch := &negativeEpochFixture{}
	cache := newWebDAVNegativePathCache(cfg, epoch)
	now := time.Unix(1700000000, 0)
	cache.now = func() time.Time { return now }
	cache.Block("/existing-miss")
	now = now.Add(time.Minute)
	if !cache.IsBlocked("/existing-miss") {
		t.Fatal("standard TTL changed")
	}
	settings.PlaybackProfile = config.PlaybackProfileTrustedLocal
	if err := cfg.UpdateAlistServer(settings); err != nil {
		t.Fatal(err)
	}
	if cache.IsBlocked("/existing-miss") {
		t.Fatal("old standard negative survived trusted profile change")
	}
	cache.Block("/new-miss")
	if !cache.IsBlocked("/new-miss") {
		t.Fatal("short trusted backoff missing")
	}
	now = now.Add(2 * time.Second)
	if cache.IsBlocked("/new-miss") {
		t.Fatal("trusted miss survived two-second cap")
	}
	cache.Block("/uploaded")
	epoch.epoch++ // LP2 successful mutation / explicit refresh increments DAO epoch.
	if cache.IsBlocked("/uploaded") {
		t.Fatal("mutation epoch did not invalidate negative immediately")
	}
	cache.Block("/configured")
	settings.RequestTimeoutSeconds++
	if err := cfg.UpdateAlistServer(settings); err != nil {
		t.Fatal(err)
	}
	if cache.IsBlocked("/configured") {
		t.Fatal("configuration revision did not invalidate negative")
	}
	cache.Block("/disabled")
	settings.NegativeCacheMinutes = 0
	if err := cfg.UpdateAlistServer(settings); err != nil {
		t.Fatal(err)
	}
	if cache.IsBlocked("/disabled") {
		t.Fatal("runtime disabled cache still blocked")
	}
	cache.Block("/never-record")
	if len(cache.data) != 0 {
		t.Fatal("disabled cache retained entries")
	}
	settings.NegativeCacheMinutes = 120
	if err := cfg.UpdateAlistServer(settings); err != nil {
		t.Fatal(err)
	}
	cache.Block("/reenabled")
	if !cache.IsBlocked("/reenabled") {
		t.Fatal("runtime reenable required restart")
	}
}

func TestNegativeCacheBoundCleanupAndExplicitClear(t *testing.T) {
	cache := newNegativePathCache(time.Minute)
	now := time.Unix(1700000000, 0)
	cache.now = func() time.Time { return now }
	for i := 0; i < negativePathCacheLimit+100; i++ {
		cache.Block(fmt.Sprintf("/miss/%d", i))
	}
	if len(cache.data) > negativePathCacheLimit {
		t.Fatalf("unbounded negative map: %d", len(cache.data))
	}
	now = now.Add(time.Minute)
	cache.Block("/fresh")
	if len(cache.data) != 1 {
		t.Fatalf("expired entries not lazily removed: %d", len(cache.data))
	}
	cache.Delete("/fresh")
	if cache.IsBlocked("/fresh") {
		t.Fatal("explicit delete failed")
	}
	cache.Block("/another")
	cache.Clear()
	if len(cache.data) != 0 {
		t.Fatal("explicit clear failed")
	}
}
