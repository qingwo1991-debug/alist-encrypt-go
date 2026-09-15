package handler

import (
	"net/http"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/storage"
)

func TestMaybeEnqueueNextEpisodeWarmup(t *testing.T) {
	cfg := config.DefaultConfig()
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	fileDAO := dao.NewFileDAO(store)

	// Pre-cache the current episode AND its next sibling as if a directory
	// listing had already populated them (the real 连播 data source).
	if err := fileDAO.Set(&dao.FileInfo{
		Path:          "/drama/第01集.mp4",
		EncryptedPath: "/drama/第01集.mp4",
		Size:          1024,
		IsDir:         false,
	}); err != nil {
		t.Fatal(err)
	}
	if err := fileDAO.Set(&dao.FileInfo{
		Path:          "/drama/第02集.mp4",
		EncryptedPath: "/drama/第02集.mp4",
		Size:          2048,
		IsDir:         false,
	}); err != nil {
		t.Fatal(err)
	}

	ps := &ProbeScheduler{
		cfg:          cfg,
		fileDAO:      fileDAO,
		enabled:      true,
		queue:        make(chan probeItem, 16),
		seen:         make(map[string]time.Time),
		providerSem:  make(map[string]chan struct{}),
		minSizeBytes: 0,
	}
	req := decryptPlaybackRequest{
		Config:   cfg,
		Probe:    ps,
		FileDAO:  fileDAO,
		FileItem: FileItem{DisplayPath: "/drama/第01集.mp4"},
	}

	auth := make(http.Header)
	auth.Set("Authorization", "Bearer test-token")
	maybeEnqueueNextEpisodeWarmup(req, auth)

	if len(ps.queue) != 1 {
		t.Fatalf("queue len=%d, want 1", len(ps.queue))
	}
	item := <-ps.queue
	if item.file.DisplayPath != "/drama/第02集.mp4" {
		t.Fatalf("enqueued display=%q, want /drama/第02集.mp4", item.file.DisplayPath)
	}
	if item.file.CompatStorageKey != "/" {
		t.Fatalf("compat key=%q", item.file.CompatStorageKey)
	}
	if item.file.TargetURL == "" {
		t.Fatal("expected non-empty TargetURL for next episode")
	}
	if item.source != probeSourceFirstFrame {
		t.Fatalf("source=%q, want %q", item.source, probeSourceFirstFrame)
	}
}

func TestMaybeEnqueueNextEpisodeWarmupSkipsMissingSibling(t *testing.T) {
	cfg := config.DefaultConfig()
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	fileDAO := dao.NewFileDAO(store)
	// Only episode 1 exists locally; episode 2 never listed -> no enqueue.
	if err := fileDAO.Set(&dao.FileInfo{
		Path:          "/drama/第01集.mp4",
		EncryptedPath: "/drama/第01集.mp4",
		Size:          1024,
	}); err != nil {
		t.Fatal(err)
	}
	ps := &ProbeScheduler{
		cfg:          cfg,
		fileDAO:      fileDAO,
		enabled:      true,
		queue:        make(chan probeItem, 1),
		providerSem:  make(map[string]chan struct{}),
		minSizeBytes: 0,
	}
	req := decryptPlaybackRequest{
		Config:   cfg,
		Probe:    ps,
		FileDAO:  fileDAO,
		FileItem: FileItem{DisplayPath: "/drama/第01集.mp4"},
	}
	maybeEnqueueNextEpisodeWarmup(req, nil)
	if len(ps.queue) != 0 {
		t.Fatalf("queue len=%d, want 0 for missing sibling", len(ps.queue))
	}
}
