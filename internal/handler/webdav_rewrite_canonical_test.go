package handler

import (
	"fmt"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/storage"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

func newCanonicalPropfindFixture(t *testing.T) (*WebDAVHandler, *dao.FileDAO, *config.PasswdInfo) {
	t.Helper()
	cfg := config.LoadFromBaseDir(t.TempDir())
	server := cfg.AlistServerSnapshot()
	server.PlaybackProfile = config.PlaybackProfileTrustedLocal
	if err := cfg.UpdateAlistServer(server); err != nil {
		t.Fatal(err)
	}
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	files := dao.NewFileDAO(store, cfg)
	t.Cleanup(func() { files.Stop(); _ = store.Close() })
	rule := &config.PasswdInfo{Enable: true, Password: "test-password", EncType: "aesctr", EncPath: []string{"/encrypt/*"}}
	return &WebDAVHandler{cfg: cfg, fileDAO: files}, files, rule
}

func canonicalPropfindInfo(h *WebDAVHandler, rule *config.PasswdInfo, version int) *dao.FileInfo {
	info := &dao.FileInfo{
		Path: "/encrypt/plain.mp4", EncryptedPath: "/encrypt/raw.bin", Size: 4096,
		CiphertextSize: 4096, ContentVersion: version,
		GeometryConfirmedAt: time.Now(),
	}
	info.GeometryIdentity = playbackIdentity(h.cfg, h.cfg.GetAlistURL(), info.EncryptedPath, rule, nil)
	switch version {
	case encryption.ContentVersionV2:
		info.HeaderLen, info.NonceField = encryption.ContentHeaderSize(), make([]byte, 16)
		info.CiphertextSize = info.Size + info.HeaderLen
	case encryption.ContentVersionV3:
		info.HeaderLen, info.NonceField = encryption.V3HeaderSize, make([]byte, 16)
		info.ChunkSize, info.KDFIterations = 73, 1234
		info.CiphertextSize = encryption.V3CiphertextSize(info.Size, int64(info.ChunkSize))
	}
	return info
}

// Playback persists its ordinary FileInfo by display path, but a directory href
// is raw. Reopening discards the transient raw alias, not the canonical proof.
func TestPropfindCanonicalGeometrySurvivesRestartWithoutRawMirror(t *testing.T) {
	for _, version := range []int{encryption.ContentVersionV1, encryption.ContentVersionV2, encryption.ContentVersionV3} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			h, _, rule := newCanonicalPropfindFixture(t)
			dir := t.TempDir()
			store, err := storage.NewStore(dir)
			if err != nil {
				t.Fatal(err)
			}
			files := dao.NewFileDAO(store, h.cfg)
			info := canonicalPropfindInfo(h, rule, version)
			if !files.PublishConfirmedPlayback(info, files.PlaybackEpoch(info.Path)) {
				t.Fatal("publish confirmation")
			}
			files.Stop()
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			store, err = storage.NewStore(dir)
			if err != nil {
				t.Fatal(err)
			}
			files = dao.NewFileDAO(store, h.cfg)
			t.Cleanup(func() { files.Stop(); _ = store.Close() })
			h.fileDAO = files
			if _, present := files.Get(info.EncryptedPath); present {
				t.Fatal("fixture unexpectedly restored ordinary raw-path mirror")
			}
			if size, known := h.propfindPlainSize(info.EncryptedPath, info.CiphertextSize, rule); !known || size != info.Size {
				t.Fatalf("canonical size=%d known=%v, want %d", size, known, info.Size)
			}
			body := []byte(buildProbeMultistatus([]probeResponse{
				{href: "/dav/encrypt/", isDir: true},
				{href: "/dav" + info.EncryptedPath, size: info.CiphertextSize},
			}))
			entries := h.parsePropfindEntries(h.rewritePropfindBody(body, rule))
			if len(entries) != 2 || !entries[0].IsDir || entries[1].Size != info.Size {
				t.Fatalf("rewritten entries=%+v", entries)
			}
			files.InvalidateDisplayPath(info.Path)
			if _, known := h.propfindPlainSize(info.EncryptedPath, info.CiphertextSize, rule); known {
				t.Fatal("invalidated confirmation survived")
			}
		})
	}
}

func TestPropfindCanonicalGeometryIgnoresIncompleteRawAlias(t *testing.T) {
	h, files, rule := newCanonicalPropfindFixture(t)
	info := canonicalPropfindInfo(h, rule, encryption.ContentVersionV2)
	if !files.PublishConfirmedPlayback(info, files.PlaybackEpoch(info.Path)) {
		t.Fatal("publish confirmation")
	}
	// A transport-only listing may leave an incomplete raw alias. Its Size and
	// version are not authoritative and must not preempt logical-object proof.
	files.SetEncPathMappingWithInfo("/encrypt/listed.mp4", info.EncryptedPath, "listed.mp4", info.CiphertextSize, false)
	if err := files.SetComplete(&dao.FileInfo{Path: info.EncryptedPath, Size: info.CiphertextSize}); err != nil {
		t.Fatal(err)
	}
	if size, known := h.propfindPlainSize(info.EncryptedPath, info.CiphertextSize, rule); !known || size != info.Size {
		t.Fatalf("size=%d known=%v", size, known)
	}
}

func TestPropfindCanonicalGeometryFailsClosed(t *testing.T) {
	for _, name := range []string{"unconfirmed", "expired", "future", "wrong_origin", "wrong_rule", "wrong_path", "ciphertext_changed", "negative_plain", "directory", "unknown_version", "incomplete_v2", "incomplete_v3"} {
		t.Run(name, func(t *testing.T) {
			h, files, rule := newCanonicalPropfindFixture(t)
			info := canonicalPropfindInfo(h, rule, encryption.ContentVersionV2)
			reported := info.CiphertextSize
			switch name {
			case "expired":
				info.GeometryConfirmedAt = time.Now().Add(-25 * time.Hour)
			case "future":
				info.GeometryConfirmedAt = time.Now().Add(time.Hour)
			case "wrong_origin":
				info.GeometryIdentity = playbackIdentity(h.cfg, "https://other.invalid", info.EncryptedPath, rule, nil)
			case "wrong_rule":
				changed := *rule
				changed.Password = "different-password"
				info.GeometryIdentity = playbackIdentity(h.cfg, h.cfg.GetAlistURL(), info.EncryptedPath, &changed, nil)
			case "wrong_path":
				info.EncryptedPath = "/encrypt/other.bin"
			case "ciphertext_changed":
				reported++
			case "negative_plain":
				info.Size = -1
			case "directory":
				info.IsDir = true
			case "unknown_version":
				info.ContentVersion = 0
			case "incomplete_v2":
				info.NonceField = nil
			case "incomplete_v3":
				info = canonicalPropfindInfo(h, rule, encryption.ContentVersionV3)
				info.ChunkSize = 0
				reported = info.CiphertextSize
			}
			if name == "unconfirmed" {
				if err := files.Set(info); err != nil {
					t.Fatal(err)
				}
			} else if !files.PublishConfirmedPlayback(info, files.PlaybackEpoch(info.Path)) {
				t.Fatal("publish fixture")
			}
			if size, known := h.propfindPlainSize("/encrypt/raw.bin", reported, rule); known {
				t.Fatalf("accepted untrusted size %d", size)
			}
		})
	}
}
