package handler

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alist-encrypt-go/internal/dao"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

func snapshotSizePayload(t *testing.T, info *dao.FileInfo, observed int64) []byte {
	t.Helper()
	payload, err := json.Marshal(map[string]interface{}{"code": 200, "data": map[string]interface{}{"content": []map[string]interface{}{{"name": "plain.mp4", "path": info.Path, "size": -1, "is_dir": false, snapshotCipherSizeKey: observed, snapshotRawPathKey: info.EncryptedPath}}}})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestSnapshotSizeOverlaysCurrentCanonicalProof(t *testing.T) {
	h, files, rule := newCanonicalPropfindFixture(t)
	h.cfg.AlistServer.PasswdList = append(h.cfg.AlistServer.PasswdList, *rule)
	keys := dao.NewPasswdDAO(nil, h.cfg)
	h.passwdDAO = keys
	t.Cleanup(keys.Stop)
	info := canonicalPropfindInfo(h, rule, encryption.ContentVersionV2)
	// Content-only encryption keeps the raw and display paths identical.
	info.EncryptedPath = info.Path
	info.GeometryIdentity = playbackIdentity(h.cfg, h.cfg.GetAlistURL(), info.EncryptedPath, rule, nil)
	payload := snapshotSizePayload(t, info, info.CiphertextSize)
	before := h.buildSnapshotMultistatus("/encrypt", payload)
	if len(before) == 0 || !strings.Contains(string(before), "404 Not Found") {
		t.Fatalf("cold snapshot must mark size unavailable: %s", before)
	}
	if !files.PublishConfirmedPlayback(info, files.PlaybackEpoch(info.Path)) {
		t.Fatal("publish")
	}
	after := h.buildSnapshotMultistatus("/encrypt", payload)
	entries := h.parsePropfindEntries(after)
	if len(entries) != 2 || entries[1].Size != info.Size {
		t.Fatalf("snapshot did not overlay proof: %+v", entries)
	}
	if strings.Contains(string(after), "404 Not Found") {
		t.Fatalf("confirmed size stayed negative: %s", after)
	}
	files.InvalidateDisplayPath(info.Path)
	revoked := h.buildSnapshotMultistatus("/encrypt", payload)
	if !strings.Contains(string(revoked), "404 Not Found") {
		t.Fatal("revoked proof was served from snapshot")
	}
}

func TestSnapshotSizeRejectsUnprovenOrMismatchedTransport(t *testing.T) {
	h, files, rule := newCanonicalPropfindFixture(t)
	h.cfg.AlistServer.PasswdList = append(h.cfg.AlistServer.PasswdList, *rule)
	keys := dao.NewPasswdDAO(nil, h.cfg)
	h.passwdDAO = keys
	t.Cleanup(keys.Stop)
	info := canonicalPropfindInfo(h, rule, encryption.ContentVersionV2)
	info.EncryptedPath = info.Path
	info.GeometryIdentity = playbackIdentity(h.cfg, h.cfg.GetAlistURL(), info.EncryptedPath, rule, nil)
	if !files.PublishConfirmedPlayback(info, files.PlaybackEpoch(info.Path)) {
		t.Fatal("publish")
	}
	old := []byte(`{"code":200,"data":{"content":[{"name":"plain.mp4","path":"/encrypt/plain.mp4","size":999,"is_dir":false}]}}`)
	if body := h.buildSnapshotMultistatus("/encrypt", old); body != nil {
		t.Fatalf("old ambiguous snapshot must refetch directory: %s", body)
	}
	mismatched := h.buildSnapshotMultistatus("/encrypt", snapshotSizePayload(t, info, info.CiphertextSize+1))
	if !strings.Contains(string(mismatched), "404 Not Found") {
		t.Fatalf("changed ciphertext must not reuse old size: %s", mismatched)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(snapshotSizePayload(t, info, info.CiphertextSize), &payload); err != nil {
		t.Fatal(err)
	}
	item := payload["data"].(map[string]interface{})["content"].([]interface{})[0].(map[string]interface{})
	item[snapshotRawPathKey] = "/encrypt/different.bin"
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if h.buildSnapshotMultistatus("/encrypt", body) != nil {
		t.Fatal("snapshot observation for a different object reused")
	}
}

func TestSnapshotSizeETagFollowsEffectiveSize(t *testing.T) {
	h, files, rule := newCanonicalPropfindFixture(t)
	h.cfg.AlistServer.PasswdList = append(h.cfg.AlistServer.PasswdList, *rule)
	keys := dao.NewPasswdDAO(nil, h.cfg)
	h.passwdDAO = keys
	t.Cleanup(keys.Stop)
	info := canonicalPropfindInfo(h, rule, encryption.ContentVersionV2)
	info.EncryptedPath = info.Path
	info.GeometryIdentity = playbackIdentity(h.cfg, h.cfg.GetAlistURL(), info.EncryptedPath, rule, nil)
	payload := strings.Replace(string(snapshotSizePayload(t, info, info.CiphertextSize)), `"size":-1`, `"modified":"2026-10-24T00:00:00Z","size":-1`, 1)
	if body := h.buildSnapshotMultistatus("/encrypt", []byte(payload)); strings.Contains(string(body), "<D:getetag>") {
		t.Fatal("unknown size generated a size-derived ETag")
	}
	if !files.PublishConfirmedPlayback(info, files.PlaybackEpoch(info.Path)) {
		t.Fatal("publish")
	}
	body := string(h.buildSnapshotMultistatus("/encrypt", []byte(payload)))
	if !strings.Contains(body, "-4096</D:getetag>") || strings.Contains(body, "--1</D:getetag>") {
		t.Fatalf("ETag did not follow canonical plaintext size: %s", body)
	}
}

func TestSnapshotRejectsDifferentProvider(t *testing.T) {
	h, dirStore, _ := newWebDAVSnapshotTestHandler(t)
	dir := "/156联通云盘/encrypt"
	seedDirSnapshot(t, dirStore, dir, buildDirScopeKey(dir, "anon"), []map[string]interface{}{{"name": "plain.mp4", "path": dir + "/plain.mp4", "size": 123, "is_dir": false}})
	r := httptest.NewRequest("PROPFIND", "/dav"+dir+"/", nil)
	r.Header.Set("Depth", "1")
	h.cfg.AlistServer.ServerHost = "another-upstream.invalid"
	if _, ok := h.serveSnapshotListing(r, dir); ok {
		t.Fatal("snapshot from previous upstream was reused")
	}
}

func TestPersistSnapshotRetainsObservedCipherNotAdjustedSize(t *testing.T) {
	h, dirStore, _ := newWebDAVSnapshotTestHandler(t)
	rule, _ := h.passwdDAO.FindByPath("/156联通云盘/encrypt/plain.mp4")
	raw := encryption.NewFileNameConverter(rule.Password, rule.EncType, rule.EncSuffix).ToRealName("plain.mp4")
	display := "/156联通云盘/encrypt/plain.mp4"
	r := httptest.NewRequest("PROPFIND", "/dav/156联通云盘/encrypt/", nil)
	// A stale global alias must not change which original response is paired.
	h.fileDAO.SetEncPathMapping(display, "/156联通云盘/encrypt/wrong-sibling.bin")
	h.persistWebDAVSnapshot(r, "/156联通云盘/encrypt", []propfindEntry{{Path: display, Name: "plain.mp4", Size: -1}}, []propfindEntry{{Path: "/156联通云盘/encrypt/" + raw, Size: 4128}})
	snap, ok, err := dirStore.GetSnapshot(r.Context(), buildDirScopeKey("/156联通云盘/encrypt", "anon"))
	if err != nil || !ok {
		t.Fatalf("snapshot missing %v", err)
	}
	var result struct {
		Data struct {
			Content []map[string]interface{} `json:"content"`
		} `json:"data"`
	}
	if err := json.Unmarshal(snap.PayloadJSON, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Data.Content) != 1 {
		t.Fatalf("items %d", len(result.Data.Content))
	}
	item := result.Data.Content[0]
	if item[snapshotCipherSizeKey] != float64(4128) || item["size"] != float64(-1) {
		t.Fatalf("transport provenance lost: %+v", item)
	}
	if item[snapshotRawPathKey] != "/156联通云盘/encrypt/"+raw {
		t.Fatal("observed object missing")
	}
}
