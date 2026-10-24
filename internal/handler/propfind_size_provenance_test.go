package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path"
	"testing"

	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/proxy"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

func seedPropfindSizeProofPair(t *testing.T, ps *ProbeScheduler, file FileItem) []*dao.FileInfo {
	t.Helper()
	var proofs []*dao.FileInfo
	for i := 0; i < 2; i++ {
		info := canonicalPropfindInfo(&WebDAVHandler{cfg: ps.cfg}, file.PasswdInfo, encryption.ContentVersionV2)
		info.Path, info.EncryptedPath = file.DisplayPath, file.EncryptedPath
		if i == 1 {
			info.Path, info.EncryptedPath = "/encrypt/Show.EP02.mp4", "/encrypt/raw02.bin"
		}
		info.Name = path.Base(info.Path)
		info.GeometryIdentity = playbackIdentity(ps.cfg, ps.cfg.GetAlistURL(), info.EncryptedPath, file.PasswdInfo, nil)
		if !ps.fileDAO.PublishConfirmedPlayback(info, ps.fileDAO.PlaybackEpoch(info.Path)) {
			t.Fatal("publish proof pair")
		}
		proofs = append(proofs, info)
	}
	return proofs
}

func assertPropfindSizeProofPairUnchanged(t *testing.T, ps *ProbeScheduler, epoch uint64, proofs []*dao.FileInfo) {
	t.Helper()
	if got := ps.fileDAO.PlaybackEpoch(proofs[0].Path); got != epoch {
		t.Fatalf("plaintext warmup changed global playback epoch: got %d want %d", got, epoch)
	}
	for _, proof := range proofs {
		if got, hit := ps.fileDAO.GetConfirmedPlayback(proof.GeometryIdentity); !hit || got.Size != proof.Size || got.CiphertextSize != proof.CiphertextSize {
			t.Fatal("plaintext warmup cleared or changed canonical proof")
		}
	}
	if len(ps.queue) != 0 || len(ps.waiting) != 0 || len(ps.pending) != 0 {
		t.Fatal("plaintext warmup acquired size-only admission")
	}
}

func TestPropfindSizeGenericWarmupCannotClaimCiphertextAuthority(t *testing.T) {
	ps, file := newPropfindSizeScheduler(t, "http://127.0.0.1:5244", 4)
	proofs := seedPropfindSizeProofPair(t, ps, file)
	epoch := ps.fileDAO.PlaybackEpoch(file.DisplayPath)
	auth := http.Header{"Authorization": []string{"Basic caller"}}
	// A source label does not prove that the size is a transport observation.
	for _, source := range []string{probeSourceFirstFrame, probeSourceFSList, probeSourcePropfind, probeSourceStartupScan, probeSourceDirSync, probeSourceUnspecified} {
		ps.EnqueueWithSource(file, auth, proofs[0].Size, source)
		assertPropfindSizeProofPairUnchanged(t, ps, epoch, proofs)
	}
	ps.EnqueueWithSize(file, auth, proofs[0].Size)
	ps.Enqueue(file, auth)
	assertPropfindSizeProofPairUnchanged(t, ps, epoch, proofs)
}

func TestPropfindSizeSuccessfulGETWarmupPreservesCanonicalProofs(t *testing.T) {
	ps, file := newPropfindSizeScheduler(t, "http://127.0.0.1:5244", 4)
	file.DisplayPath, file.EncryptedPath, file.FileName = "/encrypt/Show.EP01.mp4", "/encrypt/raw01.bin", "Show.EP01.mp4"
	proofs := seedPropfindSizeProofPair(t, ps, file)
	if nextEpisodeSiblingDisplayPath(file.DisplayPath) != proofs[1].Path {
		t.Fatal("GET fixture must exercise the cached next-episode callback")
	}
	epoch := ps.fileDAO.PlaybackEpoch(file.DisplayPath)
	sp := &startedPlaybackStreamer{strategy: proxy.StreamStrategyRange, payload: []byte("success"), outcomes: []*proxy.StreamOutcome{{StatusCode: http.StatusPartialContent, ResponseStarted: true, BytesWritten: 7, ExpectedBytes: 7}}}
	r := httptest.NewRequest(http.MethodGet, "/dav"+file.DisplayPath, nil)
	r.Header.Set("Authorization", "Basic caller")
	r.Header.Set("Range", "bytes=0-6")
	rr := httptest.NewRecorder()
	executeDecryptPlayback(decryptPlaybackRequest{ResponseWriter: rr, Request: r, Config: ps.cfg, Probe: ps, StreamProxy: sp, FileDAO: ps.fileDAO, PasswdInfo: file.PasswdInfo, FileItem: file, TargetURL: file.TargetURL, InitialSize: proofs[0].Size, ConsumerScenario: consumerScenarioWebDAV})
	if rr.Code != http.StatusPartialContent || rr.Body.String() != "success" || sp.calls != 1 || sp.hints != 1 {
		t.Fatalf("successful GET fixture failed: status=%d calls=%d hints=%d", rr.Code, sp.calls, sp.hints)
	}
	// Both the next-episode first-byte callback and the completed GET warmup
	// carry plaintext lengths, neither may revoke this or another file's proof.
	assertPropfindSizeProofPairUnchanged(t, ps, epoch, proofs)
}

func TestPropfindSizeFsGetPlaintextPreservesCanonicalProofs(t *testing.T) {
	ps, file := newPropfindSizeScheduler(t, "http://127.0.0.1:5244", 4)
	file.EncryptedPath = file.DisplayPath // Content-only rule in this fixture.
	proofs := seedPropfindSizeProofPair(t, ps, file)
	epoch := ps.fileDAO.PlaybackEpoch(file.DisplayPath)
	keys := dao.NewPasswdDAO(nil, ps.cfg)
	t.Cleanup(keys.Stop)
	ph := NewProxyHandler(ps.cfg, ps.stream, ps.fileDAO, keys, nil, nil)
	t.Cleanup(ph.Stop)
	h := NewAlistHandler(ps.cfg, ps.stream, ps.fileDAO, keys, ph, nil, ps)
	t.Cleanup(h.Stop)
	h.httpClient = &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/api/fs/get" {
			t.Fatalf("unexpected fs/get request path %s", r.URL.Path)
		}
		return jsonResponse(http.StatusOK, map[string]interface{}{"code": 200, "data": map[string]interface{}{"name": file.FileName, "raw_url": ps.cfg.GetAlistURL() + "/media", "size": proofs[0].CiphertextSize, "is_dir": false}}), nil
	})}
	body, err := json.Marshal(map[string]interface{}{"path": file.DisplayPath})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/fs/get", bytes.NewReader(body))
	r.Header.Set("Authorization", "Basic caller")
	rr := httptest.NewRecorder()
	h.HandleFsGet(rr, r)
	var result struct {
		Code int `json:"code"`
		Data struct {
			Size int64 `json:"size"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if rr.Code != http.StatusOK || result.Code != 200 || result.Data.Size != proofs[0].Size {
		t.Fatalf("fs/get did not return expected plaintext: status=%d code=%d size=%d", rr.Code, result.Code, result.Data.Size)
	}
	assertPropfindSizeProofPairUnchanged(t, ps, epoch, proofs)
}

func TestPropfindSizeHTTPPlaintextSnapshotPreservesCanonicalProofs(t *testing.T) {
	ps, file := newPropfindSizeScheduler(t, "http://127.0.0.1:5244", 4)
	file.EncryptedPath = file.DisplayPath
	proofs := seedPropfindSizeProofPair(t, ps, file)
	epoch := ps.fileDAO.PlaybackEpoch(file.DisplayPath)
	keys := dao.NewPasswdDAO(nil, ps.cfg)
	t.Cleanup(keys.Stop)
	h := &AlistHandler{cfg: ps.cfg, fileDAO: ps.fileDAO, passwdDAO: keys, probe: ps}
	t.Cleanup(h.Stop)
	body, err := json.Marshal(map[string]interface{}{"code": 200, "data": map[string]interface{}{"content": []map[string]interface{}{{"name": file.FileName, "path": file.DisplayPath, "is_dir": false, "size": proofs[0].Size}}}})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/fs/list", nil)
	r.Header.Set("Authorization", "Basic caller")
	h.enqueueProbeFromSnapshot(r, "/encrypt", body)
	h.Stop() // Join the actual asynchronous snapshot producer, not a timer.
	assertPropfindSizeProofPairUnchanged(t, ps, epoch, proofs)
}

func TestPropfindSizeOriginalDAVObservationKeepsAutomaticAdmission(t *testing.T) {
	for _, source := range []string{probeSourcePropfind, probeSourceStartupScan, probeSourceDirSync} {
		t.Run(source, func(t *testing.T) {
			ps, file := newPropfindSizeScheduler(t, "http://127.0.0.1:5244", 4)
			keys := dao.NewPasswdDAO(nil, ps.cfg)
			t.Cleanup(keys.Stop)
			h := &WebDAVHandler{cfg: ps.cfg, fileDAO: ps.fileDAO, passwdDAO: keys, probe: ps}
			ctx := context.WithValue(withProbeSource(context.Background(), source), webdavAuthContextKey, "Basic caller")
			body := []byte(buildProbeMultistatus([]probeResponse{{href: "/dav/encrypt/", isDir: true}, {href: "/dav" + file.EncryptedPath, size: 4128}}))
			h.parsePropfindResponse(ctx, body, "/encrypt")
			if len(ps.queue) != 1 {
				t.Fatal("original DAV observation was not admitted")
			}
			item := <-ps.queue
			if item.sizeOnly == nil || item.sizeOnly.ciphertextSize != 4128 || item.file.EncryptedPath != file.EncryptedPath || item.source != source {
				t.Fatal("original raw-path/transport-size/source pair was not retained")
			}
		})
	}
}

func TestPropfindSizeProvenDAVSnapshotKeepsAutomaticAdmission(t *testing.T) {
	ps, file := newPropfindSizeScheduler(t, "http://127.0.0.1:5244", 4)
	file.EncryptedPath = file.DisplayPath
	keys := dao.NewPasswdDAO(nil, ps.cfg)
	t.Cleanup(keys.Stop)
	h := &WebDAVHandler{cfg: ps.cfg, fileDAO: ps.fileDAO, passwdDAO: keys, probe: ps}
	payload := snapshotSizePayload(t, &dao.FileInfo{Path: file.DisplayPath, EncryptedPath: file.EncryptedPath}, 4128)
	r := httptest.NewRequest("PROPFIND", "/dav/encrypt/", nil)
	r.Header.Set("Authorization", "Basic caller")
	if body := h.buildSnapshotMultistatus("/encrypt", payload, r); len(body) == 0 {
		t.Fatal("proven DAV snapshot unexpectedly missed")
	}
	if len(ps.queue) != 1 {
		t.Fatal("proven DAV snapshot was not admitted")
	}
	item := <-ps.queue
	if item.sizeOnly == nil || item.sizeOnly.ciphertextSize != 4128 || item.file.EncryptedPath != file.EncryptedPath {
		t.Fatal("snapshot transport provenance was lost")
	}
}

func TestPropfindSizeOriginalDAVPairDoesNotUseStaleAlias(t *testing.T) {
	ps, file := newPropfindSizeScheduler(t, "http://127.0.0.1:5244", 4)
	keys := dao.NewPasswdDAO(nil, ps.cfg)
	t.Cleanup(keys.Stop)
	h := &WebDAVHandler{cfg: ps.cfg, fileDAO: ps.fileDAO, passwdDAO: keys, probe: ps}
	ps.fileDAO.SetEncPathMapping(file.DisplayPath, "/encrypt/stale-sibling.bin")
	ctx := context.WithValue(context.Background(), webdavAuthContextKey, "Basic caller")
	h.enqueueProbeFromPropfind(ctx, file.DisplayPath, file.EncryptedPath, 4128)
	if len(ps.queue) != 1 {
		t.Fatal("original DAV pair was not admitted")
	}
	if item := <-ps.queue; item.file.EncryptedPath != file.EncryptedPath {
		t.Fatal("stale display alias replaced the original observed object")
	}
}
