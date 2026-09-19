package handler

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/shared/encryptcore"
)

// --- static key repository -------------------------------------------------

type staticPasswdDAO struct {
	info *config.PasswdInfo
}

func (s *staticPasswdDAO) GetEncPathPrefixes() []string {
	if s.info == nil {
		return nil
	}
	return s.info.EncPath
}
func (s *staticPasswdDAO) FindByPath(urlPath string) (*config.PasswdInfo, bool) {
	if s.info == nil {
		return nil, false
	}
	for _, p := range s.info.EncPath {
		if strings.HasPrefix(urlPath, p) {
			return s.info, true
		}
	}
	return nil, false
}
func (s *staticPasswdDAO) FindByDir(dirPath string) (*config.PasswdInfo, bool) {
	return s.FindByPath(dirPath)
}
func (s *staticPasswdDAO) MatchDir(dirPath string) bool {
	_, ok := s.FindByPath(dirPath)
	return ok
}
func (s *staticPasswdDAO) PathFindPasswd(urlPath string) (*config.PasswdInfo, bool) {
	return s.FindByPath(urlPath)
}

// recordingFileDAO records the heavy per-entry writes that the huge-directory
// budget must bypass: path-cache Set/SetEnc writes. It implements
// ports.FileRepository with no-op reads so an otherwise-idle handler can run.
// metaStore/probe are left nil in the handler, making the meta upsert and probe
// enqueue safe no-ops as well.
type recordingFileDAO struct {
	mu              sync.Mutex
	setCalls        int
	encMappingCalls int
}

func (m *recordingFileDAO) Get(path string) (*dao.FileInfo, bool) { return nil, false }
func (m *recordingFileDAO) Delete(path string) error              { return nil }
func (m *recordingFileDAO) List(limit int) []*dao.FileInfo         { return nil }
func (m *recordingFileDAO) SetEncPathMapping(displayPath, encryptedPath string) {
	m.mu.Lock()
	m.encMappingCalls++
	m.mu.Unlock()
}
func (m *recordingFileDAO) SetEncPathMappingWithInfo(displayPath, encryptedPath, name string, size int64, isDir bool) {
	m.mu.Lock()
	m.encMappingCalls++
	m.mu.Unlock()
}
func (m *recordingFileDAO) GetEncPath(displayPath string) (string, bool) { return "", false }
func (m *recordingFileDAO) HasEncryptedPath(encryptedPath string) bool   { return false }
func (m *recordingFileDAO) DeleteEncPathMapping(displayPath string)       {}
func (m *recordingFileDAO) InvalidateRawURLForScope(displayPath, authScope string) bool {
	return false
}
func (m *recordingFileDAO) Set(info *dao.FileInfo) error {
	m.mu.Lock()
	m.setCalls++
	m.mu.Unlock()
	return nil
}
func (m *recordingFileDAO) Config() *config.Config       { return nil }
func (m *recordingFileDAO) InvalidateDisplayPath(string) {}
func (m *recordingFileDAO) GetFileSize(path string) (int64, bool) {
	return 0, false
}
func (m *recordingFileDAO) SetFileSize(path string, size int64, ttl time.Duration) {}
func (m *recordingFileDAO) SetFromAlistResponse(path string, data map[string]interface{}, rawURLAuthScope string) error {
	return nil
}
func (m *recordingFileDAO) PrepareFromAlistResponse(path string, data map[string]interface{}, rawURLAuthScope string) *dao.FileInfo {
	return nil
}
func (m *recordingFileDAO) PersistFromList(infos []*dao.FileInfo) error { return nil }
func (m *recordingFileDAO) FileSizeCacheStats() map[string]interface{}  { return nil }
func (m *recordingFileDAO) PathCacheStats() map[string]interface{}      { return nil }

func (m *recordingFileDAO) counts() (set int, enc int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.setCalls, m.encMappingCalls
}

// --- tests -----------------------------------------------------------------

// TestParsePropfindHugeDirSkipsPerEntryWritesButStillDecrypts is the server-side
// mirror of the mobile large-dir budget regression: a PROPFIND listing in the
// 100k-class must keep name decryption 100% intact while bypassing the per-entry
// path-cache / meta / probe writes entirely (they would otherwise drag the
// request into multi-second hangs or DB write storms at 100k+ entries).
func TestParsePropfindHugeDirSkipsPerEntryWritesButStillDecrypts(t *testing.T) {
	cfg := config.Get()
	original := cfg.AlistServer
	t.Cleanup(func() { cfg.AlistServer = original })
	passwd := config.PasswdInfo{
		Password: "123456",
		EncType:  "aesctr",
		EncName:  true,
		Enable:   true,
		EncPath:  []string{"/encrypt/"},
	}
	cfg.AlistServer.PasswdList = []config.PasswdInfo{passwd}

	passwdDAO := &staticPasswdDAO{info: &passwd}
	fileDAO := &recordingFileDAO{}
	h := &WebDAVHandler{
		cfg:       cfg,
		passwdDAO: passwdDAO,
		fileDAO:   fileDAO,
		metaStore: nil,
		probe:     nil,
	}

	conv := encryption.NewFileNameConverter(passwd.Password, passwd.EncType, passwd.EncSuffix)
	n := dirServerHugeListEntries
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?><multistatus>`)
	enc := make([]string, n)
	for i := 0; i < n; i++ {
		enc[i] = conv.ToRealName("video" + string(rune('0'+i%10)) + ".mp4")
		b.WriteString(`<response><href>/dav/encrypt/`)
		b.WriteString(enc[i])
		b.WriteString(`</href><propstat><prop><displayname>`)
		b.WriteString(enc[i])
		b.WriteString(`</displayname><getcontentlength>12345</getcontentlength><resourcetype></resourcetype></prop></propstat></response>`)
	}
	b.WriteString(`</multistatus>`)

	entries := h.parsePropfindResponse(context.Background(), []byte(b.String()), "/encrypt/")
	if len(entries) != n {
		t.Fatalf("entries=%d, want %d (listing must not be truncated)", len(entries), n)
	}

	// Heavy per-entry work must be bypassed entirely.
	if setCalls, encCalls := fileDAO.counts(); setCalls != 0 || encCalls != 0 {
		t.Fatalf("huge dir wrote to fileDAO: set=%d enc=%d, want 0/0", setCalls, encCalls)
	}

	// Name decryption must still reach the client: the actual display-name
	// decryption for PROPFIND happens in the response rewrite stage, which is
	// independent of the per-entry budget. Assert it still produces the plain
	// name for a sample in the rewritten (client-visible) multistatus body.
	rewritten := h.rewritePropfindBody([]byte(b.String()), &passwd)
	for _, plainName := range []string{"video0.mp4", "video5.mp4", "video9.mp4"} {
		if !strings.Contains(string(rewritten), plainName) {
			t.Fatalf("rewrite lost decrypted name %q (len=%d)", plainName, len(rewritten))
		}
	}
}