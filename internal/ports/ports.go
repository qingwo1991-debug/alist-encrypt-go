// Package ports defines the *ports* of the internal hexagonal/clean boundary:
// the abstractions that the transport layer (internal/handler, internal/server)
// depends on, implemented by the adapter layer (internal/dao, internal/proxy,
// internal/cache, internal/storage/*). Keeping the handler wiring against these
// interfaces instead of concrete DAO/StreamProxy types ensures every adapter
// stays swappable (e.g. sqlite vs mysqlstore, decrypted-cache backends) and
// keeps the transport handlers thin.
//
// Layering map to the audit's batch-4 architecture:
//
//	transport/runtime : internal/server, internal/handler (routes + wiring)
//	application        : internal/appservice, internal/handler (probe_scheduler,
//	                     playback_orchestrator, filesize_resolver)
//	ports              : this package (the seams below)
//	adapters           : internal/dao, internal/proxy, internal/cache,
//	                     internal/storage/mysqlstore, internal/backoff
//	domain             : shared/encryptcore (format/encryption domain),
//	                     internal/config, internal/errors, internal/httputil
//
// Each interface below is satisfied implicitly (structural typing) by the
// concrete adapter type; the ports_check test in this package pins that
// conformance at compile time.
package ports

import (
	"context"
	"net/http"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/proxy"
)

// FileRepository is the file metadata cache and persistence port implemented
// by *dao.FileDAO. It mirrors the member surface the transport handlers use.
type FileRepository interface {
	Get(path string) (*dao.FileInfo, bool)
	Set(info *dao.FileInfo) error
	Delete(path string) error
	List(limit int) []*dao.FileInfo

	SetEncPathMapping(displayPath, encryptedPath string)
	SetEncPathMappingWithInfo(displayPath, encryptedPath, name string, size int64, isDir bool)
	GetEncPath(displayPath string) (string, bool)
	HasEncryptedPath(encryptedPath string) bool
	DeleteEncPathMapping(displayPath string)
	InvalidateRawURLForScope(displayPath, authScope string) bool
	Config() *config.Config
	InvalidateDisplayPath(displayPath string)

	GetFileSize(path string) (int64, bool)
	SetFileSize(path string, size int64, ttl time.Duration)

	SetFromAlistResponse(path string, data map[string]interface{}, rawURLAuthScope string) error
	PrepareFromAlistResponse(path string, data map[string]interface{}, rawURLAuthScope string) *dao.FileInfo
	PersistFromList(infos []*dao.FileInfo) error

	FileSizeCacheStats() map[string]interface{}
	PathCacheStats() map[string]interface{}
}

// KeyRepository is the password/key discovery port implemented by
// *dao.PasswdDAO. Handlers use it to resolve the key protecting a path before
// any decrypt/probe work.
type KeyRepository interface {
	GetEncPathPrefixes() []string
	FindByPath(urlPath string) (*config.PasswdInfo, bool)
	FindByDir(dirPath string) (*config.PasswdInfo, bool)
	MatchDir(dirPath string) bool
	PathFindPasswd(urlPath string) (*config.PasswdInfo, bool)
}

// Streamer is the encrypted-content streaming point implemented by
// *proxy.StreamProxy: proxying requests, inspecting/decrypting V2/V3
// containers, resumable encrypted uploads, and the decrypted-block cache
// that the playback pipeline uses.
type Streamer interface {
	InspectEncryptedContentResult(ctx context.Context, targetURL string, authHeaders http.Header, passwdInfo *config.PasswdInfo, ciphertextSize int64) proxy.ContentInspectionResult
	ProxyRequest(w http.ResponseWriter, r *http.Request, targetURL string) error
	ProxyUploadEncrypt(w http.ResponseWriter, r *http.Request, targetURL string, passwdInfo *config.PasswdInfo, fileSize int64, startOffset int64) error
	DecryptedBlockCacheStats() map[string]interface{}
	RangeCompatStats() map[string]interface{}
	StreamLimitStats() map[string]interface{}
	SetRedirectRewriter(rewriter proxy.RedirectRewriter)

	AcquireStream() (func(), bool)
	SelectOptimalStrategy(targetURL, storageKey, method, rangeHeader string) proxy.StreamStrategy
	ProxyDownloadDecryptWithStrategyForStorage(w http.ResponseWriter, r *http.Request, targetURL string, passwdInfo *config.PasswdInfo, fileSize int64, strategy proxy.StreamStrategy, compatStorageKey string) *proxy.StreamOutcome
	RecordPlaybackHint(targetURL, storageKey string, strategy proxy.StreamStrategy)
}
