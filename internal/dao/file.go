package dao

import (
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/encryption"
	"github.com/alist-encrypt-go/internal/storage"
)

// FileInfo represents cached file information
type FileInfo struct {
	Path              string    `json:"path"`
	EncryptedPath     string    `json:"encrypted_path,omitempty"`
	Name              string    `json:"name"`
	Size              int64     `json:"size"`
	CiphertextSize    int64     `json:"ciphertext_size"`
	ContentVersion    int       `json:"content_version"`
	HeaderLen         int64     `json:"header_len"`
	NonceField        []byte    `json:"nonce_field,omitempty"`
	IsDir             bool      `json:"is_dir"`
	Modified          time.Time `json:"modified"`
	RawURL            string    `json:"raw_url"`
	Sign              string    `json:"sign"`
	UpstreamFetchedAt time.Time `json:"upstream_fetched_at"`
}

// UpstreamStaleness returns how long ago the upstream metadata was fetched.
func (fi *FileInfo) UpstreamStaleness() time.Duration {
	if fi.UpstreamFetchedAt.IsZero() {
		return time.Hour * 24 * 365 // treat missing timestamp as very stale
	}
	return time.Since(fi.UpstreamFetchedAt)
}

// FileSizeEntry represents a persistent file size mapping
type FileSizeEntry struct {
	Path      string    `json:"path"`
	Size      int64     `json:"size"`
	UpdatedAt time.Time `json:"updated_at"`
}

// FileMetaStoreWriter is a minimal interface for writing file metadata to external stores like MySQL.
type FileMetaStoreWriter interface {
	UpsertFileMeta(info *FileInfo) error
}

// FileDAO handles file information caching
type FileDAO struct {
	store          *storage.Store
	pathCache      *PathCache // Unified high-performance cache
	fileMetaWriter FileMetaStoreWriter
}

// NewFileDAO creates a new file DAO
func NewFileDAO(store *storage.Store) *FileDAO {
	dao := &FileDAO{
		store:     store,
		pathCache: NewPathCache(32, 1000), // 32 shards, 1000 entries per shard = 32k max
	}

	// Start background cleanup for expired entries
	go dao.cleanupPathCache()

	return dao
}

// SetFileMetaWriter injects an external store for persisting file metadata (e.g. MySQL).
func (d *FileDAO) SetFileMetaWriter(w FileMetaStoreWriter) {
	d.fileMetaWriter = w
}

// Get retrieves file info from cache or store
func (d *FileDAO) Get(path string) (*FileInfo, bool) {
	// Check unified path cache first
	if entry, ok := d.pathCache.Get(path); ok {
		fi := &FileInfo{
			Path:           entry.DisplayPath,
			EncryptedPath:  entry.EncryptedPath,
			Name:           entry.Name,
			Size:           entry.Size,
			CiphertextSize: entry.CiphertextSize,
			ContentVersion: entry.ContentVersion,
			HeaderLen:      entry.HeaderLen,
			NonceField:     append([]byte(nil), entry.NonceField...),
			IsDir:          entry.IsDir,
			RawURL:         entry.RawURL,
			Sign:           entry.Sign,
		}
		if entry.UpstreamFetchedAt > 0 {
			fi.UpstreamFetchedAt = time.Unix(0, entry.UpstreamFetchedAt)
		}
		return fi, true
	}

	// Check persistent store
	var info FileInfo
	if err := d.store.GetJSON(storage.BucketFileInfo, path, &info); err != nil {
		return nil, false
	}
	if info.Path == "" {
		return nil, false
	}

	return &info, true
}

// Set stores file info
func (d *FileDAO) Set(info *FileInfo) error {
	if existing, ok := d.Get(info.Path); ok && existing != nil {
		if info.EncryptedPath == "" {
			info.EncryptedPath = existing.EncryptedPath
		}
		if info.Name == "" {
			info.Name = existing.Name
		}
		if info.Size <= 0 {
			info.Size = existing.Size
		}
		if info.CiphertextSize <= 0 {
			info.CiphertextSize = existing.CiphertextSize
		}
		if info.ContentVersion <= 0 {
			info.ContentVersion = existing.ContentVersion
		}
		if info.HeaderLen <= 0 {
			info.HeaderLen = existing.HeaderLen
		}
		if len(info.NonceField) == 0 && len(existing.NonceField) > 0 {
			info.NonceField = append([]byte(nil), existing.NonceField...)
		}
		if info.RawURL == "" {
			info.RawURL = existing.RawURL
		}
		if info.Sign == "" {
			info.Sign = existing.Sign
		}
		if info.Modified.IsZero() {
			info.Modified = existing.Modified
		}
		if info.UpstreamFetchedAt.IsZero() {
			info.UpstreamFetchedAt = existing.UpstreamFetchedAt
		}
	}

	// Store in unified path cache
	now := time.Now()
	upstreamFetchedAt := info.UpstreamFetchedAt
	if upstreamFetchedAt.IsZero() {
		upstreamFetchedAt = now
	}
	info.UpstreamFetchedAt = upstreamFetchedAt
	entry := &PathEntry{
		EncryptedPath:     info.EncryptedPath,
		DisplayPath:       info.Path,
		Name:              info.Name,
		Size:              info.Size,
		CiphertextSize:    info.CiphertextSize,
		ContentVersion:    info.ContentVersion,
		HeaderLen:         info.HeaderLen,
		NonceField:        append([]byte(nil), info.NonceField...),
		IsDir:             info.IsDir,
		RawURL:            info.RawURL,
		Sign:              info.Sign,
		UpstreamFetchedAt: upstreamFetchedAt.UnixNano(),
	}
	if entry.EncryptedPath == "" {
		entry.EncryptedPath = info.Path
	}
	d.pathCache.Set(entry, 24*time.Hour)

	// Persist: prefer MySQL if available, else BoltDB.
	if d.fileMetaWriter != nil {
		if writeErr := d.fileMetaWriter.UpsertFileMeta(info); writeErr != nil {
			// Log but don't fail — data is still in the in-memory cache
			// and will be retried on the next Set() call for the same path.
			log.Warn().Err(writeErr).Str("path", info.Path).Msg("MySQL file meta write failed (cached in memory)")
		}
		return nil
	}
	return d.store.SetJSON(storage.BucketFileInfo, info.Path, info)
}

// SetComplete stores a fully-populated FileInfo without the read-before-write merge.
// Use this when the caller guarantees all fields are already set (e.g., when copying
// from an existing cache entry or assembling from a complete upstream response).
// This avoids the Get() round-trip that Set() performs to fill in missing fields.
func (d *FileDAO) SetComplete(info *FileInfo) error {
	now := time.Now()
	upstreamFetchedAt := info.UpstreamFetchedAt
	if upstreamFetchedAt.IsZero() {
		upstreamFetchedAt = now
	}
	info.UpstreamFetchedAt = upstreamFetchedAt

	entry := &PathEntry{
		EncryptedPath:     info.EncryptedPath,
		DisplayPath:       info.Path,
		Name:              info.Name,
		Size:              info.Size,
		CiphertextSize:    info.CiphertextSize,
		ContentVersion:    info.ContentVersion,
		HeaderLen:         info.HeaderLen,
		NonceField:        append([]byte(nil), info.NonceField...),
		IsDir:             info.IsDir,
		RawURL:            info.RawURL,
		Sign:              info.Sign,
		UpstreamFetchedAt: upstreamFetchedAt.UnixNano(),
	}
	if entry.EncryptedPath == "" {
		entry.EncryptedPath = info.Path
	}
	d.pathCache.Set(entry, 24*time.Hour)

	// Persist: prefer MySQL if available, else BoltDB.
	if d.fileMetaWriter != nil {
		if writeErr := d.fileMetaWriter.UpsertFileMeta(info); writeErr != nil {
			log.Warn().Err(writeErr).Str("path", info.Path).Msg("MySQL file meta write failed (cached in memory)")
		}
		return nil
	}
	return d.store.SetJSON(storage.BucketFileInfo, info.Path, info)
}

// Delete removes file info
func (d *FileDAO) Delete(path string) error {
	d.pathCache.Delete(path)
	return d.store.Delete(storage.BucketFileInfo, path)
}

// SetEncPathMapping caches the display path to encrypted path mapping with file info
func (d *FileDAO) SetEncPathMapping(displayPath, encryptedPath string) {
	// Check if we already have this mapping with file info
	if existing, ok := d.pathCache.GetByDispPath(displayPath); ok {
		// Update encrypted path if needed
		if existing.EncryptedPath != encryptedPath {
			existing.EncryptedPath = encryptedPath
			d.pathCache.Set(existing, 24*time.Hour)
		}
		return
	}

	// Create new entry
	entry := &PathEntry{
		EncryptedPath: encryptedPath,
		DisplayPath:   displayPath,
		Name:          "",
		Size:          0,
		IsDir:         false,
	}
	d.pathCache.Set(entry, 24*time.Hour)
}

// SetEncPathMappingWithInfo caches mapping with full file info (recommended)
func (d *FileDAO) SetEncPathMappingWithInfo(displayPath, encryptedPath, name string, size int64, isDir bool) {
	entry := &PathEntry{
		EncryptedPath: encryptedPath,
		DisplayPath:   displayPath,
		Name:          name,
		Size:          size,
		IsDir:         isDir,
	}
	d.pathCache.Set(entry, 24*time.Hour)
}

// GetEncPath retrieves the encrypted path for a display path
func (d *FileDAO) GetEncPath(displayPath string) (string, bool) {
	return d.pathCache.GetEncPath(displayPath)
}

// HasEncryptedPath reports whether the path cache already knows this encrypted path.
func (d *FileDAO) HasEncryptedPath(encryptedPath string) bool {
	if d == nil || d.pathCache == nil {
		return false
	}
	_, ok := d.pathCache.GetByEncPath(encryptedPath)
	return ok
}

// DeleteEncPathMapping removes the display path to encrypted path mapping
func (d *FileDAO) DeleteEncPathMapping(displayPath string) {
	// Find and delete both encrypted path and display path indexes
	if entry, ok := d.pathCache.GetByDispPath(displayPath); ok {
		d.pathCache.Delete(entry.EncryptedPath)
		// Also delete by display path to clear the reverse index
		if entry.DisplayPath != "" && entry.DisplayPath != entry.EncryptedPath {
			d.pathCache.Delete(entry.DisplayPath)
		}
	}
}

// GetFileSize retrieves cached file size (optimized for long-term caching)
func (d *FileDAO) GetFileSize(path string) (int64, bool) {
	if size, ok := d.pathCache.GetSize(path); ok {
		return size, true
	}

	cfg := config.Get()
	if cfg.AlistServer.EnableSizeMap && cfg.AlistServer.SizeMapTtlMinutes > 0 {
		var entry FileSizeEntry
		if err := d.store.GetJSON(storage.BucketFileSize, path, &entry); err == nil && entry.Size > 0 {
			ttl := time.Duration(cfg.AlistServer.SizeMapTtlMinutes) * time.Minute
			if entry.UpdatedAt.IsZero() || time.Since(entry.UpdatedAt) <= ttl {
				cacheEntry := &PathEntry{EncryptedPath: path, DisplayPath: path, Size: entry.Size}
				d.pathCache.Set(cacheEntry, ttl)
				return entry.Size, true
			}
		}
	}

	return 0, false
}

// SetFileSize caches file size with TTL (default 24 hours for stability)
func (d *FileDAO) SetFileSize(path string, size int64, ttl time.Duration) {
	if ttl == 0 {
		ttl = 24 * time.Hour
	}

	// Try to update existing entry
	if entry, ok := d.pathCache.Get(path); ok {
		entry.Size = size
		d.pathCache.Set(entry, ttl)
	} else {
		// Create minimal entry for size caching
		cacheEntry := &PathEntry{
			EncryptedPath: path,
			DisplayPath:   path,
			Size:          size,
		}
		d.pathCache.Set(cacheEntry, ttl)
	}

	cfg := config.Get()
	if d.fileMetaWriter == nil && cfg.AlistServer.EnableSizeMap && cfg.AlistServer.SizeMapTtlMinutes > 0 {
		persistEntry := FileSizeEntry{Path: path, Size: size, UpdatedAt: time.Now()}
		_ = d.store.SetJSON(storage.BucketFileSize, path, persistEntry)
	}
}

// DeleteFileSize removes cached file size
func (d *FileDAO) DeleteFileSize(path string) {
	// We don't delete the whole entry, just mark size as 0
	if entry, ok := d.pathCache.Get(path); ok {
		entry.Size = 0
		d.pathCache.Set(entry, 24*time.Hour)
	}
	_ = d.store.Delete(storage.BucketFileSize, path)
}

// InvalidateDisplayPath clears volatile upstream metadata for a display path
// while preserving any encrypted-path mapping that may still be valid.
func (d *FileDAO) InvalidateDisplayPath(displayPath string) {
	displayPath = strings.TrimSpace(displayPath)
	if displayPath == "" {
		return
	}
	d.DeleteFileSize(displayPath)
	_ = d.store.Delete(storage.BucketFileInfo, displayPath)
	// Get() already checks both byEncPath and byDispPath maps, so a single
	// lookup is sufficient. The second GetByDispPath() call in the original
	// code always returned the same *PathEntry pointer (dual-indexed cache),
	// making it a redundant double-lookup.
	if entry, ok := d.pathCache.Get(displayPath); ok && entry != nil {
		entry.Size = 0
		entry.RawURL = ""
		entry.Sign = ""
		entry.UpstreamFetchedAt = 0
		d.pathCache.Set(entry, 24*time.Hour)
		if entry.EncryptedPath != "" && entry.EncryptedPath != displayPath {
			d.DeleteFileSize(entry.EncryptedPath)
		}
	}
}

// FileSizeCacheStats returns file size cache statistics
func (d *FileDAO) FileSizeCacheStats() map[string]interface{} {
	return d.pathCache.Stats()
}

// PathCacheStats returns full path cache statistics
func (d *FileDAO) PathCacheStats() map[string]interface{} {
	return d.pathCache.Stats()
}

// cleanupPathCache runs periodic cleanup of expired entries
func (d *FileDAO) cleanupPathCache() {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		d.pathCache.CleanExpired()
	}
}

// SetFromAlistResponse parses and stores file info from Alist API response
func (d *FileDAO) SetFromAlistResponse(path string, data map[string]interface{}) error {
	info := &FileInfo{
		Path:              path,
		UpstreamFetchedAt: time.Now(),
	}

	if name, ok := data["name"].(string); ok {
		info.Name = name
	}
	if size, ok := data["size"].(float64); ok {
		info.Size = int64(size)
	}
	if isDir, ok := data["is_dir"].(bool); ok {
		info.IsDir = isDir
	}
	if rawURL, ok := data["raw_url"].(string); ok {
		info.RawURL = rawURL
	}
	if sign, ok := data["sign"].(string); ok {
		info.Sign = sign
	}
	if modified, ok := data["modified"].(string); ok {
		if t, err := time.Parse(time.RFC3339, modified); err == nil {
			info.Modified = t
		}
	}

	return d.Set(info)
}

// PasswdDAO handles password configuration lookup
type PasswdDAO struct {
	cfg   *config.Config
	cache *storage.Cache
}

// NewPasswdDAO creates a new password DAO
func NewPasswdDAO(store *storage.Store) *PasswdDAO {
	return &PasswdDAO{
		cfg:   config.Get(),
		cache: storage.NewCache(5 * time.Minute),
	}
}

// Stop terminates background goroutines owned by the DAO (cache cleanup).
func (d *PasswdDAO) Stop() {
	if d.cache != nil {
		d.cache.Stop()
	}
}

// GetAll retrieves all password configs from the main config
func (d *PasswdDAO) GetAll() []*config.PasswdInfo {
	var result []*config.PasswdInfo
	for i := range d.cfg.AlistServer.PasswdList {
		result = append(result, &d.cfg.AlistServer.PasswdList[i])
	}
	return result
}

// GetEncPathPrefixes returns directory prefixes extracted from encPath patterns.
func (d *PasswdDAO) GetEncPathPrefixes() []string {
	seen := make(map[string]struct{})
	var prefixes []string

	for i := range d.cfg.AlistServer.PasswdList {
		passwdInfo := &d.cfg.AlistServer.PasswdList[i]
		if !passwdInfo.Enable {
			continue
		}
		for _, pattern := range passwdInfo.EncPath {
			if strings.HasPrefix(pattern, "/d/") || strings.HasPrefix(pattern, "/p/") || strings.HasPrefix(pattern, "/dav/") {
				continue
			}
			prefix := extractLiteralPrefix(pattern)
			if prefix == "" {
				continue
			}
			if _, ok := seen[prefix]; ok {
				continue
			}
			seen[prefix] = struct{}{}
			prefixes = append(prefixes, prefix)
		}
	}

	return prefixes
}

// FindByPath finds password config by matching encPath patterns
func (d *PasswdDAO) FindByPath(urlPath string) (*config.PasswdInfo, bool) {
	// Check cache first
	if cached, ok := d.cache.Get(urlPath); ok {
		if cached == nil {
			return nil, false
		}
		return cached.(*config.PasswdInfo), true
	}

	result, found := d.findByPathInternal(urlPath)
	if found {
		d.cache.Set(urlPath, result)
	} else {
		d.cache.Set(urlPath, nil)
	}
	return result, found
}

// FindByDir finds password config for a directory by probing a child path
func (d *PasswdDAO) FindByDir(dirPath string) (*config.PasswdInfo, bool) {
	probePath := buildProbePath(dirPath)
	return d.PathFindPasswd(probePath)
}

// MatchDir checks if any encryption path matches this directory's contents
func (d *PasswdDAO) MatchDir(dirPath string) bool {
	cacheKey := "dir:" + dirPath
	if cached, ok := d.cache.Get(cacheKey); ok {
		if value, ok := cached.(bool); ok {
			return value
		}
	}

	probePath := buildProbePath(dirPath)
	for i := range d.cfg.AlistServer.PasswdList {
		passwdInfo := &d.cfg.AlistServer.PasswdList[i]
		if !passwdInfo.Enable {
			continue
		}
		if encryption.PathExec(passwdInfo.EncPath, probePath) {
			d.cache.Set(cacheKey, true)
			return true
		}
	}

	d.cache.Set(cacheKey, false)
	return false
}

func (d *PasswdDAO) findByPathInternal(urlPath string) (*config.PasswdInfo, bool) {
	var bestMatch *config.PasswdInfo
	var bestLen int
	for i := range d.cfg.AlistServer.PasswdList {
		passwdInfo := &d.cfg.AlistServer.PasswdList[i]
		if !passwdInfo.Enable {
			continue
		}
		if encryption.PathExec(passwdInfo.EncPath, urlPath) {
			// Prefer the most specific (longest base path) match
			matchLen := longestEncPathLen(passwdInfo.EncPath)
			if bestMatch == nil || matchLen > bestLen {
				bestMatch = passwdInfo
				bestLen = matchLen
			}
		}
	}
	if bestMatch != nil {
		return bestMatch, true
	}
	return nil, false
}

func longestEncPathLen(encPaths []string) int {
	maxLen := 0
	for _, p := range encPaths {
		p = strings.TrimSuffix(p, "/*")
		p = strings.TrimSuffix(p, "*")
		if len(p) > maxLen {
			maxLen = len(p)
		}
	}
	return maxLen
}

// PathFindPasswd finds password config matching URL path with encPath patterns.
// Returns the most specific (longest base path) match with folder password decoding.
func (d *PasswdDAO) PathFindPasswd(urlPath string) (*config.PasswdInfo, bool) {
	all := d.GetAll()

	var bestMatch *config.PasswdInfo
	var bestLen int
	for _, passwdInfo := range all {
		if !passwdInfo.Enable {
			continue
		}
		if encryption.PathExec(passwdInfo.EncPath, urlPath) {
			matchLen := longestEncPathLen(passwdInfo.EncPath)
			if bestMatch == nil || matchLen > bestLen {
				bestMatch = passwdInfo
				bestLen = matchLen
			}
		}
	}

	if bestMatch != nil {
		newPasswdInfo := *bestMatch // Copy
		folders := strings.Split(urlPath, "/")
		for _, folderName := range folders {
			if folderName == "" {
				continue
			}
			decoded, _ := url.QueryUnescape(folderName)
			folderEncType, folderPasswd, ok := encryption.DecodeFolderName(
				bestMatch.Password,
				bestMatch.EncType,
				decoded,
			)
			if ok {
				newPasswdInfo.EncType = folderEncType
				newPasswdInfo.Password = folderPasswd
				return &newPasswdInfo, true
			}
		}
		return &newPasswdInfo, true
	}

	return nil, false
}

func buildProbePath(dirPath string) string {
	if dirPath == "" {
		return "/__probe__"
	}
	if !strings.HasSuffix(dirPath, "/") {
		dirPath += "/"
	}
	return dirPath + "__probe__"
}

func extractLiteralPrefix(pattern string) string {
	if pattern == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range pattern {
		switch r {
		case '*', '+', '?', '[', ']', '(', ')', '{', '}', '|', '^', '$', '.', '\\':
			return strings.TrimRight(b.String(), "/")
		default:
			b.WriteRune(r)
		}
	}
	return strings.TrimRight(b.String(), "/")
}
