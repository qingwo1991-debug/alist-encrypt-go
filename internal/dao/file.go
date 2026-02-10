package dao

import (
	"net/url"
	"strings"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/encryption"
	"github.com/alist-encrypt-go/internal/storage"
)

// FileInfo represents cached file information
type FileInfo struct {
	Path     string    `json:"path"`
	Name     string    `json:"name"`
	Size     int64     `json:"size"`
	IsDir    bool      `json:"is_dir"`
	Modified time.Time `json:"modified"`
	RawURL   string    `json:"raw_url"`
	Sign     string    `json:"sign"`
}

// FileSizeEntry represents a persistent file size mapping
type FileSizeEntry struct {
	Path      string    `json:"path"`
	Size      int64     `json:"size"`
	UpdatedAt time.Time `json:"updated_at"`
}

// FileDAO handles file information caching
type FileDAO struct {
	store     *storage.Store
	pathCache *PathCache // Unified high-performance cache
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

// Get retrieves file info from cache or store
func (d *FileDAO) Get(path string) (*FileInfo, bool) {
	// Check unified path cache first
	if entry, ok := d.pathCache.Get(path); ok {
		return &FileInfo{
			Path:  entry.DisplayPath,
			Name:  entry.Name,
			Size:  entry.Size,
			IsDir: entry.IsDir,
		}, true
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
	// Store in unified path cache
	entry := &PathEntry{
		EncryptedPath: info.Path,
		DisplayPath:   info.Path,
		Name:          info.Name,
		Size:          info.Size,
		IsDir:         info.IsDir,
	}
	d.pathCache.Set(entry, 24*time.Hour)

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

// DeleteEncPathMapping removes the display path to encrypted path mapping
func (d *FileDAO) DeleteEncPathMapping(displayPath string) {
	// Find and delete by display path
	if entry, ok := d.pathCache.GetByDispPath(displayPath); ok {
		d.pathCache.Delete(entry.EncryptedPath)
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
	if cfg.AlistServer.EnableSizeMap && cfg.AlistServer.SizeMapTtlMinutes > 0 {
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
		Path: path,
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

// GetAll retrieves all password configs from the main config
func (d *PasswdDAO) GetAll() []*config.PasswdInfo {
	var result []*config.PasswdInfo
	for i := range d.cfg.AlistServer.PasswdList {
		result = append(result, &d.cfg.AlistServer.PasswdList[i])
	}
	return result
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

func (d *PasswdDAO) findByPathInternal(urlPath string) (*config.PasswdInfo, bool) {
	for i := range d.cfg.AlistServer.PasswdList {
		passwdInfo := &d.cfg.AlistServer.PasswdList[i]
		if !passwdInfo.Enable {
			continue
		}

		// Check encPath patterns
		if encryption.PathExec(passwdInfo.EncPath, urlPath) {
			return passwdInfo, true
		}
	}
	return nil, false
}

// PathFindPasswd finds password config matching URL path with encPath patterns
// Returns a potentially modified PasswdInfo (for folder password decoding)
func (d *PasswdDAO) PathFindPasswd(urlPath string) (*config.PasswdInfo, bool) {
	all := d.GetAll()

	for _, passwdInfo := range all {
		if !passwdInfo.Enable {
			continue
		}

		// Check encPath patterns
		if encryption.PathExec(passwdInfo.EncPath, urlPath) {
			// Check if any folder in the path contains encoded password
			newPasswdInfo := *passwdInfo // Copy
			folders := strings.Split(urlPath, "/")

			for _, folderName := range folders {
				if folderName == "" {
					continue
				}
				decoded, _ := url.QueryUnescape(folderName)
				folderEncType, folderPasswd, ok := encryption.DecodeFolderName(
					passwdInfo.Password,
					passwdInfo.EncType,
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
	}

	return nil, false
}
