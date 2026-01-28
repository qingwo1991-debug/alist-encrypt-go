package dao

import (
	"encoding/json"
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

// FileDAO handles file information caching
type FileDAO struct {
	store *storage.Store
	cache *storage.Cache
}

// NewFileDAO creates a new file DAO
func NewFileDAO(store *storage.Store) *FileDAO {
	return &FileDAO{
		store: store,
		cache: storage.NewCache(10 * time.Minute),
	}
}

// Get retrieves file info from cache or store
func (d *FileDAO) Get(path string) (*FileInfo, bool) {
	// Check cache first
	if cached, ok := d.cache.Get(path); ok {
		return cached.(*FileInfo), true
	}

	// Check persistent store
	var info FileInfo
	if err := d.store.GetJSON(storage.BucketFileInfo, path, &info); err != nil {
		return nil, false
	}
	if info.Path == "" {
		return nil, false
	}

	// Update cache
	d.cache.Set(path, &info)
	return &info, true
}

// Set stores file info
func (d *FileDAO) Set(info *FileInfo) error {
	d.cache.Set(info.Path, info)
	return d.store.SetJSON(storage.BucketFileInfo, info.Path, info)
}

// Delete removes file info
func (d *FileDAO) Delete(path string) error {
	d.cache.Delete(path)
	return d.store.Delete(storage.BucketFileInfo, path)
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

// PasswdDAO handles password configuration
type PasswdDAO struct {
	store *storage.Store
	cache *storage.Cache
}

// NewPasswdDAO creates a new password DAO
func NewPasswdDAO(store *storage.Store) *PasswdDAO {
	return &PasswdDAO{
		store: store,
		cache: storage.NewCache(0), // No expiration
	}
}

// Get retrieves password info for a path
func (d *PasswdDAO) Get(path string) (*config.PasswdInfo, bool) {
	// Check cache first
	if cached, ok := d.cache.Get(path); ok {
		return cached.(*config.PasswdInfo), true
	}

	var info config.PasswdInfo
	if err := d.store.GetJSON(storage.BucketPasswd, path, &info); err != nil {
		return nil, false
	}
	if info.Path == "" {
		return nil, false
	}

	d.cache.Set(path, &info)
	return &info, true
}

// Set stores password info
func (d *PasswdDAO) Set(info *config.PasswdInfo) error {
	d.cache.Set(info.Path, info)
	return d.store.SetJSON(storage.BucketPasswd, info.Path, info)
}

// Delete removes password info
func (d *PasswdDAO) Delete(path string) error {
	d.cache.Delete(path)
	return d.store.Delete(storage.BucketPasswd, path)
}

// GetAll retrieves all password configs
func (d *PasswdDAO) GetAll() ([]*config.PasswdInfo, error) {
	data, err := d.store.GetAll(storage.BucketPasswd)
	if err != nil {
		return nil, err
	}

	var result []*config.PasswdInfo
	for _, v := range data {
		var info config.PasswdInfo
		if err := json.Unmarshal(v, &info); err == nil {
			result = append(result, &info)
		}
	}
	return result, nil
}

// FindByPrefix finds password config by path prefix match
func (d *PasswdDAO) FindByPrefix(path string) (*config.PasswdInfo, bool) {
	all, err := d.GetAll()
	if err != nil {
		return nil, false
	}

	var bestMatch *config.PasswdInfo
	bestLen := 0

	for _, info := range all {
		if len(info.Path) > bestLen && strings.HasPrefix(path, info.Path) {
			bestMatch = info
			bestLen = len(info.Path)
		}
	}

	return bestMatch, bestMatch != nil
}

// PathFindPasswd finds password config matching URL path with encPath patterns
// Returns a potentially modified PasswdInfo (for folder password decoding)
func (d *PasswdDAO) PathFindPasswd(urlPath string) (*config.PasswdInfo, bool) {
	all, err := d.GetAll()
	if err != nil {
		return nil, false
	}

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
