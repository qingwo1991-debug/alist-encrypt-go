package dao

import (
	"net/url"
	"strings"
	"sync"
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
	store      *storage.Store
	cache      *storage.Cache
	encPathMap sync.Map // displayPath -> encryptedPath mapping
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

// SetEncPathMapping caches the display path to encrypted path mapping
func (d *FileDAO) SetEncPathMapping(displayPath, encryptedPath string) {
	d.encPathMap.Store(displayPath, encryptedPath)
}

// GetEncPath retrieves the encrypted path for a display path
func (d *FileDAO) GetEncPath(displayPath string) (string, bool) {
	if v, ok := d.encPathMap.Load(displayPath); ok {
		return v.(string), true
	}
	return "", false
}

// DeleteEncPathMapping removes the display path to encrypted path mapping
func (d *FileDAO) DeleteEncPathMapping(displayPath string) {
	d.encPathMap.Delete(displayPath)
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
