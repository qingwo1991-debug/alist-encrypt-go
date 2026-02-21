package proxydict

import (
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type ProviderItem struct {
	ID              string   `json:"id"`
	ProviderNameZH  string   `json:"provider_name_zh"`
	ProviderNameEN  string   `json:"provider_name_en"`
	Category        string   `json:"category"` // overseas, domestic, other
	Domains         []string `json:"domains"`
	DefaultSelected bool     `json:"default_selected"`
	Aliases         []string `json:"aliases,omitempty"`
}

type Dictionary struct {
	Version   string         `json:"version"`
	Source    string         `json:"source"`
	UpdatedAt string         `json:"updated_at"`
	Providers []ProviderItem `json:"providers"`
}

type Manager struct {
	openListPath string
	dictPath     string
	seedPath     string
}

func NewManager(openListPath, dictPath, seedPath string) *Manager {
	return &Manager{
		openListPath: openListPath,
		dictPath:     dictPath,
		seedPath:     seedPath,
	}
}

func (m *Manager) ensureDir() error {
	return os.MkdirAll(filepath.Dir(m.dictPath), 0755)
}

func (m *Manager) Load() (*Dictionary, error) {
	data, err := os.ReadFile(m.dictPath)
	if err != nil {
		return nil, err
	}
	var out Dictionary
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (m *Manager) Save(dict *Dictionary) error {
	if dict == nil {
		return nil
	}
	if err := m.ensureDir(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(dict, "", "\t")
	if err != nil {
		return err
	}
	return os.WriteFile(m.dictPath, data, 0644)
}

func (m *Manager) LoadOrRefresh() (*Dictionary, error) {
	if dict, err := m.Load(); err == nil && len(dict.Providers) > 0 {
		return dict, nil
	}
	if dict, err := m.Refresh(); err == nil && len(dict.Providers) > 0 {
		return dict, nil
	}
	return m.loadSeed()
}

func (m *Manager) Refresh() (*Dictionary, error) {
	openListPath := strings.TrimSpace(m.openListPath)
	if openListPath == "" {
		return m.refreshFromSeedOnly()
	}
	if _, err := os.Stat(filepath.Join(openListPath, "drivers")); err != nil {
		return m.refreshFromSeedOnly()
	}
	scanned, err := scanOpenListDrivers(openListPath)
	if err != nil {
		return m.refreshFromSeedOnlyWithErr(err)
	}
	existing, _ := m.Load()
	dict := mergeDictionary(scanned, existing)
	dict.Version = "v1"
	dict.Source = "openlist_scan+manual"
	dict.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := m.Save(dict); err != nil {
		return nil, err
	}
	return dict, nil
}

func (m *Manager) refreshFromSeedOnly() (*Dictionary, error) {
	return m.refreshFromSeedOnlyWithErr(nil)
}

func (m *Manager) refreshFromSeedOnlyWithErr(cause error) (*Dictionary, error) {
	seed, seedErr := m.loadSeed()
	if seedErr != nil {
		if cause != nil {
			return nil, errors.Join(cause, seedErr)
		}
		return nil, seedErr
	}
	existing, _ := m.Load()
	dict := mergeDictionary(seed, existing)
	dict.Version = "v1"
	dict.Source = "seed+manual"
	dict.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := m.Save(dict); err != nil {
		return nil, err
	}
	return dict, nil
}

func (m *Manager) loadSeed() (*Dictionary, error) {
	if strings.TrimSpace(m.seedPath) == "" {
		return nil, os.ErrNotExist
	}
	data, err := os.ReadFile(m.seedPath)
	if err != nil {
		return nil, err
	}
	var out Dictionary
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	if out.Version == "" {
		out.Version = "v1"
	}
	if out.Source == "" {
		out.Source = "seed"
	}
	if out.UpdatedAt == "" {
		out.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	return &out, nil
}

type scanProvider struct {
	ID      string
	NameEN  string
	Domains map[string]struct{}
}

var (
	nameRegex = regexp.MustCompile(`Name:\s*"([^"]+)"`)
	urlRegex  = regexp.MustCompile(`https?://[A-Za-z0-9._:-]+`)
)

func scanOpenListDrivers(openListPath string) (*Dictionary, error) {
	root := filepath.Join(openListPath, "drivers")
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	providers := make([]ProviderItem, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		driverID := strings.ToLower(strings.TrimSpace(entry.Name()))
		if driverID == "" {
			continue
		}
		driverDir := filepath.Join(root, entry.Name())
		sp := &scanProvider{
			ID:      driverID,
			NameEN:  readDriverNameEN(driverDir),
			Domains: map[string]struct{}{},
		}
		filepath.WalkDir(driverDir, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil || d.IsDir() || !strings.HasSuffix(strings.ToLower(path), ".go") {
				return nil
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			for _, u := range urlRegex.FindAllString(string(body), -1) {
				host := extractHost(u)
				if host == "" || shouldSkipHost(host) {
					continue
				}
				sp.Domains[host] = struct{}{}
			}
			return nil
		})
		if sp.NameEN == "" {
			sp.NameEN = entry.Name()
		}
		domains := mapKeys(sp.Domains)
		if len(domains) == 0 {
			continue
		}
		zh := mapProviderNameZH(sp.ID, sp.NameEN)
		category := classifyProvider(sp.ID, domains)
		providers = append(providers, ProviderItem{
			ID:              sp.ID,
			ProviderNameZH:  zh,
			ProviderNameEN:  sp.NameEN,
			Category:        category,
			Domains:         domains,
			DefaultSelected: category == "overseas",
		})
	}
	sort.Slice(providers, func(i, j int) bool {
		if providers[i].Category != providers[j].Category {
			return providers[i].Category < providers[j].Category
		}
		return providers[i].ID < providers[j].ID
	})
	return &Dictionary{Providers: providers}, nil
}

func readDriverNameEN(driverDir string) string {
	metaPath := filepath.Join(driverDir, "meta.go")
	body, err := os.ReadFile(metaPath)
	if err != nil {
		return ""
	}
	m := nameRegex.FindStringSubmatch(string(body))
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

func extractHost(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if host == "" {
		return ""
	}
	return host
}

func shouldSkipHost(host string) bool {
	if host == "" {
		return true
	}
	if host == "localhost" || strings.HasSuffix(host, ".local") {
		return true
	}
	if strings.HasPrefix(host, "127.") || strings.HasPrefix(host, "192.168.") {
		return true
	}
	if strings.Contains(host, "example.com") {
		return true
	}
	return false
}

func mapKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for item := range m {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func classifyProvider(id string, domains []string) string {
	domesticKeywords := []string{"baidu", "aliyun", "alipan", "189", "139", "quark", "uc.", "xunlei", "weiyun", "123pan", "lanzou", "woozooo", "wps", "yun.139", "10086", "chaoxing"}
	checkText := id + " " + strings.Join(domains, " ")
	for _, keyword := range domesticKeywords {
		if strings.Contains(checkText, keyword) {
			return "domestic"
		}
	}
	overseasKeywords := []string{"google", "onedrive", "microsoft", "dropbox", "proton", "yandex", "mega", "mediafire", "terabox", "pikpak", "github"}
	for _, keyword := range overseasKeywords {
		if strings.Contains(checkText, keyword) {
			return "overseas"
		}
	}
	return "other"
}

func mapProviderNameZH(id, fallbackEN string) string {
	known := map[string]string{
		"google_drive":       "谷歌云盘",
		"google_photo":       "谷歌相册",
		"onedrive":           "微软网盘",
		"onedrive_app":       "微软网盘",
		"onedrive_sharelink": "微软网盘分享",
		"dropbox":            "Dropbox 网盘",
		"proton_drive":       "Proton 网盘",
		"yandex_disk":        "Yandex 网盘",
		"mediafire":          "MediaFire 网盘",
		"mega":               "MEGA 网盘",
		"terabox":            "TeraBox 网盘",
		"baidu_netdisk":      "百度网盘",
		"baidu_photo":        "百度相册",
		"aliyundrive":        "阿里云盘",
		"aliyundrive_open":   "阿里云盘开放",
		"quark_uc":           "夸克/UC 网盘",
		"quark_open":         "夸克开放平台",
		"quark_uc_tv":        "夸克/UC TV 网盘",
		"weiyun":             "微云",
		"_123":               "123网盘",
		"123":                "123网盘",
		"123_open":           "123网盘开放",
		"123_share":          "123网盘分享",
		"115":                "115 网盘",
		"115_open":           "115 开放平台",
		"115_share":          "115 分享",
		"189":                "天翼云盘",
		"189pc":              "天翼云盘PC",
		"189_tv":             "天翼云盘TV",
		"139":                "移动云盘",
		"pikpak":             "PikPak",
		"pikpak_share":       "PikPak 分享",
	}
	if zh, ok := known[id]; ok {
		return zh
	}
	return fallbackEN
}

func mergeDictionary(scanned *Dictionary, existing *Dictionary) *Dictionary {
	if scanned == nil {
		scanned = &Dictionary{}
	}
	if existing == nil {
		return scanned
	}
	byID := make(map[string]ProviderItem, len(existing.Providers))
	for _, item := range existing.Providers {
		byID[item.ID] = item
	}
	for i := range scanned.Providers {
		old, ok := byID[scanned.Providers[i].ID]
		if !ok {
			continue
		}
		if strings.TrimSpace(old.ProviderNameZH) != "" {
			scanned.Providers[i].ProviderNameZH = old.ProviderNameZH
		}
		extra := make(map[string]struct{}, len(scanned.Providers[i].Domains)+len(old.Domains))
		for _, d := range scanned.Providers[i].Domains {
			extra[d] = struct{}{}
		}
		for _, d := range old.Domains {
			extra[strings.ToLower(strings.TrimSpace(d))] = struct{}{}
		}
		scanned.Providers[i].Domains = mapKeys(extra)
	}
	return scanned
}
