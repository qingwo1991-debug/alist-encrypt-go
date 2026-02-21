package proxydict

import (
	"encoding/json"
	"os"
	"path/filepath"
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

// Manager only supports "seed + manual override" mode.
// It intentionally does not scan external source trees.
type Manager struct {
	dictPath string
	seedPath string
}

func NewManager(dictPath, seedPath string) *Manager {
	return &Manager{
		dictPath: dictPath,
		seedPath: seedPath,
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
	return m.Refresh()
}

func (m *Manager) Refresh() (*Dictionary, error) {
	seed, err := m.loadSeed()
	if err != nil {
		return nil, err
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

func mapKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for item := range m {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func mergeDictionary(seed *Dictionary, existing *Dictionary) *Dictionary {
	if seed == nil {
		seed = &Dictionary{}
	}
	if existing == nil {
		return seed
	}
	byID := make(map[string]ProviderItem, len(existing.Providers))
	for _, item := range existing.Providers {
		byID[item.ID] = item
	}
	for i := range seed.Providers {
		old, ok := byID[seed.Providers[i].ID]
		if !ok {
			continue
		}
		if strings.TrimSpace(old.ProviderNameZH) != "" {
			seed.Providers[i].ProviderNameZH = old.ProviderNameZH
		}
		extra := make(map[string]struct{}, len(seed.Providers[i].Domains)+len(old.Domains))
		for _, d := range seed.Providers[i].Domains {
			extra[d] = struct{}{}
		}
		for _, d := range old.Domains {
			item := strings.ToLower(strings.TrimSpace(d))
			if item == "" {
				continue
			}
			extra[item] = struct{}{}
		}
		seed.Providers[i].Domains = mapKeys(extra)
	}
	return seed
}
