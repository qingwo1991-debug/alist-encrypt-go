package proxydict

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRefreshMergesSeedAndManual(t *testing.T) {
	tmp := t.TempDir()
	dictPath := filepath.Join(tmp, "conf", "proxy_domain_dict.json")
	seedPath := filepath.Join(tmp, "configs", "proxy_domain_dict.seed.json")
	if err := os.MkdirAll(filepath.Dir(seedPath), 0755); err != nil {
		t.Fatalf("mkdir seed dir failed: %v", err)
	}

	seed := `{
		"version":"v1",
		"source":"seed",
		"providers":[
			{"id":"google_drive","provider_name_zh":"谷歌云盘","provider_name_en":"GoogleDrive","category":"overseas","domains":["googleapis.com"],"default_selected":true}
		]
	}`
	if err := os.WriteFile(seedPath, []byte(seed), 0644); err != nil {
		t.Fatalf("write seed failed: %v", err)
	}

	manual := `{
		"version":"v1",
		"source":"seed+manual",
		"providers":[
			{"id":"google_drive","provider_name_zh":"Google 云盘","provider_name_en":"GoogleDrive","category":"overseas","domains":["custom.googleapis.com"],"default_selected":true}
		]
	}`
	if err := os.MkdirAll(filepath.Dir(dictPath), 0755); err != nil {
		t.Fatalf("mkdir conf dir failed: %v", err)
	}
	if err := os.WriteFile(dictPath, []byte(manual), 0644); err != nil {
		t.Fatalf("write manual failed: %v", err)
	}

	mgr := NewManager(dictPath, seedPath)
	out, err := mgr.Refresh()
	if err != nil {
		t.Fatalf("refresh failed: %v", err)
	}
	if out.Source != "seed+manual" {
		t.Fatalf("source=%q, want seed+manual", out.Source)
	}
	if len(out.Providers) != 1 {
		t.Fatalf("providers len=%d, want 1", len(out.Providers))
	}
	item := out.Providers[0]
	if item.ProviderNameZH != "Google 云盘" {
		t.Fatalf("provider zh=%q, want manual override", item.ProviderNameZH)
	}
	if len(item.Domains) != 2 {
		t.Fatalf("domains len=%d, want 2", len(item.Domains))
	}
}
