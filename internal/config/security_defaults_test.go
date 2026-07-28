package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigGeneratesRandomJWTSecret(t *testing.T) {
	baseDir := t.TempDir()
	cfg := loadConfigAt(filepath.Join(baseDir, "conf", "config.json"))

	if cfg.JWTSecret == "" {
		t.Fatal("expected generated jwt secret")
	}
	if cfg.JWTSecret == "alist-encrypt-secret" {
		t.Fatal("expected non-default jwt secret")
	}
	if len(cfg.JWTSecret) != 64 {
		t.Fatalf("jwt secret len=%d, want 64", len(cfg.JWTSecret))
	}
}

func TestDefaultConfigDoesNotEnableKnownEncryptionPassword(t *testing.T) {
	cfg := DefaultConfig()
	for _, rule := range cfg.AlistServer.PasswdList {
		if rule.Enable && (rule.Password == "" || rule.Password == "123456") {
			t.Fatalf("default config enables an unsafe encryption password for %v", rule.EncPath)
		}
	}
}

func TestConfigRejectsEnabledRulesWithBlankPasswords(t *testing.T) {
	cfg := LoadFromBaseDir(t.TempDir())
	server := cfg.AlistServerSnapshot()
	server.PasswdList = []PasswdInfo{{Enable: true, Password: "  ", EncPath: []string{"/encrypt/*"}}}
	if err := cfg.UpdateAlistServer(server); err == nil || !strings.Contains(err.Error(), "password is empty") {
		t.Fatalf("UpdateAlistServer() error = %v, want blank-password rejection", err)
	}
	if got := cfg.AlistServerSnapshot().PasswdList; len(got) != 0 {
		t.Fatalf("invalid Alist rule was persisted: %#v", got)
	}

	webdav := WebDAVServer{ID: "test", PasswdList: []PasswdInfo{{Enable: true, Password: "\t"}}}
	if err := cfg.AddWebDAVServer(webdav); err == nil || !strings.Contains(err.Error(), "password is empty") {
		t.Fatalf("AddWebDAVServer() error = %v, want blank-password rejection", err)
	}
	if got := cfg.WebDAVServersSnapshot(); len(got) != 0 {
		t.Fatalf("invalid WebDAV rule was persisted: %#v", got)
	}
}

func TestConfigUpdatesDoNotRetainCallerSlices(t *testing.T) {
	cfg := LoadFromBaseDir(t.TempDir())
	server := cfg.AlistServerSnapshot()
	server.PasswdList = []PasswdInfo{{Enable: true, Password: "strong-password", EncPath: []string{"/safe/*"}}}
	if err := cfg.UpdateAlistServer(server); err != nil {
		t.Fatal(err)
	}
	saved := cfg.AlistServerSnapshot().PasswdList[0]
	server.PasswdList[0].Password = "mutated"
	server.PasswdList[0].EncPath[0] = "/mutated/*"
	got := cfg.AlistServerSnapshot().PasswdList[0]
	if got.Password != saved.Password || got.EncPath[0] != saved.EncPath[0] {
		t.Fatalf("live Alist config retained caller-owned slices: %#v", got)
	}

	webdav := WebDAVServer{ID: "test", PasswdList: []PasswdInfo{{Enable: true, Password: "webdav-password", EncPath: []string{"/dav/*"}}}}
	if err := cfg.AddWebDAVServer(webdav); err != nil {
		t.Fatal(err)
	}
	savedWebDAV := cfg.WebDAVServersSnapshot()[0].PasswdList[0]
	webdav.PasswdList[0].Password = "mutated"
	webdav.PasswdList[0].EncPath[0] = "/mutated/*"
	gotWebDAV := cfg.WebDAVServersSnapshot()[0].PasswdList[0]
	if gotWebDAV.Password != savedWebDAV.Password || gotWebDAV.EncPath[0] != savedWebDAV.EncPath[0] {
		t.Fatalf("live WebDAV config retained caller-owned slices: %#v", gotWebDAV)
	}
}

func TestConfigUpdateRollsBackWhenPersistenceFails(t *testing.T) {
	cfg := DefaultConfig()
	cfg.configPath = t.TempDir() // atomic rename cannot replace an existing directory
	before := cfg.AlistServerSnapshot()
	updated := before
	updated.Name = "must-not-stick"
	if err := cfg.UpdateAlistServer(updated); err == nil {
		t.Fatal("UpdateAlistServer() unexpectedly succeeded with an invalid config path")
	}
	after := cfg.AlistServerSnapshot()
	if after.Name != before.Name {
		t.Fatalf("failed persistence changed live config: before=%q after=%q", before.Name, after.Name)
	}
}

func TestConfigSaveUses0600Permissions(t *testing.T) {
	baseDir := t.TempDir()
	cfg := loadConfigAt(filepath.Join(baseDir, "conf", "config.json"))
	if err := cfg.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	info, err := os.Stat(filepath.Join(baseDir, "conf", "config.json"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("perm=%#o, want %#o", got, 0o600)
	}
}

func TestConfigSavePreservesDatabaseConfig(t *testing.T) {
	baseDir := t.TempDir()
	cfg := loadConfigAt(filepath.Join(baseDir, "conf", "config.json"))
	cfg.Database.Type = "mysql"
	cfg.Database.DSN = "user:pass@tcp(localhost:3306)/alist"
	if err := cfg.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(baseDir, "conf", "config.json"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !bytes.Contains(data, []byte(`"database"`)) {
		t.Fatalf("saved config missing database section: %s", data)
	}
	if !bytes.Contains(data, []byte(`"type": "mysql"`)) {
		t.Fatalf("saved config missing database type: %s", data)
	}
}
