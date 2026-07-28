package dao

import (
	"testing"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/storage"
)

func TestDAOsUseProvidedConfigInstance(t *testing.T) {
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("storage.NewStore: %v", err)
	}
	defer store.Close()

	cfg := config.DefaultConfig()
	cfg.AlistServer.PasswdList = []config.PasswdInfo{{
		Password: "provided-config-password",
		Enable:   true,
	}}

	fileDAO := NewFileDAO(store, cfg)
	defer fileDAO.Stop()
	passwdDAO := NewPasswdDAO(store, cfg)
	defer passwdDAO.Stop()

	if fileDAO.cfg != cfg || fileDAO.Config() != cfg {
		t.Fatal("FileDAO did not retain the provided config instance")
	}
	if passwdDAO.cfg != cfg {
		t.Fatal("PasswdDAO did not retain the provided config instance")
	}
	passwords := passwdDAO.GetAll()
	if len(passwords) != 1 || passwords[0].Password != "provided-config-password" {
		t.Fatalf("PasswdDAO read unexpected config: %+v", passwords)
	}
}

func TestPasswdDAOReloadClearsNegativeMatchesAndUsesSnapshots(t *testing.T) {
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("storage.NewStore: %v", err)
	}
	defer store.Close()

	cfg := config.DefaultConfig()
	cfg.AlistServer.PasswdList = []config.PasswdInfo{}
	passwdDAO := NewPasswdDAO(store, cfg)
	defer passwdDAO.Stop()

	if _, ok := passwdDAO.FindByPath("/secure/movie.mp4"); ok {
		t.Fatal("unexpected match before rule is configured")
	}
	cfg.AlistServer.PasswdList = []config.PasswdInfo{{
		Password: "new-password",
		EncType:  "aesctr",
		Enable:   true,
		EncPath:  []string{"/secure/*"},
	}}
	passwdDAO.Reload()
	got, ok := passwdDAO.FindByPath("/secure/movie.mp4")
	if !ok || got.Password != "new-password" {
		t.Fatalf("match after Reload = %#v, %v", got, ok)
	}

	all := passwdDAO.GetAll()
	cfg.AlistServer.PasswdList[0].Password = "mutated-live-config"
	if all[0].Password != "new-password" {
		t.Fatalf("GetAll returned a pointer into live config: %q", all[0].Password)
	}
}
