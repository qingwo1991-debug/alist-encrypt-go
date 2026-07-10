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
