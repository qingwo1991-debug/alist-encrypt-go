package dao

import (
	"testing"

	"github.com/alist-encrypt-go/internal/storage"
)

func TestEnsureDefaultUserGeneratesRandomPassword(t *testing.T) {
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	dao := NewUserDAO(store)
	if err := dao.EnsureDefaultUser(); err != nil {
		t.Fatalf("ensure default user: %v", err)
	}

	if err := dao.Validate("admin", "123456"); err == nil {
		t.Fatal("default admin password should no longer be 123456")
	}
	user, err := dao.Get("admin")
	if err != nil {
		t.Fatalf("get admin: %v", err)
	}
	if user.PasswordHash == "" {
		t.Fatal("expected stored password hash")
	}
}
