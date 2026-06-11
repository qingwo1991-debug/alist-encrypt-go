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

func TestUserDAORenameIsAtomicWhenTargetExists(t *testing.T) {
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	dao := NewUserDAO(store)
	if err := dao.Create("admin", "password123"); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	if err := dao.Create("existing", "password456"); err != nil {
		t.Fatalf("create existing: %v", err)
	}

	if err := dao.Rename("admin", "password123", "existing"); err != ErrUserExists {
		t.Fatalf("rename err=%v, want %v", err, ErrUserExists)
	}
	if err := dao.Validate("admin", "password123"); err != nil {
		t.Fatalf("old user should remain valid after failed rename: %v", err)
	}
	if err := dao.Validate("existing", "password456"); err != nil {
		t.Fatalf("target user should remain valid: %v", err)
	}
}

func TestUserDAORenameSuccess(t *testing.T) {
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	dao := NewUserDAO(store)
	if err := dao.Create("admin", "password123"); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	if err := dao.Rename("admin", "password123", "owner"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if err := dao.Validate("owner", "password123"); err != nil {
		t.Fatalf("new user should validate: %v", err)
	}
	if _, err := dao.Get("admin"); err != ErrUserNotFound {
		t.Fatalf("old user err=%v, want %v", err, ErrUserNotFound)
	}
}
