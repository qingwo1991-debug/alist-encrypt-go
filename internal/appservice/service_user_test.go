package appservice

import (
	"strings"
	"testing"

	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/storage"
)

func TestUpdatePasswordRejectsPasswordsShorterThanEightCharacters(t *testing.T) {
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	users := dao.NewUserDAO(store)
	if err := users.Create("admin", "current-password"); err != nil {
		t.Fatalf("create user: %v", err)
	}
	svc := New(Deps{UserDAO: users})

	for _, password := range []string{"1234567", "中文密码", "        "} {
		err = svc.UpdatePassword("admin", "current-password", password)
		if err == nil || !strings.Contains(err.Error(), "at least 8") {
			t.Fatalf("UpdatePassword(%q) error = %v, want minimum-length rejection", password, err)
		}
	}
	if err := users.Validate("admin", "current-password"); err != nil {
		t.Fatalf("rejected update changed the current password: %v", err)
	}
}
