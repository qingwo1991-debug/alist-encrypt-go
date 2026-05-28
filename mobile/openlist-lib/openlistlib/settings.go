package openlistlib

import (
	"fmt"
	"strings"

	"github.com/OpenListTeam/OpenList/v4/cmd"
	"github.com/OpenListTeam/OpenList/v4/cmd/flags"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
)

func SetConfigData(path string) {
	flags.DataDir = path
}

func SetConfigLogStd(b bool) {
	flags.LogStd = b
}

func SetConfigDebug(b bool) {
	flags.Debug = b
}

func SetConfigNoPrefix(b bool) {
	flags.NoPrefix = b
}

func SetAdminPassword(pwd string) error {
	pwd = strings.TrimSpace(pwd)
	if len(pwd) < 4 {
		return fmt.Errorf("admin password must be at least 4 characters")
	}

	admin, err := op.GetAdmin()
	if err != nil {
		return fmt.Errorf("failed get admin user: %w", err)
	}
	admin.SetPassword(pwd)
	if err := op.UpdateUser(admin); err != nil {
		return fmt.Errorf("failed update admin user: %w", err)
	}
	utils.Log.Infof("admin user has been updated:")
	utils.Log.Infof("username: %s", admin.Username)
	cmd.DelAdminCacheOnline()
	return nil
}
