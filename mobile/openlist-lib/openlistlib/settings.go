package openlistlib

import (
	"strings"

	"github.com/OpenListTeam/OpenList/v4/cmd"
	"github.com/OpenListTeam/OpenList/v4/cmd/flags"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/server/common"
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

func SetAdminPassword(pwd string) {
	pwd = strings.TrimSpace(pwd)
	if len(pwd) < 4 {
		utils.Log.Errorf("[mobile_set_admin_password] password too short: length=%d", len(pwd))
		return
	}

	utils.Log.Infof("[mobile_set_admin_password] start length=%d", len(pwd))
	admin, err := op.GetAdmin()
	if err != nil {
		utils.Log.Errorf("[mobile_set_admin_password] failed get admin user: %+v", err)
		return
	}
	utils.Log.Infof("[mobile_set_admin_password] admin user loaded: username=%s", admin.Username)
	admin.SetPassword(pwd)
	utils.Log.Infof("[mobile_set_admin_password] password hash prepared")
	if err := op.UpdateUser(admin); err != nil {
		utils.Log.Errorf("[mobile_set_admin_password] failed update admin user: %+v", err)
		return
	}
	utils.Log.Infof("[mobile_set_admin_password] admin user updated: username=%s", admin.Username)
	cmd.DelAdminCacheOnline()
	utils.Log.Infof("[mobile_set_admin_password] admin cache refresh requested")
}

func VerifyAdminPassword(pwd string) bool {
	pwd = strings.TrimSpace(pwd)
	if len(pwd) < 4 {
		return false
	}
	admin, err := op.GetAdmin()
	if err != nil {
		utils.Log.Errorf("[mobile_verify_admin_password] failed get admin user: %+v", err)
		return false
	}
	if err := admin.ValidateRawPassword(pwd); err != nil {
		return false
	}
	return true
}

func AcquireAdminTokenByPassword(pwd string) string {
	pwd = strings.TrimSpace(pwd)
	if len(pwd) < 4 {
		return ""
	}
	admin, err := op.GetAdmin()
	if err != nil {
		utils.Log.Errorf("[mobile_acquire_admin_token] failed get admin user: %+v", err)
		return ""
	}
	if err := admin.ValidateRawPassword(pwd); err != nil {
		return ""
	}
	if admin.OtpSecret != "" {
		utils.Log.Warnf("[mobile_acquire_admin_token] admin user has 2FA enabled; local token shortcut skipped")
		return ""
	}
	token, err := common.GenerateToken(admin)
	if err != nil {
		utils.Log.Errorf("[mobile_acquire_admin_token] failed generate token: %+v", err)
		return ""
	}
	return token
}
