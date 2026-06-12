package handler

import (
	"path"
	"strings"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/encryption"
)

const (
	pathModePlain                    = "plain"
	pathModeCacheMapping             = "cache_mapping"
	pathModeOriginalPassthrough      = "orig_passthrough"
	pathModeEncryptedNameCache       = "encrypted_name_cache"
	pathModeEncryptedNamePassthrough = "encrypted_name_passthrough"
	pathModeDerived                  = "derived"
)

func resolveEncryptedRealPath(fileDAO *dao.FileDAO, passwdInfo *config.PasswdInfo, displayPath string, allowLoose bool) (string, string) {
	if passwdInfo == nil || !passwdInfo.EncName {
		return displayPath, pathModePlain
	}

	if fileDAO != nil {
		if encPath, ok := fileDAO.GetEncPath(displayPath); ok && strings.TrimSpace(encPath) != "" {
			return encPath, pathModeCacheMapping
		}
		if fileDAO.HasEncryptedPath(displayPath) {
			return displayPath, pathModeEncryptedNameCache
		}
	}

	fileName := path.Base(displayPath)
	if encryption.IsOriginalFile(fileName) {
		realName := encryption.StripOriginalPrefix(fileName)
		return path.Join(path.Dir(displayPath), realName), pathModeOriginalPassthrough
	}

	converter := encryption.NewFileNameConverter(passwdInfo.Password, passwdInfo.EncType, passwdInfo.EncSuffix)
	decryptedName := encryption.ConvertShowNameWithSuffixOptions(
		passwdInfo.Password,
		passwdInfo.EncType,
		fileName,
		passwdInfo.EncSuffix,
		allowLoose,
	)
	if decryptedName != "" && !encryption.IsOriginalFile(decryptedName) && decryptedName != fileName {
		if converter.ToRealName(decryptedName) == fileName {
			return displayPath, pathModeEncryptedNamePassthrough
		}
	}

	return path.Join(path.Dir(displayPath), converter.ToRealName(fileName)), pathModeDerived
}
