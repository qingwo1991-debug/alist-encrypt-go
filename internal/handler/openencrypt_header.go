package handler

import (
	"net/http"
	"strings"

	"github.com/alist-encrypt-go/internal/config"
)

// PasswdInfoFromOpenEncryptHeaders extracts encryption configuration from
// X-OpenEncrypt-Rule-* headers set by openencrypt-android's core-openlist-go proxy.
// Returns nil if the headers are not present or incomplete.
func PasswdInfoFromOpenEncryptHeaders(r *http.Request) *config.PasswdInfo {
	if r == nil {
		return nil
	}
	matched := strings.TrimSpace(r.Header.Get("X-OpenEncrypt-Rule-Matched"))
	if matched != "true" {
		return nil
	}
	operation := strings.TrimSpace(r.Header.Get("X-OpenEncrypt-Operation"))
	if operation != "" && operation != "decrypt" {
		// Only handle decrypt operations; encrypt is for uploads
		return nil
	}
	password := strings.TrimSpace(r.Header.Get("X-OpenEncrypt-Rule-Password"))
	if password == "" {
		return nil
	}
	encType := strings.TrimSpace(r.Header.Get("X-OpenEncrypt-Rule-Enc-Type"))
	if encType == "" {
		encType = "aesctr" // default
	}
	encNameStr := strings.TrimSpace(r.Header.Get("X-OpenEncrypt-Rule-Enc-Name"))
	encName := encNameStr == "true"

	return &config.PasswdInfo{
		Password: password,
		EncType:  encType,
		EncName:  encName,
		Enable:   true,
	}
}
