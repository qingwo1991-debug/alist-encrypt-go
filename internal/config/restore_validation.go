package config

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
)

// ValidateRestoreConfig validates supplied bytes without defaults, file writes,
// environment expansion or secret generation. It does not prove historical
// correspondence to a DB-only snapshot; the operator supplies a pinned digest.
func ValidateRestoreConfig(raw []byte, storeDir string) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	for _, key := range []string{"alistServer", "data_dir", "jwt_secret", "port"} {
		if len(fields[key]) == 0 {
			return errors.New("incomplete external config")
		}
	}
	var alistFields map[string]json.RawMessage
	if err := json.Unmarshal(fields["alistServer"], &alistFields); err != nil {
		return err
	}
	for _, key := range []string{"serverHost", "serverPort", "passwdList"} {
		if len(alistFields[key]) == 0 {
			return errors.New("incomplete external alist config")
		}
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return err
	}
	if !filepath.IsAbs(c.DataDir) || filepath.Clean(c.DataDir) != storeDir || strings.TrimSpace(c.JWTSecret) == "" || c.Port < 1 || c.Port > 65535 {
		return errors.New("external config store/secret/port mismatch")
	}
	// Match mysqlstore.NewStore's actual selector: either empty Type or empty
	// DSN disables the external store; only both set activate it.
	if c.Database != nil && c.Database.Type != "" && c.Database.DSN != "" {
		return errors.New("external database restore unsupported")
	}
	if err := validateServerEndpoint(c.AlistServer.ServerHost, c.AlistServer.ServerPort, "alist"); err != nil {
		return err
	}
	if err := validateEnabledPasswdList(c.AlistServer.PasswdList); err != nil {
		return err
	}
	return validateFilenameWriteLimits(c.AlistServer.FilenameWriteLimits)
}
