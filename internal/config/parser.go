package config

import "strings"

// ParsePasswdList parses a raw passwdList from JSON into PasswdInfo slice
func ParsePasswdList(raw interface{}) []PasswdInfo {
	var result []PasswdInfo

	passwdListRaw, ok := raw.([]interface{})
	if !ok {
		return result
	}

	for _, item := range passwdListRaw {
		passwdMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		passwd := PasswdInfo{
			Password:  getStringField(passwdMap, "password"),
			EncType:   getStringField(passwdMap, "encType"),
			Describe:  getStringField(passwdMap, "describe"),
			Enable:    getBoolField(passwdMap, "enable"),
			EncName:   getBoolField(passwdMap, "encName"),
			EncSuffix: getStringField(passwdMap, "encSuffix"),
			EncPath:   getStringArrayField(passwdMap, "encPath"),
		}
		result = append(result, passwd)
	}

	return result
}

// Helper functions for parsing raw JSON maps

func getStringField(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func getIntField(m map[string]interface{}, key string) int {
	if v, ok := m[key].(float64); ok {
		return int(v)
	}
	return 0
}

func getBoolField(m map[string]interface{}, key string) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return false
}

func getStringArrayField(m map[string]interface{}, key string) []string {
	// Handle as array
	if arr, ok := m[key].([]interface{}); ok {
		var result []string
		for _, v := range arr {
			if s, ok := v.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	// Handle as comma-separated string
	if s, ok := m[key].(string); ok && s != "" {
		return strings.Split(s, ",")
	}
	return nil
}

// ParseAlistServerFromMap parses an AlistServer from a raw map
func ParseAlistServerFromMap(raw map[string]interface{}) AlistServer {
	server := AlistServer{
		Name:       getStringField(raw, "name"),
		Path:       getStringField(raw, "path"),
		Describe:   getStringField(raw, "describe"),
		ServerHost: getStringField(raw, "serverHost"),
		ServerPort: getIntField(raw, "serverPort"),
		HTTPS:      getBoolField(raw, "https"),
		EnableH2C:  getBoolField(raw, "enableH2c"),
	}

	if passwdListRaw, ok := raw["passwdList"]; ok {
		server.PasswdList = ParsePasswdList(passwdListRaw)
	}

	return server
}

// ParseWebDAVServerFromMap parses a WebDAVServer from a raw map
func ParseWebDAVServerFromMap(raw map[string]interface{}) WebDAVServer {
	server := WebDAVServer{
		ID:         getStringField(raw, "id"),
		Name:       getStringField(raw, "name"),
		Describe:   getStringField(raw, "describe"),
		Path:       getStringField(raw, "path"),
		Enable:     getBoolField(raw, "enable"),
		ServerHost: getStringField(raw, "serverHost"),
		ServerPort: getIntField(raw, "serverPort"),
		HTTPS:      getBoolField(raw, "https"),
	}

	if passwdListRaw, ok := raw["passwdList"]; ok {
		server.PasswdList = ParsePasswdList(passwdListRaw)
	}

	return server
}
