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
			EncSuffix: normalizeEncSuffixField(getStringField(passwdMap, "encSuffix")),
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

func getInt64Field(m map[string]interface{}, key string) int64 {
	if v, ok := m[key].(float64); ok {
		return int64(v)
	}
	return 0
}

func getBoolField(m map[string]interface{}, key string) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return false
}

func getBoolFieldWithDefault(m map[string]interface{}, key string, defaultValue bool) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return defaultValue
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
		return NormalizeUserEncPaths(result)
	}
	// Handle as comma-separated string
	if s, ok := m[key].(string); ok && s != "" {
		return NormalizeUserEncPaths([]string{s})
	}
	return nil
}

func normalizeEncSuffixField(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if strings.HasPrefix(v, ".") {
		return v
	}
	return "." + v
}

// ParseAlistServerFromMap parses an AlistServer from a raw map
func ParseAlistServerFromMap(raw map[string]interface{}) AlistServer {
	server := AlistServer{
		Name:                        getStringField(raw, "name"),
		Path:                        getStringField(raw, "path"),
		Describe:                    getStringField(raw, "describe"),
		ServerHost:                  getStringField(raw, "serverHost"),
		ServerPort:                  getIntField(raw, "serverPort"),
		HTTPS:                       getBoolField(raw, "https"),
		EnableH2C:                   getBoolField(raw, "enableH2c"),
		EnableSizeMap:               getBoolField(raw, "enableSizeMap"),
		SizeMapTtlMinutes:           getIntField(raw, "sizeMapTtlMinutes"),
		EnableRangeCompatCache:      getBoolField(raw, "enableRangeCompatCache"),
		RangeFailToDowngrade:        getIntField(raw, "rangeFailToDowngrade"),
		RangeSuccessToRecover:       getIntField(raw, "rangeSuccessToRecover"),
		RangeReprobeMinutes:         getIntField(raw, "rangeReprobeMinutes"),
		RangeProbeTimeoutSeconds:    getIntField(raw, "rangeProbeTimeoutSeconds"),
		EnableParallelDecrypt:       getBoolField(raw, "enableParallelDecrypt"),
		ParallelDecryptConcurrency:  getIntField(raw, "parallelDecryptConcurrency"),
		StreamBufferKb:              getIntField(raw, "streamBufferKb"),
		FollowRedirectForDecrypt:    getBoolField(raw, "followRedirectForDecrypt"),
		RedirectMaxHops:             getIntField(raw, "redirectMaxHops"),
		AllowLooseDecode:            getBoolField(raw, "allowLooseDecode"),
		RequestTimeoutSeconds:       getIntField(raw, "requestTimeoutSeconds"),
		EnableStartupProbe:          getBoolField(raw, "enableStartupProbe"),
		StartupProbeDelaySeconds:    getIntField(raw, "startupProbeDelaySeconds"),
		StartupProbeIntervalMinutes: getIntField(raw, "startupProbeIntervalMinutes"),
		NegativeCacheMinutes:        getIntField(raw, "negativeCacheMinutes"),
		StartupProbeDeepScan:        getBoolField(raw, "startupProbeDeepScan"),
		ScanUsername:                getStringField(raw, "scanUsername"),
		ScanPassword:                getStringField(raw, "scanPassword"),
		ScanAuthHeader:              getStringField(raw, "scanAuthHeader"),
		ScanVideoOnly:               getBoolField(raw, "scanVideoOnly"),
		ScanMaxDepth:                getIntField(raw, "scanMaxDepth"),
		ScanConcurrency:             getIntField(raw, "scanConcurrency"),
		EnableStrategyStore:         getBoolField(raw, "enableStrategyStore"),
		StrategyStoreFile:           getStringField(raw, "strategyStoreFile"),
		StrategyFailToDowngrade:     getIntField(raw, "strategyFailToDowngrade"),
		StrategySuccessToRecover:    getIntField(raw, "strategySuccessToRecover"),
		StrategyCooldownMinutes:     getIntField(raw, "strategyCooldownMinutes"),
		EnableBackgroundProbe:       getBoolFieldWithDefault(raw, "enableBackgroundProbe", true),
		ProbeConcurrency:            getIntField(raw, "probeConcurrency"),
		ProbeProviderConcurrency:    getIntField(raw, "probeProviderConcurrency"),
		ProbeMinDelayMs:             getIntField(raw, "probeMinDelayMs"),
		ProbeMaxDelayMs:             getIntField(raw, "probeMaxDelayMs"),
		ProbeCooldownMinutes:        getIntField(raw, "probeCooldownMinutes"),
		ProbeQueueSize:              getIntField(raw, "probeQueueSize"),
		ProbeMinSizeBytes:           getInt64Field(raw, "probeMinSizeBytes"),
		PlayFirstFallback:           getBoolFieldWithDefault(raw, "playFirstFallback", true),
	}

	if passwdListRaw, ok := raw["passwdList"]; ok {
		server.PasswdList = ParsePasswdList(passwdListRaw)
	}
	if overridesRaw, ok := raw["streamStrategyOverrides"]; ok {
		server.StreamStrategyOverrides = ParseStreamStrategyOverrides(overridesRaw)
	}
	if !hasBoolField(raw, "enableRangeCompatCache") {
		server.EnableRangeCompatCache = true
	}
	if server.RangeFailToDowngrade <= 0 {
		server.RangeFailToDowngrade = 2
	}
	if server.RangeSuccessToRecover <= 0 {
		server.RangeSuccessToRecover = 3
	}
	if server.RangeReprobeMinutes <= 0 {
		server.RangeReprobeMinutes = 30
	}
	if server.RangeProbeTimeoutSeconds <= 0 {
		server.RangeProbeTimeoutSeconds = 8
	}
	server.RangeFailToDowngrade = clampInt(server.RangeFailToDowngrade, 1, 10)
	server.RangeSuccessToRecover = clampInt(server.RangeSuccessToRecover, 1, 20)
	server.RangeReprobeMinutes = clampInt(server.RangeReprobeMinutes, 1, 1440)
	server.RangeProbeTimeoutSeconds = clampInt(server.RangeProbeTimeoutSeconds, 2, 60)
	server.ProbeConcurrency = clampInt(server.ProbeConcurrency, 1, 20)
	server.ProbeProviderConcurrency = clampInt(server.ProbeProviderConcurrency, 1, 5)
	server.ProbeMinDelayMs = clampInt(server.ProbeMinDelayMs, 0, 60000)
	server.ProbeMaxDelayMs = clampInt(server.ProbeMaxDelayMs, 0, 120000)
	server.ProbeCooldownMinutes = clampInt(server.ProbeCooldownMinutes, 1, 10080)
	server.ProbeQueueSize = clampInt(server.ProbeQueueSize, 100, 10000)

	return server
}

func hasBoolField(m map[string]interface{}, key string) bool {
	_, ok := m[key].(bool)
	return ok
}

func clampInt(v, min, max int) int {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

// ParseStreamStrategyOverrides parses overrides from JSON into StreamStrategyOverride slice
func ParseStreamStrategyOverrides(raw interface{}) []StreamStrategyOverride {
	var result []StreamStrategyOverride
	items, ok := raw.([]interface{})
	if !ok {
		return result
	}
	for _, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		override := StreamStrategyOverride{
			PathPrefix: getStringField(m, "pathPrefix"),
			Strategy:   getStringField(m, "strategy"),
		}
		if override.PathPrefix == "" || override.Strategy == "" {
			continue
		}
		result = append(result, override)
	}
	return result
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
