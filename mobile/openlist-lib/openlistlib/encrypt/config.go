package encrypt

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/OpenListTeam/OpenList/v4/openlistlib/internal"
	log "github.com/sirupsen/logrus"
)

// ConfigManager 配置管理器
type ConfigManager struct {
	configPath string
	config     *ProxyConfig
	mutex      sync.RWMutex
}

// DefaultConfig 默认配置
func DefaultConfig() *ProxyConfig {
	return &ProxyConfig{
		AlistHost:                       "127.0.0.1",
		AlistPort:                       5244,
		AlistHttps:                      false,
		ProxyPort:                       5344,
		UpstreamTimeoutSeconds:          8,
		ProbeTimeoutSeconds:             3,
		ProbeBudgetSeconds:              5,
		UpstreamBackoffSeconds:          20,
		EnableLocalBypass:               true,
		RoutingMode:                     routingModeByProvider,
		ProviderRuleSource:              "builtin+custom",
		RoutingUnmatchedDefault:         routingActionProxy,
		ProviderCatalogEnabled:          true,
		ProviderCatalogTTLMinutes:       720,
		ProviderCatalogBootstrapOnStart: true,
		StorageMapRefreshMinutes:        30,
		ProbeOnDownload:                 true,  // 默认开启，确保能正确获取文件大小以解密
		EnableH2C:                       false, // H2C 默认关闭，需要后端 OpenList 也开启 enable_h2c 才有效
		ProbeStrategyTTLMinutes:         defaultProbeStrategyTTLMinutes,
		ProbeStrategyStableThreshold:    int(defaultProbeStrategyStableThreshold),
		ProbeStrategyFailureThreshold:   int(defaultProbeStrategyFailureThreshold),
		EnableSizeMap:                   true,
		SizeMapTTL:                      defaultSizeMapTTLMinutes,
		EnableRangeCompatCache:          true,
		RangeCompatTTL:                  defaultRangeCompatTTLMinutes,
		RangeCompatMinFailures:          2,
		RangeSkipMaxBytes:               defaultRangeSkipMaxBytes,
		PlayFirstFallback:               true,
		WebDAVNegativeCacheTTLMinutes:   10,
		RedirectCacheTTLMinutes:         1440,
		EnableParallelDecrypt:           true,
		ParallelDecryptConcurrency:      8,
		StreamBufferKB:                  1024,
		StreamEngineVersion:             defaultStreamEngineVersion,
		DebugEnabled:                    false,
		DebugLevel:                      "info",
		DebugMaskSensitive:              true,
		DebugSampleRate:                 100,
		DebugLogBodyBytes:               0,
		LocalSizeRetentionDays:          defaultLocalSizeRetentionDays,
		LocalStrategyRetentionDays:      defaultLocalStrategyRetentionDays,
		EnableDBExportSync:              false,
		DBExportBaseURL:                 "",
		DBExportSyncIntervalSeconds:     defaultDBExportSyncIntervalSecs,
		DBExportAuthEnabled:             false,
		DBExportUsername:                "admin",
		DBExportPassword:                "",
		EncryptPaths: []*EncryptPath{
			{
				Path:     "encrypt_folder/*",
				Password: "123456",
				EncType:  EncTypeAESCTR,
				EncName:  false,
				Enable:   true,
			},
			{
				Path:     "movie_encrypt/*",
				Password: "123456",
				EncType:  EncTypeAESCTR,
				EncName:  false,
				Enable:   true,
			},
		},
		AdminPassword: "123456",
	}
}

// NewConfigManager 创建配置管理器
func NewConfigManager(configPath string) *ConfigManager {
	return &ConfigManager{
		configPath: configPath,
		config:     DefaultConfig(),
	}
}

// Load 加载配置
func (m *ConfigManager) Load() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// 检查配置文件是否存在
	if _, err := os.Stat(m.configPath); os.IsNotExist(err) {
		// 创建默认配置
		return m.saveConfigLocked()
	}

	// 读取配置文件
	data, err := os.ReadFile(m.configPath)
	if err != nil {
		log.Errorf("[%s] Failed to read config file: %v", internal.TagConfig, err)
		return err
	}

	// 解析配置
	var config ProxyConfig
	if err := json.Unmarshal(data, &config); err != nil {
		log.Errorf("[%s] Failed to parse config: %v", internal.TagConfig, err)
		return err
	}

	// 旧配置兼容：ProbeOnDownload 对加密文件解密至关重要，确保默认开启
	// JSON 中 bool 缺失会被解析为 false，通过检查多个新增字段是否全为零值来判断旧配置
	if !config.ProbeOnDownload && config.ProbeStrategy == "" && config.SizeMapTTL == 0 {
		config.ProbeOnDownload = true
	}
	rawUpstreamTimeout := config.UpstreamTimeoutSeconds
	rawProbeTimeout := config.ProbeTimeoutSeconds
	rawProbeBudget := config.ProbeBudgetSeconds
	rawBackoff := config.UpstreamBackoffSeconds
	rawEnableParallelDecrypt := config.EnableParallelDecrypt
	rawParallelDecryptConcurrency := config.ParallelDecryptConcurrency
	rawStreamBufferKB := config.StreamBufferKB
	rawEnableRangeCompatCache := config.EnableRangeCompatCache
	rawRangeCompatTTL := config.RangeCompatTTL
	rawRangeCompatMinFailures := config.RangeCompatMinFailures
	rawRangeSkipMaxBytes := config.RangeSkipMaxBytes
	if config.UpstreamTimeoutSeconds <= 0 {
		config.UpstreamTimeoutSeconds = 15
	}
	if config.ProbeTimeoutSeconds <= 0 {
		config.ProbeTimeoutSeconds = 5
	}
	if config.ProbeBudgetSeconds <= 0 {
		config.ProbeBudgetSeconds = 10
	}
	if config.UpstreamBackoffSeconds <= 0 {
		config.UpstreamBackoffSeconds = 20
	}
	if !config.EnableLocalBypass &&
		rawUpstreamTimeout == 0 &&
		rawProbeTimeout == 0 &&
		rawProbeBudget == 0 &&
		rawBackoff == 0 {
		config.EnableLocalBypass = true
	}
	config.RoutingMode = normalizeRoutingMode(config.RoutingMode)
	if strings.TrimSpace(config.ProviderRuleSource) == "" {
		config.ProviderRuleSource = "builtin+custom"
	}
	config.RoutingUnmatchedDefault = normalizeRoutingUnmatchedDefault(config.RoutingUnmatchedDefault)
	if !config.ProviderCatalogEnabled && config.ProviderCatalogTTLMinutes == 0 && config.StorageMapRefreshMinutes == 0 {
		config.ProviderCatalogEnabled = true
	}
	if config.ProviderCatalogTTLMinutes <= 0 {
		config.ProviderCatalogTTLMinutes = 720
	}
	if !config.ProviderCatalogBootstrapOnStart && config.ProviderCatalogTTLMinutes == 720 {
		config.ProviderCatalogBootstrapOnStart = true
	}
	if config.StorageMapRefreshMinutes <= 0 {
		config.StorageMapRefreshMinutes = 30
	}
	for i := range config.ProviderRoutingRules {
		config.ProviderRoutingRules[i].MatchType = normalizeRoutingMatchType(config.ProviderRoutingRules[i].MatchType)
		config.ProviderRoutingRules[i].Action = normalizeRoutingAction(config.ProviderRoutingRules[i].Action)
		config.ProviderRoutingRules[i].MatchValues = normalizeRoutingMatchValues(&config.ProviderRoutingRules[i])
	}
	if config.DBExportSyncIntervalSeconds <= 0 {
		config.DBExportSyncIntervalSeconds = defaultDBExportSyncIntervalSecs
	}
	if config.ProbeStrategyTTLMinutes <= 0 {
		config.ProbeStrategyTTLMinutes = defaultProbeStrategyTTLMinutes
	}
	if config.ProbeStrategyStableThreshold <= 0 {
		config.ProbeStrategyStableThreshold = int(defaultProbeStrategyStableThreshold)
	}
	if config.ProbeStrategyFailureThreshold <= 0 {
		config.ProbeStrategyFailureThreshold = int(defaultProbeStrategyFailureThreshold)
	}
	if config.SizeMapTTL <= 0 {
		config.SizeMapTTL = defaultSizeMapTTLMinutes
	}
	if config.RangeCompatTTL <= 0 {
		config.RangeCompatTTL = defaultRangeCompatTTLMinutes
	}
	if config.RangeCompatMinFailures <= 0 {
		config.RangeCompatMinFailures = 2
	}
	if config.RangeSkipMaxBytes <= 0 {
		config.RangeSkipMaxBytes = defaultRangeSkipMaxBytes
	}
	if config.ParallelDecryptConcurrency <= 0 {
		config.ParallelDecryptConcurrency = 8
	}
	if config.StreamBufferKB <= 0 {
		config.StreamBufferKB = 1024
	}
	if config.StreamEngineVersion <= 0 {
		config.StreamEngineVersion = defaultStreamEngineVersion
	}
	if !config.EnableParallelDecrypt && !rawEnableParallelDecrypt &&
		rawParallelDecryptConcurrency == 0 && rawStreamBufferKB == 0 {
		config.EnableParallelDecrypt = true
	}
	if !config.EnableRangeCompatCache && !rawEnableRangeCompatCache &&
		rawRangeCompatTTL == 0 && rawRangeCompatMinFailures == 0 && rawRangeSkipMaxBytes == 0 {
		config.EnableRangeCompatCache = true
	}
	// 旧配置兼容：未配置时启用播放优先兜底
	if !config.PlayFirstFallback && config.WebDAVNegativeCacheTTLMinutes == 0 {
		config.PlayFirstFallback = true
	}
	if config.WebDAVNegativeCacheTTLMinutes <= 0 {
		config.WebDAVNegativeCacheTTLMinutes = 10
	}
	if config.RedirectCacheTTLMinutes <= 0 {
		config.RedirectCacheTTLMinutes = 1440
	}
	if config.DebugLevel == "" {
		config.DebugLevel = "info"
	}
	if config.DebugSampleRate <= 0 || config.DebugSampleRate > 100 {
		config.DebugSampleRate = 100
	}
	if config.LocalSizeRetentionDays <= 0 {
		config.LocalSizeRetentionDays = defaultLocalSizeRetentionDays
	}
	if config.LocalStrategyRetentionDays <= 0 {
		config.LocalStrategyRetentionDays = defaultLocalStrategyRetentionDays
	}
	if !config.DebugMaskSensitive && !config.DebugEnabled && config.DebugLogBodyBytes == 0 {
		config.DebugMaskSensitive = true
	}

	m.config = &config
	log.Info("[" + internal.TagConfig + "] Config loaded successfully")
	return nil
}

// Save 保存配置
func (m *ConfigManager) Save() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return m.saveConfigLocked()
}

// saveConfigLocked 保存配置（内部方法，需要持有锁）
func (m *ConfigManager) saveConfigLocked() error {
	// 确保目录存在
	dir := filepath.Dir(m.configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// 序列化配置
	data, err := json.MarshalIndent(m.config, "", "  ")
	if err != nil {
		return err
	}

	// 写入文件
	if err := os.WriteFile(m.configPath, data, 0644); err != nil {
		return err
	}

	log.Info("[" + internal.TagConfig + "] Config saved successfully")
	return nil
}

// GetConfig 获取配置副本
func (m *ConfigManager) GetConfig() *ProxyConfig {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// 返回配置副本
	configCopy := *m.config
	pathsCopy := make([]*EncryptPath, len(m.config.EncryptPaths))
	for i, p := range m.config.EncryptPaths {
		pathCopy := *p
		pathsCopy[i] = &pathCopy
	}
	configCopy.EncryptPaths = pathsCopy
	if len(m.config.ProviderRoutingRules) > 0 {
		rulesCopy := make([]ProviderRoutingRule, len(m.config.ProviderRoutingRules))
		copy(rulesCopy, m.config.ProviderRoutingRules)
		configCopy.ProviderRoutingRules = rulesCopy
	}
	configCopy.ConfigPath = m.configPath

	return &configCopy
}

// SetAlistHost 设置 Alist 主机
func (m *ConfigManager) SetAlistHost(host string, port int, https bool) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.config.AlistHost = host
	m.config.AlistPort = port
	m.config.AlistHttps = https

	return m.saveConfigLocked()
}

// SetProxyPort 设置代理端口
func (m *ConfigManager) SetProxyPort(port int) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if port < 1 || port > 65535 {
		return errors.New("invalid port number")
	}

	m.config.ProxyPort = port
	return m.saveConfigLocked()
}

// SetEnableH2C 设置 H2C 开关
func (m *ConfigManager) SetEnableH2C(enable bool) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.config.EnableH2C = enable
	return m.saveConfigLocked()
}

// SetNetworkPolicy 设置网络策略参数
func (m *ConfigManager) SetNetworkPolicy(upstreamTimeoutSeconds, probeTimeoutSeconds, probeBudgetSeconds, upstreamBackoffSeconds int, enableLocalBypass bool) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if upstreamTimeoutSeconds <= 0 {
		upstreamTimeoutSeconds = 15
	}
	if probeTimeoutSeconds <= 0 {
		probeTimeoutSeconds = 5
	}
	if probeBudgetSeconds <= 0 {
		probeBudgetSeconds = 10
	}
	if upstreamBackoffSeconds <= 0 {
		upstreamBackoffSeconds = 20
	}

	m.config.UpstreamTimeoutSeconds = upstreamTimeoutSeconds
	m.config.ProbeTimeoutSeconds = probeTimeoutSeconds
	m.config.ProbeBudgetSeconds = probeBudgetSeconds
	m.config.UpstreamBackoffSeconds = upstreamBackoffSeconds
	m.config.EnableLocalBypass = enableLocalBypass

	return m.saveConfigLocked()
}

// SetDBExportSyncConfig 设置 DB_EXPORT 同步配置
func (m *ConfigManager) SetDBExportSyncConfig(enable bool, baseURL string, intervalSeconds int, authEnabled bool, username, password string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if intervalSeconds <= 0 {
		intervalSeconds = defaultDBExportSyncIntervalSecs
	}
	if intervalSeconds < minDBExportSyncIntervalSecs {
		intervalSeconds = minDBExportSyncIntervalSecs
	}

	m.config.EnableDBExportSync = enable
	m.config.DBExportBaseURL = normalizeDBExportBaseURL(baseURL)
	m.config.DBExportSyncIntervalSeconds = intervalSeconds
	m.config.DBExportAuthEnabled = authEnabled
	m.config.DBExportUsername = strings.TrimSpace(username)
	if strings.TrimSpace(password) != "" {
		m.config.DBExportPassword = password
	}

	return m.saveConfigLocked()
}

// SetAdvancedConfigFromJSON 设置解密和缓存高级配置（JSON）
func (m *ConfigManager) SetAdvancedConfigFromJSON(configJSON string) error {
	type advancedConfigPayload struct {
		PlayFirstFallback             *bool  `json:"playFirstFallback"`
		EnableRangeCompatCache        *bool  `json:"enableRangeCompatCache"`
		RangeCompatTTLMinutes         *int   `json:"rangeCompatTtlMinutes"`
		RangeCompatMinFailures        *int   `json:"rangeCompatMinFailures"`
		RangeSkipMaxBytes             *int64 `json:"rangeSkipMaxBytes"`
		EnableParallelDecrypt         *bool  `json:"enableParallelDecrypt"`
		ParallelDecryptConcurrency    *int   `json:"parallelDecryptConcurrency"`
		StreamBufferKB                *int   `json:"streamBufferKb"`
		StreamEngineVersion           *int   `json:"streamEngineVersion"`
		WebDAVNegativeCacheTTLMinutes *int   `json:"webdavNegativeCacheTtlMinutes"`
	}
	var payload advancedConfigPayload
	if err := json.Unmarshal([]byte(configJSON), &payload); err != nil {
		return err
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	if payload.PlayFirstFallback != nil {
		m.config.PlayFirstFallback = *payload.PlayFirstFallback
	}
	if payload.EnableRangeCompatCache != nil {
		m.config.EnableRangeCompatCache = *payload.EnableRangeCompatCache
	}
	if payload.RangeCompatTTLMinutes != nil {
		if *payload.RangeCompatTTLMinutes <= 0 {
			m.config.RangeCompatTTL = defaultRangeCompatTTLMinutes
		} else {
			m.config.RangeCompatTTL = *payload.RangeCompatTTLMinutes
		}
	}
	if payload.RangeCompatMinFailures != nil {
		if *payload.RangeCompatMinFailures <= 0 {
			m.config.RangeCompatMinFailures = 2
		} else {
			m.config.RangeCompatMinFailures = *payload.RangeCompatMinFailures
		}
	}
	if payload.RangeSkipMaxBytes != nil {
		if *payload.RangeSkipMaxBytes <= 0 {
			m.config.RangeSkipMaxBytes = defaultRangeSkipMaxBytes
		} else {
			m.config.RangeSkipMaxBytes = *payload.RangeSkipMaxBytes
		}
	}
	if payload.EnableParallelDecrypt != nil {
		m.config.EnableParallelDecrypt = *payload.EnableParallelDecrypt
	}
	if payload.ParallelDecryptConcurrency != nil {
		if *payload.ParallelDecryptConcurrency <= 0 {
			m.config.ParallelDecryptConcurrency = 8
		} else {
			m.config.ParallelDecryptConcurrency = *payload.ParallelDecryptConcurrency
		}
	}
	if payload.StreamBufferKB != nil {
		if *payload.StreamBufferKB <= 0 {
			m.config.StreamBufferKB = 1024
		} else {
			m.config.StreamBufferKB = *payload.StreamBufferKB
		}
	}
	if payload.StreamEngineVersion != nil {
		if *payload.StreamEngineVersion <= 0 {
			m.config.StreamEngineVersion = defaultStreamEngineVersion
		} else {
			m.config.StreamEngineVersion = *payload.StreamEngineVersion
		}
	}
	if payload.WebDAVNegativeCacheTTLMinutes != nil {
		if *payload.WebDAVNegativeCacheTTLMinutes <= 0 {
			m.config.WebDAVNegativeCacheTTLMinutes = 10
		} else {
			m.config.WebDAVNegativeCacheTTLMinutes = *payload.WebDAVNegativeCacheTTLMinutes
		}
	}

	return m.saveConfigLocked()
}

// AddEncryptPath 添加加密路径
func (m *ConfigManager) AddEncryptPath(pathVal, password string, encType EncryptionType, encName bool, encSuffix string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	encSuffix = NormalizeEncSuffix(encSuffix)

	// 支持逗号分隔的多个路径
	paths := strings.Split(pathVal, ",")
	for _, pStr := range paths {
		rawPath := strings.TrimSpace(pStr)
		if rawPath == "" {
			continue
		}

		// 检查是否已存在
		exists := false
		for _, p := range m.config.EncryptPaths {
			if p.Path == rawPath {
				exists = true
				break
			}
		}
		if exists {
			continue
		}

		m.config.EncryptPaths = append(m.config.EncryptPaths, &EncryptPath{
			Path:      rawPath,
			Password:  password,
			EncType:   encType,
			EncName:   encName,
			EncSuffix: encSuffix,
			Enable:    true,
		})
	}

	return m.saveConfigLocked()
}

// UpdateEncryptPath 更新加密路径
func (m *ConfigManager) UpdateEncryptPath(index int, path, password string, encType EncryptionType, encName bool, encSuffix string, enable bool) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	encSuffix = NormalizeEncSuffix(encSuffix)

	if index < 0 || index >= len(m.config.EncryptPaths) {
		return errors.New("index out of range")
	}

	originalPassword := m.config.EncryptPaths[index].Password
	if strings.TrimSpace(password) == "" {
		password = originalPassword
	}

	m.config.EncryptPaths[index] = &EncryptPath{
		Path:      path,
		Password:  password,
		EncType:   encType,
		EncName:   encName,
		EncSuffix: encSuffix,
		Enable:    enable,
	}

	return m.saveConfigLocked()
}

// RemoveEncryptPath 删除加密路径
func (m *ConfigManager) RemoveEncryptPath(index int) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if index < 0 || index >= len(m.config.EncryptPaths) {
		return errors.New("index out of range")
	}

	m.config.EncryptPaths = append(
		m.config.EncryptPaths[:index],
		m.config.EncryptPaths[index+1:]...,
	)

	return m.saveConfigLocked()
}

// SetAdminPassword 设置管理密码
func (m *ConfigManager) SetAdminPassword(password string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if len(password) < 4 {
		return errors.New("password too short")
	}

	m.config.AdminPassword = password
	return m.saveConfigLocked()
}

// VerifyAdminPassword 验证管理密码
func (m *ConfigManager) VerifyAdminPassword(password string) bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	return m.config.AdminPassword == password
}

// GetEncryptPaths 获取加密路径列表（不含密码）
func (m *ConfigManager) GetEncryptPaths() []*EncryptPath {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	paths := make([]*EncryptPath, len(m.config.EncryptPaths))
	for i, p := range m.config.EncryptPaths {
		paths[i] = &EncryptPath{
			Path:    p.Path,
			EncType: p.EncType,
			EncName: p.EncName,
			Enable:  p.Enable,
		}
	}

	return paths
}
