package openlistlib

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/OpenListTeam/OpenList/v4/openlistlib/encrypt"
	"github.com/OpenListTeam/OpenList/v4/openlistlib/internal"
	log "github.com/sirupsen/logrus"
)

func init() {
	// 将日志输出到标准错误，以便在 Android logcat 中查看（通常 tag 为 GoLog）
	log.SetOutput(os.Stderr)
	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&log.TextFormatter{
		DisableColors: true,
		FullTimestamp: true,
	})
}

// EncryptProxyManager 加密代理管理器
type EncryptProxyManager struct {
	configManager *encrypt.ConfigManager
	proxyServer   *encrypt.ProxyServer
	mutex         sync.Mutex
	initialized   bool
}

var (
	encryptManager *EncryptProxyManager
	encryptOnce    sync.Once
)

// GetEncryptManager 获取加密管理器单例
func GetEncryptManager() *EncryptProxyManager {
	encryptOnce.Do(func() {
		encryptManager = &EncryptProxyManager{}
	})
	return encryptManager
}

// Initialize 初始化加密代理管理器
func (m *EncryptProxyManager) Initialize(configPath string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.initialized {
		return nil
	}

	// 创建配置管理器
	m.configManager = encrypt.NewConfigManager(configPath)
	if err := m.configManager.Load(); err != nil {
		log.Warnf("[%s] Failed to load encrypt config, using default: %v", internal.TagConfig, err)
	}

	m.initialized = true
	log.Info("[" + internal.TagServer + "] Encrypt proxy manager initialized")
	return nil
}

// StartProxy 启动加密代理服务器
func (m *EncryptProxyManager) StartProxy() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if !m.initialized {
		return errors.New("encrypt manager not initialized")
	}

	if m.proxyServer != nil && m.proxyServer.IsRunning() {
		return errors.New("proxy server is already running")
	}

	config := m.configManager.GetConfig()
	server, err := encrypt.NewProxyServer(config)
	if err != nil {
		return err
	}

	if err := server.Start(); err != nil {
		return err
	}

	m.proxyServer = server
	log.Info("[" + internal.TagServer + "] Encrypt proxy server started")
	return nil
}

// StopProxy 停止加密代理服务器
func (m *EncryptProxyManager) StopProxy() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.proxyServer == nil {
		return nil
	}

	if err := m.proxyServer.Stop(); err != nil {
		return err
	}

	m.proxyServer = nil
	log.Info("[" + internal.TagServer + "] Encrypt proxy server stopped")
	return nil
}

// IsProxyRunning 检查代理服务器是否运行中
func (m *EncryptProxyManager) IsProxyRunning() bool {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.proxyServer == nil {
		return false
	}
	return m.proxyServer.IsRunning()
}

// RestartProxy 重启代理服务器
func (m *EncryptProxyManager) RestartProxy() error {
	if err := m.StopProxy(); err != nil {
		log.Warnf("[%s] Error stopping proxy: %v", internal.TagServer, err)
	}
	return m.StartProxy()
}

// GetConfig 获取配置
func (m *EncryptProxyManager) GetConfig() *encrypt.ProxyConfig {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.configManager == nil {
		return nil
	}
	return m.configManager.GetConfig()
}

// updateProxyServerConfig 更新代理服务器配置（内部方法）
func (m *EncryptProxyManager) updateProxyServerConfig() {
	if m.proxyServer != nil && m.proxyServer.IsRunning() {
		config := m.configManager.GetConfig()
		m.proxyServer.UpdateConfig(config)
	}
}

// SetAlistHost 设置 Alist 主机
func (m *EncryptProxyManager) SetAlistHost(host string, port int, https bool) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.configManager == nil {
		return errors.New("config manager not initialized")
	}
	err := m.configManager.SetAlistHost(host, port, https)
	if err == nil {
		m.updateProxyServerConfig()
	}
	return err
}

// SetProxyPort 设置代理端口
func (m *EncryptProxyManager) SetProxyPort(port int) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.configManager == nil {
		return errors.New("config manager not initialized")
	}
	oldCfg := m.configManager.GetConfig()
	oldPort := 0
	if oldCfg != nil {
		oldPort = oldCfg.ProxyPort
	}
	err := m.configManager.SetProxyPort(port)
	if err == nil {
		// 端口修改需要重绑监听，运行中时执行安全重启
		if m.proxyServer != nil && m.proxyServer.IsRunning() && oldPort != port {
			if stopErr := m.proxyServer.Stop(); stopErr != nil {
				return stopErr
			}
			newCfg := m.configManager.GetConfig()
			server, newErr := encrypt.NewProxyServer(newCfg)
			if newErr != nil {
				return newErr
			}
			if startErr := server.Start(); startErr != nil {
				return startErr
			}
			m.proxyServer = server
			log.Infof("[%s] Encrypt proxy restarted to apply new port: %d", internal.TagServer, port)
		} else {
			m.updateProxyServerConfig()
		}
	}
	return err
}

// SetEnableH2C 设置 H2C 开关
func (m *EncryptProxyManager) SetEnableH2C(enable bool) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.configManager == nil {
		return errors.New("config manager not initialized")
	}
	err := m.configManager.SetEnableH2C(enable)
	if err == nil {
		// H2C 修改需要重启代理才能生效
		if m.proxyServer != nil && m.proxyServer.IsRunning() {
			log.Info("[" + internal.TagConfig + "] H2C setting changed, restart proxy to apply")
		}
	}
	return err
}

// SetProxyListenLocalOnly 设置代理是否仅监听本机回环（供 gomobile 调用）。
// true 时代理只监听 127.0.0.1，局域网/其他设备不能访问代理端口；
// 监听地址变化需要重绑，运行中执行安全重启。
func (m *EncryptProxyManager) SetProxyListenLocalOnly(localOnly bool) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.configManager == nil {
		return errors.New("config manager not initialized")
	}
	oldCfg := m.configManager.GetConfig()
	oldLocalOnly := false
	if oldCfg != nil {
		oldLocalOnly = oldCfg.ProxyListenLocalOnly
	}
	err := m.configManager.SetProxyListenLocalOnly(localOnly)
	if err != nil {
		return err
	}
	if oldLocalOnly == localOnly {
		// 值没变：仅同步运行时配置，无需重绑监听。
		m.updateProxyServerConfig()
		return nil
	}
	if err := m.restartProxyIfRunning(); err != nil {
		return err
	}
	log.Infof("[%s] Encrypt proxy listen mode changed: localOnly=%v", internal.TagServer, localOnly)
	return nil
}

// restartProxyIfRunning 在代理运行中时执行安全重启，用当前配置重建并
// 重新绑定监听。调用方需持有 EncryptProxyManager.mutex。
func (m *EncryptProxyManager) restartProxyIfRunning() error {
	if m.proxyServer == nil || !m.proxyServer.IsRunning() {
		return nil
	}
	if err := m.proxyServer.Stop(); err != nil {
		return fmt.Errorf("configuration saved, but stopping proxy failed: %w", err)
	}
	// Keep the requested configuration on failure. Never silently restore an
	// old wildcard listener after the user requested local-only access.
	m.proxyServer = nil
	server, err := encrypt.NewProxyServer(m.configManager.GetConfig())
	if err != nil {
		return fmt.Errorf("configuration saved, proxy stopped: %w", err)
	}
	if err := server.Start(); err != nil {
		return fmt.Errorf("configuration saved, proxy restart failed: %w", err)
	}
	m.proxyServer = server
	log.Infof("[%s] Encrypt proxy restarted", internal.TagServer)
	return nil
}

// GetProxyListenLocalOnly 获取代理是否仅监听本机回环（供 gomobile 调用）。
func (m *EncryptProxyManager) GetProxyListenLocalOnly() bool {
	if m.configManager == nil {
		return false
	}
	cfg := m.configManager.GetConfig()
	if cfg == nil {
		return false
	}
	return cfg.ProxyListenLocalOnly
}

// SetNetworkPolicy 设置网络策略
func (m *EncryptProxyManager) SetNetworkPolicy(upstreamTimeoutSeconds, probeTimeoutSeconds, probeBudgetSeconds, upstreamBackoffSeconds int, enableLocalBypass bool) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.configManager == nil {
		return errors.New("config manager not initialized")
	}
	err := m.configManager.SetNetworkPolicy(upstreamTimeoutSeconds, probeTimeoutSeconds, probeBudgetSeconds, upstreamBackoffSeconds, enableLocalBypass)
	if err == nil {
		m.updateProxyServerConfig()
	}
	return err
}

// SetDBExportSyncConfig 设置 DB_EXPORT 同步配置
func (m *EncryptProxyManager) SetDBExportSyncConfig(enable bool, baseURL string, intervalSeconds int, authEnabled bool, username, password string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.configManager == nil {
		return errors.New("config manager not initialized")
	}
	err := m.configManager.SetDBExportSyncConfig(enable, baseURL, intervalSeconds, authEnabled, username, password)
	if err == nil {
		m.updateProxyServerConfig()
	}
	return err
}

// SetAdvancedConfigJSON 设置解密和缓存配置（JSON）
func (m *EncryptProxyManager) SetAdvancedConfigJSON(configJSON string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.configManager == nil {
		return errors.New("config manager not initialized")
	}
	oldCfg := m.configManager.GetConfig()
	oldLocalOnly := false
	if oldCfg != nil {
		oldLocalOnly = oldCfg.ProxyListenLocalOnly
	}
	err := m.configManager.SetAdvancedConfigFromJSON(configJSON)
	if err == nil {
		newCfg := m.configManager.GetConfig()
		newLocalOnly := false
		if newCfg != nil {
			newLocalOnly = newCfg.ProxyListenLocalOnly
		}
		if oldLocalOnly != newLocalOnly {
			// 监听模式变化需要重绑监听。
			return m.restartProxyIfRunning()
		}
		m.updateProxyServerConfig()
	}
	return err
}

// AddEncryptPath 添加加密路径
func (m *EncryptProxyManager) AddEncryptPath(path, password string, encType string, encName bool, encSuffix string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.configManager == nil {
		return errors.New("config manager not initialized")
	}
	err := m.configManager.AddEncryptPath(path, password, encrypt.EncryptionType(encType), encName, encSuffix)
	if err == nil {
		m.updateProxyServerConfig()
	}
	return err
}

// UpdateEncryptPath 更新加密路径
func (m *EncryptProxyManager) UpdateEncryptPath(index int, path, password string, encType string, encName bool, encSuffix string, enable bool) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.configManager == nil {
		return errors.New("config manager not initialized")
	}
	err := m.configManager.UpdateEncryptPath(index, path, password, encrypt.EncryptionType(encType), encName, encSuffix, enable)
	if err == nil {
		m.updateProxyServerConfig()
	}
	return err
}

// RemoveEncryptPath 删除加密路径
func (m *EncryptProxyManager) RemoveEncryptPath(index int) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.configManager == nil {
		return errors.New("config manager not initialized")
	}
	err := m.configManager.RemoveEncryptPath(index)
	if err == nil {
		m.updateProxyServerConfig()
	}
	return err
}

// GetEncryptPaths 获取加密路径列表
func (m *EncryptProxyManager) GetEncryptPaths() []*encrypt.EncryptPath {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.configManager == nil {
		return nil
	}
	return m.configManager.GetEncryptPaths()
}

// VerifyAdminPassword 验证管理密码
func (m *EncryptProxyManager) VerifyAdminPassword(password string) bool {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.configManager == nil {
		return false
	}
	return m.configManager.VerifyAdminPassword(password)
}

// SetStatsPassword 设置统计导出访问密码（独立于管理密码）。
func (m *EncryptProxyManager) SetStatsPassword(password string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if m.configManager == nil {
		return errors.New("config manager not initialized")
	}
	return m.configManager.SetStatsPassword(password)
}

// SetAdminPassword 设置管理密码
func (m *EncryptProxyManager) SetAdminPassword(password string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.configManager == nil {
		return errors.New("config manager not initialized")
	}
	err := m.configManager.SetAdminPassword(password)
	if err == nil {
		m.updateProxyServerConfig()
	}
	return err
}

// === 以下是为 gomobile 导出的函数 ===

// InitEncryptProxy 初始化加密代理（供 gomobile 调用）
func InitEncryptProxy(configPath string) error {
	return GetEncryptManager().Initialize(configPath)
}

// StartEncryptProxy 启动加密代理（供 gomobile 调用）
func StartEncryptProxy() error {
	return GetEncryptManager().StartProxy()
}

// StopEncryptProxy 停止加密代理（供 gomobile 调用）
func StopEncryptProxy() error {
	return GetEncryptManager().StopProxy()
}

// IsEncryptProxyRunning 检查加密代理是否运行中（供 gomobile 调用）
func IsEncryptProxyRunning() bool {
	return GetEncryptManager().IsProxyRunning()
}

// RestartEncryptProxy 重启加密代理（供 gomobile 调用）
func RestartEncryptProxy() error {
	return GetEncryptManager().RestartProxy()
}

// GetEncryptProxyPort 获取代理端口（供 gomobile 调用）
func GetEncryptProxyPort() int64 {
	config := GetEncryptManager().GetConfig()
	if config == nil {
		return 5344
	}
	return int64(config.ProxyPort)
}

// SetEncryptAlistHost 设置 Alist 主机（供 gomobile 调用）
func SetEncryptAlistHost(host string, port int64, https bool) error {
	return GetEncryptManager().SetAlistHost(host, int(port), https)
}

// SetEncryptProxyPort 设置代理端口（供 gomobile 调用）
func SetEncryptProxyPort(port int64) error {
	return GetEncryptManager().SetProxyPort(int(port))
}

// SetEncryptEnableH2C 设置 H2C 开关（供 gomobile 调用）
func SetEncryptEnableH2C(enable bool) error {
	return GetEncryptManager().SetEnableH2C(enable)
}

// SetEncryptDbExportSyncConfig 设置 DB_EXPORT 同步配置（供 gomobile 调用）
func SetEncryptDbExportSyncConfig(enable bool, baseURL string, intervalSeconds int64, authEnabled bool, username, password string) error {
	return GetEncryptManager().SetDBExportSyncConfig(enable, baseURL, int(intervalSeconds), authEnabled, username, password)
}

// SetEncryptNetworkPolicy 设置网络策略（供 gomobile 调用）
func SetEncryptNetworkPolicy(upstreamTimeoutSeconds, probeTimeoutSeconds, probeBudgetSeconds, upstreamBackoffSeconds int64, enableLocalBypass bool) error {
	return GetEncryptManager().SetNetworkPolicy(int(upstreamTimeoutSeconds), int(probeTimeoutSeconds), int(probeBudgetSeconds), int(upstreamBackoffSeconds), enableLocalBypass)
}

// SetEncryptDualNetworkMarks 设置双网络(WiFi+蜂窝)的 fwmark 与开关（供 gomobile 调用）。
// wifiFwmark/cellFwmark 为 0 表示"该网络不可绑定"；enabled=false 时完全不改默认拨号路径。
func SetEncryptDualNetworkMarks(wifiFwmark, cellFwmark int64, enabled bool) {
	encrypt.SetEncryptDualNetworkMarks(wifiFwmark, cellFwmark, enabled)
}

// GetEncryptDualNetworkStatusJson 返回双网络状态 JSON（供 gomobile 调用，可选延迟面板用）。
func GetEncryptDualNetworkStatusJson() string {
	return encrypt.GetEncryptDualNetworkStatusJson()
}

// SetEncryptAdvancedConfigJson 设置解密和缓存配置（供 gomobile 调用）
func SetEncryptAdvancedConfigJson(configJSON string) error {
	return GetEncryptManager().SetAdvancedConfigJSON(configJSON)
}

// GetEncryptEnableH2C 获取 H2C 开关状态（供 gomobile 调用）
func GetEncryptEnableH2C() bool {
	config := GetEncryptManager().GetConfig()
	if config == nil {
		return false
	}
	return config.EnableH2C
}

// SetEncryptListenLocalOnly 设置代理是否仅监听本机回环（供 gomobile 调用）。
func SetEncryptListenLocalOnly(localOnly bool) error {
	return GetEncryptManager().SetProxyListenLocalOnly(localOnly)
}

// GetEncryptListenLocalOnly 获取代理是否仅监听本机回环（供 gomobile 调用）。
func GetEncryptListenLocalOnly() bool {
	return GetEncryptManager().GetProxyListenLocalOnly()
}

// AddEncryptPathConfig 添加加密路径配置（供 gomobile 调用）
func AddEncryptPathConfig(path, password, encType string, encName bool, encSuffix string) error {
	return GetEncryptManager().AddEncryptPath(path, password, encType, encName, encSuffix)
}

// RemoveEncryptPathConfig 删除加密路径配置（供 gomobile 调用）
func RemoveEncryptPathConfig(index int64) error {
	return GetEncryptManager().RemoveEncryptPath(int(index))
}

// VerifyEncryptAdminPassword 验证管理密码（供 gomobile 调用）
func VerifyEncryptAdminPassword(password string) bool {
	return GetEncryptManager().VerifyAdminPassword(password)
}

// SetEncryptAdminPassword 设置管理密码（供 gomobile 调用）
func SetEncryptAdminPassword(password string) error {
	return GetEncryptManager().SetAdminPassword(password)
}

// SetEncryptStatsPassword 设置统计导出访问密码（供 gomobile 调用，独立于管理密码）。
func SetEncryptStatsPassword(password string) error {
	return GetEncryptManager().SetStatsPassword(password)
}

// ExportEncryptStatsJson 导出播放/删除统计 JSON（供 gomobile 调用）。
// 需要 password 与配置的 StatsPassword 一致才返回数据，否则返回错误 JSON。
func ExportEncryptStatsJson(password string) string {
	manager := GetEncryptManager()
	config := manager.GetConfig()
	if config == nil || config.StatsPassword == "" {
		return `{"error":"stats disabled"}`
	}
	if password != config.StatsPassword {
		return `{"error":"invalid stats password"}`
	}
	server := manager.proxyServer
	if server == nil {
		return `{"error":"proxy not running"}`
	}
	server.FlushPlaybackSessions()
	plays, err := server.ListPlaybackStats(0)
	if err != nil {
		return `{"error":"` + strings.ReplaceAll(err.Error(), `"`, `'`) + `"}`
	}
	dels, err := server.ListDeletionStats(0)
	if err != nil {
		return `{"error":"` + strings.ReplaceAll(err.Error(), `"`, `'`) + `"}`
	}
	payload := map[string]interface{}{
		"playbacks":   plays,
		"deletions":   dels,
		"probe_stats": server.ProbeStatsSnapshot(),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return `{"error":"marshal failed"}`
	}
	return string(data)
}

// GetEncryptPathsJson 获取加密路径列表 JSON（供 gomobile 调用）
func GetEncryptPathsJson() string {
	paths := GetEncryptManager().GetEncryptPaths()
	if paths == nil {
		return "[]"
	}

	type PathInfo struct {
		Path      string `json:"path"`
		EncType   string `json:"encType"`
		EncName   bool   `json:"encName"`
		EncSuffix string `json:"encSuffix,omitempty"`
		Enable    bool   `json:"enable"`
	}

	infos := make([]PathInfo, len(paths))
	for i, p := range paths {
		infos[i] = PathInfo{
			Path:      p.Path,
			EncType:   string(p.EncType),
			EncName:   p.EncName,
			EncSuffix: p.EncSuffix,
			Enable:    p.Enable,
		}
	}

	data, err := json.Marshal(infos)
	if err != nil {
		return "[]"
	}
	return string(data)
}

// GetEncryptConfigJson 获取完整配置 JSON（供 gomobile 调用）
func GetEncryptConfigJson() string {
	config := GetEncryptManager().GetConfig()
	if config == nil {
		return "{}"
	}

	type PathInfo struct {
		Path      string `json:"path"`
		EncType   string `json:"encType"`
		EncName   bool   `json:"encName"`
		EncSuffix string `json:"encSuffix,omitempty"`
		Enable    bool   `json:"enable"`
	}

	type ConfigInfo struct {
		AlistHost                string     `json:"alistHost"`
		AlistPort                int        `json:"alistPort"`
		AlistHttps               bool       `json:"alistHttps"`
		ProxyPort                int        `json:"proxyPort"`
		UpstreamTimeoutSeconds   int        `json:"upstreamTimeoutSeconds"`
		ProbeTimeoutSeconds      int        `json:"probeTimeoutSeconds"`
		ProbeBudgetSeconds       int        `json:"probeBudgetSeconds"`
		UpstreamBackoffSeconds   int        `json:"upstreamBackoffSeconds"`
		EnableLocalBypass        bool       `json:"enableLocalBypass"`
		EnableH2C                bool       `json:"enableH2C"`
		ProxyListenLocalOnly     bool       `json:"proxyListenLocalOnly"`
		EnableDbExportSync       bool       `json:"enableDbExportSync"`
		DbExportBaseUrl          string     `json:"dbExportBaseUrl"`
		DbExportSyncIntervalSecs int        `json:"dbExportSyncIntervalSeconds"`
		DbExportAuthEnabled      bool       `json:"dbExportAuthEnabled"`
		DbExportUsername         string     `json:"dbExportUsername"`
		DbExportPassword         string     `json:"dbExportPassword"`
		DbExportPasswordSet      bool       `json:"dbExportPasswordSet"`
		PlayFirstFallback        bool       `json:"playFirstFallback"`
		EnableRangeCompatCache   bool       `json:"enableRangeCompatCache"`
		RangeCompatTtlMinutes    int        `json:"rangeCompatTtlMinutes"`
		RangeCompatMinFailures   int        `json:"rangeCompatMinFailures"`
		RangeSkipMaxBytes        int64      `json:"rangeSkipMaxBytes"`
		EnableParallelDecrypt    bool       `json:"enableParallelDecrypt"`
		ParallelDecryptConc      int        `json:"parallelDecryptConcurrency"`
		StreamBufferKb           int        `json:"streamBufferKb"`
		WebDAVNegativeCacheTtl   int        `json:"webdavNegativeCacheTtlMinutes"`
		EncryptPaths             []PathInfo `json:"encryptPaths"`
	}

	paths := make([]PathInfo, len(config.EncryptPaths))
	for i, p := range config.EncryptPaths {
		paths[i] = PathInfo{
			Path:      p.Path,
			EncType:   string(p.EncType),
			EncName:   p.EncName,
			EncSuffix: p.EncSuffix,
			Enable:    p.Enable,
		}
	}

	info := ConfigInfo{
		AlistHost:                config.AlistHost,
		AlistPort:                config.AlistPort,
		AlistHttps:               config.AlistHttps,
		ProxyPort:                config.ProxyPort,
		UpstreamTimeoutSeconds:   config.UpstreamTimeoutSeconds,
		ProbeTimeoutSeconds:      config.ProbeTimeoutSeconds,
		ProbeBudgetSeconds:       config.ProbeBudgetSeconds,
		UpstreamBackoffSeconds:   config.UpstreamBackoffSeconds,
		EnableLocalBypass:        config.EnableLocalBypass,
		EnableH2C:                config.EnableH2C,
		ProxyListenLocalOnly:     config.ProxyListenLocalOnly,
		EnableDbExportSync:       config.EnableDBExportSync,
		DbExportBaseUrl:          config.DBExportBaseURL,
		DbExportSyncIntervalSecs: config.DBExportSyncIntervalSeconds,
		DbExportAuthEnabled:      config.DBExportAuthEnabled,
		DbExportUsername:         config.DBExportUsername,
		DbExportPassword:         "",
		DbExportPasswordSet:      strings.TrimSpace(config.DBExportPassword) != "",
		PlayFirstFallback:        config.PlayFirstFallback,
		EnableRangeCompatCache:   config.EnableRangeCompatCache,
		RangeCompatTtlMinutes:    config.RangeCompatTTL,
		RangeCompatMinFailures:   config.RangeCompatMinFailures,
		RangeSkipMaxBytes:        config.RangeSkipMaxBytes,
		EnableParallelDecrypt:    config.EnableParallelDecrypt,
		ParallelDecryptConc:      config.ParallelDecryptConcurrency,
		StreamBufferKb:           config.StreamBufferKB,
		WebDAVNegativeCacheTtl:   config.WebDAVNegativeCacheTTLMinutes,
		EncryptPaths:             paths,
	}

	data, err := json.Marshal(info)
	if err != nil {
		return "{}"
	}
	return string(data)
}

// UpdateEncryptPathConfig 更新加密路径配置（供 gomobile 调用）
func UpdateEncryptPathConfig(index int64, path, password, encType string, encName bool, encSuffix string, enable bool) error {
	return GetEncryptManager().UpdateEncryptPath(int(index), path, password, encType, encName, encSuffix, enable)
}
