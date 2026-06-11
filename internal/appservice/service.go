package appservice

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/alist-encrypt-go/internal/auth"
	"github.com/alist-encrypt-go/internal/buildinfo"
	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/encryption"
	"github.com/alist-encrypt-go/internal/proxy"
	"github.com/alist-encrypt-go/internal/proxydict"
	"github.com/alist-encrypt-go/internal/storage/mysqlstore"
)

type FileStatsProvider interface {
	PathCacheStats() map[string]interface{}
	FileSizeCacheStats() map[string]interface{}
}

type StatsProvider interface {
	Stats() map[string]interface{}
}

type RangeCompatStatsProvider interface {
	RangeCompatStats() map[string]interface{}
}

type Service struct {
	cfg         *config.Config
	jwtAuth     *auth.JWTAuth
	userDAO     *dao.UserDAO
	passwdDAO   *dao.PasswdDAO
	mysqlStore  *mysqlstore.Store
	dictMgr     *proxydict.Manager
	fileStats   FileStatsProvider
	proxyStats  StatsProvider
	webdavStats StatsProvider
	rangeStats  RangeCompatStatsProvider
	startTime   time.Time
}

type Deps struct {
	Cfg         *config.Config
	UserDAO     *dao.UserDAO
	PasswdDAO   *dao.PasswdDAO
	MySQLStore  *mysqlstore.Store
	DictMgr     *proxydict.Manager
	FileStats   FileStatsProvider
	ProxyStats  StatsProvider
	WebDAVStats StatsProvider
	RangeStats  RangeCompatStatsProvider
	StartTime   time.Time
}

func New(deps Deps) *Service {
	cfg := deps.Cfg
	if cfg == nil {
		cfg = config.DefaultConfig()
	}
	expireHours := cfg.JWTExpire
	if expireHours <= 0 {
		expireHours = 48
	}
	return &Service{
		cfg:         cfg,
		jwtAuth:     auth.NewJWTAuth(cfg.JWTSecret, time.Duration(expireHours)*time.Hour),
		userDAO:     deps.UserDAO,
		passwdDAO:   deps.PasswdDAO,
		mysqlStore:  deps.MySQLStore,
		dictMgr:     deps.DictMgr,
		fileStats:   deps.FileStats,
		proxyStats:  deps.ProxyStats,
		webdavStats: deps.WebDAVStats,
		rangeStats:  deps.RangeStats,
		startTime:   deps.StartTime,
	}
}

func (s *Service) BuildInfo() map[string]interface{} {
	return map[string]interface{}{
		"version":          config.Version,
		"embedded_web_ui":  buildinfo.EmbeddedWebUI(),
		"management_mode":  buildinfo.ManagementMode(),
		"default_head_img": DefaultHeadImageURL(),
	}
}

func DefaultHeadImageURL() string {
	return "/public/logo.png"
}

func (s *Service) Login(username, password string) (map[string]interface{}, string, error) {
	if s.userDAO == nil {
		return nil, "", fmt.Errorf("user dao not initialized")
	}
	if err := s.userDAO.Validate(username, password); err != nil {
		return nil, "", err
	}
	token, err := s.jwtAuth.GenerateToken(username)
	if err != nil {
		return nil, "", err
	}
	return map[string]interface{}{
		"username":   username,
		"headImgUrl": DefaultHeadImageURL(),
	}, token, nil
}

func (s *Service) UserInfo() (map[string]interface{}, error) {
	username := "admin"
	if s.userDAO != nil {
		if user, err := s.userDAO.GetFirstUser(); err == nil && user != nil {
			username = user.Username
		}
	}
	return map[string]interface{}{
		"codes": []int{16, 9, 10, 11, 12, 13, 15},
		"userInfo": map[string]interface{}{
			"username":   username,
			"headImgUrl": DefaultHeadImageURL(),
		},
		"menuList": []interface{}{},
		"roles":    []string{"admin"},
		"version":  config.Version,
	}, nil
}

func (s *Service) UpdatePassword(username, password, newPassword string) error {
	if s.userDAO == nil {
		return fmt.Errorf("user dao not initialized")
	}
	if len(newPassword) < 7 {
		return fmt.Errorf("password too short, at less 8 digits")
	}
	if err := s.userDAO.Validate(username, password); err != nil {
		return fmt.Errorf("password error")
	}
	return s.userDAO.UpdatePassword(username, newPassword)
}

func (s *Service) UpdateUsername(username, password, newUsername string) error {
	if s.userDAO == nil {
		return fmt.Errorf("user dao not initialized")
	}
	if len(newUsername) < 3 {
		return fmt.Errorf("username too short, at least 3 characters")
	}
	if err := s.userDAO.Rename(username, password, newUsername); err != nil {
		if errors.Is(err, dao.ErrInvalidPassword) || errors.Is(err, dao.ErrUserNotFound) {
			return fmt.Errorf("password error")
		}
		return err
	}
	return nil
}

func (s *Service) GetAlistConfig() interface{} {
	return s.cfg.AlistServer
}

func (s *Service) SaveAlistConfig(raw map[string]interface{}) error {
	if _, hasLegacy := raw["rangeCompatTtlMinutes"]; hasLegacy {
		return fmt.Errorf("rangeCompatTtlMinutes is deprecated, use rangeReprobeMinutes")
	}
	server := config.ParseAlistServerFromMap(raw)
	return s.cfg.UpdateAlistServer(server)
}

func (s *Service) ValidateScanConfig(raw map[string]interface{}, ctx context.Context) (map[string]interface{}, error) {
	server := config.ParseAlistServerFromMap(raw)
	authHeader, authMode := buildScanValidationAuth(server)
	targetURL := buildAlistURLForServer(server) + "/dav/"
	if authHeader == "" {
		return map[string]interface{}{
			"ok":         false,
			"auth_mode":  "none",
			"target_url": targetURL,
			"message":    "未配置扫描账号，请填写 scanUsername/scanPassword 或 scanAuthHeader",
		}, nil
	}
	req, err := http.NewRequestWithContext(ctx, "PROPFIND", targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Depth", "0")
	req.Header.Set("Authorization", authHeader)
	tempCfg := &config.Config{
		AlistServer: server,
		Proxy:       s.cfg.Proxy,
	}
	client := proxy.NewHTTPClient(tempCfg, getAlistRequestTimeout(tempCfg))
	resp, err := client.Do(req)
	if err != nil {
		return map[string]interface{}{
			"ok":         false,
			"auth_mode":  authMode,
			"target_url": targetURL,
			"message":    "请求失败: " + err.Error(),
		}, nil
	}
	defer resp.Body.Close()
	bodyPreview, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	statusCode := resp.StatusCode
	ok := statusCode == http.StatusOK || statusCode == http.StatusNoContent || statusCode == http.StatusMultiStatus
	message := "连接成功"
	switch statusCode {
	case http.StatusUnauthorized:
		message = "认证失败，账号或授权头无效"
	case http.StatusForbidden:
		message = "认证通过但权限不足"
	case http.StatusNotFound:
		message = "后端未暴露 /dav 路由或路径不可用"
	case http.StatusMethodNotAllowed:
		message = "后端不支持 PROPFIND，请检查 WebDAV 是否开启"
	case http.StatusMultiStatus:
		message = "连接成功，WebDAV PROPFIND 可用"
	}
	return map[string]interface{}{
		"ok":            ok,
		"auth_mode":     authMode,
		"target_url":    targetURL,
		"status_code":   statusCode,
		"message":       message,
		"response_hint": strings.TrimSpace(string(bodyPreview)),
	}, nil
}

func (s *Service) GetWebdavConfig() interface{} {
	return s.cfg.WebDAVServer
}

func (s *Service) SaveWebdavConfig(raw map[string]interface{}) error {
	server := config.ParseWebDAVServerFromMap(raw)
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return err
	}
	server.ID = hex.EncodeToString(id)
	return s.cfg.AddWebDAVServer(server)
}

func (s *Service) UpdateWebdavConfig(raw map[string]interface{}) error {
	server := config.ParseWebDAVServerFromMap(raw)
	return s.cfg.UpdateWebDAVServer(server)
}

func (s *Service) DeleteWebdavConfig(id string) error {
	return s.cfg.DeleteWebDAVServer(id)
}

func (s *Service) EncodeFolderName(password, encType, folderPasswd, folderEncType string) map[string]interface{} {
	return map[string]interface{}{
		"folderNameEnc": encryption.EncodeFolderName(password, encType, folderPasswd, folderEncType),
	}
}

func (s *Service) DecodeFolderName(password, encType, folderNameEnc string) (map[string]interface{}, error) {
	folderEncType, folderPasswd, ok := encryption.DecodeFolderName(password, encType, folderNameEnc)
	if !ok {
		return nil, fmt.Errorf("folderName is error")
	}
	return map[string]interface{}{
		"folderEncType": folderEncType,
		"folderPasswd":  folderPasswd,
	}, nil
}

func (s *Service) GetSchemeConfig() interface{} {
	return s.cfg.Scheme
}

func (s *Service) SaveSchemeConfig(scheme config.SchemeConfig) (bool, error) {
	return s.cfg.UpdateScheme(scheme)
}

func (s *Service) ExportFileMeta(ctx context.Context, filter mysqlstore.FileMetaFilter) ([]mysqlstore.FileMetaRecord, error) {
	if s.mysqlStore == nil {
		return nil, fmt.Errorf("mysql not enabled")
	}
	return s.mysqlStore.ListFileMeta(ctx, filter)
}

func (s *Service) ExportStrategies(ctx context.Context) ([]mysqlstore.StrategyRecord, error) {
	if s.mysqlStore == nil {
		return nil, fmt.Errorf("mysql not enabled")
	}
	return s.mysqlStore.ListStrategies(ctx)
}

func (s *Service) ExportRangeCompats(ctx context.Context) ([]mysqlstore.RangeCompatRecord, error) {
	if s.mysqlStore == nil {
		return nil, fmt.Errorf("mysql not enabled")
	}
	return s.mysqlStore.ListRangeCompats(ctx)
}

func (s *Service) CleanupLegacyBoltDB() (string, error) {
	if s.mysqlStore == nil {
		return "", fmt.Errorf("MySQL 未连接，请先配置 MySQL 后再试")
	}
	dbPath := "data/alist-encrypt.db"
	if s.cfg != nil && s.cfg.DataDir != "" {
		dbPath = filepath.Join(s.cfg.DataDir, "alist-encrypt.db")
	}
	info, err := os.Stat(dbPath)
	if os.IsNotExist(err) {
		return "没有旧数据需要清理", nil
	}
	if err != nil {
		return "", err
	}
	sizeKB := info.Size() / 1024
	if err := os.Remove(dbPath); err != nil {
		return "", err
	}
	return fmt.Sprintf("已清理旧数据（%d KB），清理后无法找回", sizeKB), nil
}

func (s *Service) GetProxyDomainDictionary() (interface{}, error) {
	if s.dictMgr == nil {
		return nil, fmt.Errorf("proxy dictionary not initialized")
	}
	return s.dictMgr.LoadOrRefresh()
}

func (s *Service) RefreshProxyDomainDictionary() (interface{}, error) {
	if s.dictMgr == nil {
		return nil, fmt.Errorf("proxy dictionary not initialized")
	}
	return s.dictMgr.Refresh()
}

func (s *Service) GetProxyRoutingConfig() interface{} {
	return s.cfg.Proxy
}

func (s *Service) SaveProxyRoutingConfig(proxyCfg config.ProxyConfig) error {
	if proxyCfg.Mode == "rules" && len(proxyCfg.Rules) == 0 && len(proxyCfg.SelectedProviderIDs) > 0 {
		s.buildRulesFromSelection(&proxyCfg)
	}
	return s.cfg.UpdateProxy(proxyCfg)
}

func (s *Service) GetStats() map[string]interface{} {
	proxyStats := map[string]interface{}{}
	webdavStats := map[string]interface{}{}
	rangeStats := map[string]interface{}{}
	pathStats := map[string]interface{}{}
	fileSizeStats := map[string]interface{}{}
	if s.proxyStats != nil {
		proxyStats = s.proxyStats.Stats()
	}
	if s.webdavStats != nil {
		webdavStats = s.webdavStats.Stats()
	}
	if s.rangeStats != nil {
		rangeStats = s.rangeStats.RangeCompatStats()
	}
	if s.fileStats != nil {
		pathStats = s.fileStats.PathCacheStats()
		fileSizeStats = s.fileStats.FileSizeCacheStats()
	}
	return map[string]interface{}{
		"version": config.Version,
		"uptime":  time.Since(s.startTime).Round(time.Second).String(),
		"meta": map[string]interface{}{
			"cleanup_disabled": s.cfg != nil && s.cfg.Database != nil && s.cfg.Database.DisableCleanup,
		},
		"stream": map[string]interface{}{
			"play_first_fallback":     s.cfg != nil && s.cfg.AlistServer.PlayFirstFallback,
			"final_passthrough_count": getUint64FromMap(proxyStats, "stream", "final_passthrough_count") + getUint64FromMap(webdavStats, "stream", "final_passthrough_count"),
			"size_conflict_count":     getUint64FromMap(proxyStats, "stream", "size_conflict_count") + getUint64FromMap(webdavStats, "stream", "size_conflict_count"),
			"strategy_fallback_count": getUint64FromMap(proxyStats, "stream", "strategy_fallback_count") + getUint64FromMap(webdavStats, "stream", "strategy_fallback_count"),
			"first_frame_count":       getUint64FromMap(proxyStats, "stream", "first_frame_count") + getUint64FromMap(webdavStats, "stream", "first_frame_count"),
			"first_frame_fallbacks":   getUint64FromMap(proxyStats, "stream", "first_frame_fallbacks") + getUint64FromMap(webdavStats, "stream", "first_frame_fallbacks"),
			"warmup_enqueue_count":    getUint64FromMap(proxyStats, "stream", "warmup_enqueue_count") + getUint64FromMap(webdavStats, "stream", "warmup_enqueue_count"),
			"strategy_reason_counts":  getMapAny(proxyStats, "strategy_selector", "reason_counts"),
			"provider_strategy":       getMapAny(proxyStats, "strategy_selector", "provider_strategy"),
			"recent_strategy_events":  getSliceAny(proxyStats, "strategy_selector", "recent_events"),
		},
		"cache": map[string]interface{}{
			"path_cache":      pathStats,
			"file_size_cache": fileSizeStats,
		},
		"proxy":              proxyStats,
		"webdav":             webdavStats,
		"range_compat_cache": rangeStats,
	}
}

func buildScanValidationAuth(server config.AlistServer) (string, string) {
	if raw := strings.TrimSpace(server.ScanAuthHeader); raw != "" {
		return extractAuthorizationValue(raw), "header"
	}
	if server.ScanUsername == "" && server.ScanPassword == "" {
		return "", "none"
	}
	token := base64.StdEncoding.EncodeToString([]byte(server.ScanUsername + ":" + server.ScanPassword))
	return "Basic " + token, "basic"
}

func buildAlistURLForServer(server config.AlistServer) string {
	scheme := "http"
	if server.HTTPS {
		scheme = "https"
	}
	if server.ServerPort == 80 || server.ServerPort == 443 {
		return scheme + "://" + server.ServerHost
	}
	return scheme + "://" + server.ServerHost + ":" + strconv.Itoa(server.ServerPort)
}

func extractAuthorizationValue(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	lower := strings.ToLower(raw)
	if strings.HasPrefix(lower, "authorization:") {
		raw = strings.TrimSpace(raw[len("authorization:"):])
	}
	return raw
}

func getAlistRequestTimeout(cfg *config.Config) time.Duration {
	if cfg == nil || cfg.AlistServer.RequestTimeoutSeconds <= 0 {
		return 20 * time.Second
	}
	return time.Duration(cfg.AlistServer.RequestTimeoutSeconds) * time.Second
}

func (s *Service) buildRulesFromSelection(proxyCfg *config.ProxyConfig) {
	if proxyCfg == nil || len(proxyCfg.SelectedProviderIDs) == 0 || s.dictMgr == nil {
		return
	}
	dict, err := s.dictMgr.LoadOrRefresh()
	if err != nil || dict == nil {
		return
	}
	selected := make(map[string]struct{}, len(proxyCfg.SelectedProviderIDs))
	for _, id := range proxyCfg.SelectedProviderIDs {
		item := strings.ToLower(strings.TrimSpace(id))
		if item != "" {
			selected[item] = struct{}{}
		}
	}
	domainSet := make(map[string]struct{})
	priority := 100
	rules := make([]config.ProxyRule, 0, 128)
	for _, provider := range dict.Providers {
		if _, ok := selected[strings.ToLower(provider.ID)]; !ok {
			continue
		}
		for _, domain := range provider.Domains {
			domain = strings.ToLower(strings.TrimSpace(domain))
			if domain == "" {
				continue
			}
			if _, ok := domainSet[domain]; ok {
				continue
			}
			domainSet[domain] = struct{}{}
			rules = append(rules, config.ProxyRule{
				ID:         provider.ID + "-" + domain,
				ProviderID: provider.ID,
				MatchType:  "domain_suffix",
				Pattern:    domain,
				Action:     "proxy",
				Enabled:    true,
				Priority:   priority,
			})
			priority++
		}
	}
	if len(rules) > 0 {
		proxyCfg.Rules = rules
	}
	if len(domainSet) > 0 {
		domains := make([]string, 0, len(domainSet))
		for domain := range domainSet {
			domains = append(domains, domain)
		}
		proxyCfg.SelectedDomains = domains
	}
}

func getUint64FromMap(m map[string]interface{}, path ...string) uint64 {
	if len(path) == 0 {
		return 0
	}
	current := any(m)
	for _, key := range path {
		mp, ok := current.(map[string]interface{})
		if !ok {
			return 0
		}
		current = mp[key]
	}
	switch v := current.(type) {
	case uint64:
		return v
	case int:
		return uint64(v)
	case int64:
		return uint64(v)
	case float64:
		return uint64(v)
	default:
		return 0
	}
}

func getMapAny(m map[string]interface{}, path ...string) map[string]uint64 {
	if len(path) == 0 {
		return map[string]uint64{}
	}
	current := any(m)
	for _, key := range path {
		mp, ok := current.(map[string]interface{})
		if !ok {
			return map[string]uint64{}
		}
		current = mp[key]
	}
	result := map[string]uint64{}
	if src, ok := current.(map[string]uint64); ok {
		return src
	}
	if src, ok := current.(map[string]string); ok {
		for k, v := range src {
			if n, err := strconv.ParseUint(v, 10, 64); err == nil {
				result[k] = n
			}
		}
	}
	if src, ok := current.(map[string]interface{}); ok {
		for k, v := range src {
			switch n := v.(type) {
			case uint64:
				result[k] = n
			case int:
				result[k] = uint64(n)
			case int64:
				result[k] = uint64(n)
			case float64:
				result[k] = uint64(n)
			}
		}
	}
	return result
}

func getSliceAny(m map[string]interface{}, path ...string) []interface{} {
	if len(path) == 0 {
		return []interface{}{}
	}
	current := any(m)
	for _, key := range path {
		mp, ok := current.(map[string]interface{})
		if !ok {
			return []interface{}{}
		}
		current = mp[key]
	}
	if src, ok := current.([]interface{}); ok {
		return src
	}
	return []interface{}{}
}
