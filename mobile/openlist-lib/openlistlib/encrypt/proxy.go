package encrypt

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/OpenListTeam/OpenList/v4/openlistlib/internal"
	log "github.com/sirupsen/logrus"
)

// 流式传输优化常量

const (
	// mediumBufferSize 中等文件缓冲区 (128KB)
	mediumBufferSize = 128 * 1024
	// smallBufferSize 小文件/API响应缓冲区 (32KB)
	smallBufferSize = 32 * 1024
	// prefetchBufferSize 视频预读缓冲区大小 (2MB)，优化快进体验
	prefetchBufferSize = 2 * 1024 * 1024
	// fileCacheTTL 文件信息缓存过期时间
	fileCacheTTL = 10 * time.Minute
	// fileCacheMaxSize 文件缓存最大条目数
	fileCacheMaxSize = 10000
	// redirectCacheTTL 重定向缓存过期时间
	redirectCacheTTL = 5 * time.Minute
	// parallelDecryptThreshold 并行解密文件名的阈值（降低以更早启用并行）
	parallelDecryptThreshold = 5
	// defaultParallelDecrypt 默认并行解密数（当无法获取 CPU 核心数时使用）
	defaultParallelDecrypt = 8
	// maxParallelDecryptLimit 最大并行解密数上限
	maxParallelDecryptLimit = 32
	// defaultRangeSkipMaxBytes 当上游不支持 Range 时，本地最多跳过的字节数
	defaultRangeSkipMaxBytes = 256 * 1024 * 1024
	// rangePreferUpstreamStartBytes 当偏移超过该值时优先保留上游 Range，避免本地大跨度 skip
	rangePreferUpstreamStartBytes = 4 * 1024 * 1024
	// encryptedPrefetchMaxDirs 单次最多预热的子目录数
	encryptedPrefetchMaxDirs = 20
	// encryptedPrefetchConcurrency 预热并发
	encryptedPrefetchConcurrency = 4
	// encryptedPrefetchCooldown 同一路径预热冷却窗口
	encryptedPrefetchCooldown = 45 * time.Second
	// upstreamFailureThreshold 连续失败达到该阈值才触发全局快速失败
	upstreamFailureThreshold = 3
	// defaultStreamEngineVersion 默认播放内核版本（V2）
	defaultStreamEngineVersion = 2
)

// streamBufferSize 流传输缓冲区大小 (默认 512KB)
var streamBufferSize = 512 * 1024

func pathScopeKey(rawPath string) string {
	trimmed := strings.Trim(strings.TrimSpace(rawPath), "/")
	if trimmed == "" {
		return "/"
	}
	first := trimmed
	if idx := strings.IndexByte(trimmed, '/'); idx >= 0 {
		first = trimmed[:idx]
	}
	if first == "" {
		return "/"
	}
	return strings.ToLower(first)
}

const (
	routingModeOff        = "off"
	routingModeByProvider = "by_provider"
	routingActionDirect   = "direct"
	routingActionProxy    = "proxy"
	routingMatchProvider  = "provider"
	routingMatchDriver    = "driver"
)

var builtinDirectProviders = map[string]struct{}{
	"aliyundriveopen": {},
	"baidunetdisk":    {},
	"baiduphoto":      {},
	"cloud189":        {},
	"cloud189pc":      {},
	"open123":         {},
	"pan115":          {},
	"quarkoruc":       {},
	"weiyun":          {},
	"wps":             {},
}

var builtinProxyProviders = map[string]struct{}{
	"onedrive":    {},
	"onedriveapp": {},
	"googlephoto": {},
	"mega":        {},
	"mediafire":   {},
	"protondrive": {},
	"dropbox":     {},
	"github":      {},
}

var providerLabelMap = map[string]string{
	"aliyundriveopen":    "阿里云盘",
	"baidunetdisk":       "百度网盘",
	"baiduphoto":         "百度相册",
	"chinatelecom":       "天翼云盘",
	"cloud189":           "天翼云盘",
	"cloud189pc":         "天翼云盘PC",
	"open123":            "123网盘",
	"pan115":             "115网盘",
	"quarkoruc":          "夸克/UC网盘",
	"weiyun":             "微云",
	"wps":                "WPS网盘",
	"onedrive":           "OneDrive",
	"onedriveapp":        "OneDrive App",
	"googledrive":        "Google Drive",
	"google_drive":       "Google Drive",
	"googlephotoapp":     "Google Photos",
	"googlephoto":        "Google Photos",
	"mega":               "MEGA",
	"mediafire":          "MediaFire",
	"protondrive":        "Proton Drive",
	"dropbox":            "Dropbox",
	"github":             "GitHub",
	"mopan":              "移动云盘",
	"china_mobile_cloud": "移动云盘",
	"mobile_cloud":       "移动云盘",
	"unicom_cloud":       "联通云盘",
	"china_unicom_cloud": "联通云盘",
	"wo_cloud":           "联通云盘",
	"mobile":             "移动云盘",
	"unicom":             "联通云盘",
	"chinamobile":        "移动云盘",
	"chinaunicom":        "联通云盘",
	"google":             "Google Drive",
	"googlephotos":       "Google Photos",
}

const (
	providerSourceBuiltin = 1 << iota
	providerSourceSeen
	providerSourceDriverNames
	providerSourceStorage
	providerSourceRemote
)

var builtinProviderCatalog = map[string]string{
	"aliyundriveopen":    "阿里云盘",
	"aliyundrive":        "阿里云盘",
	"baidunetdisk":       "百度网盘",
	"baiduphoto":         "百度相册",
	"cloud189":           "天翼云盘",
	"cloud189pc":         "天翼云盘PC",
	"open123":            "123网盘",
	"pan115":             "115网盘",
	"quarkoruc":          "夸克/UC网盘",
	"weiyun":             "微云",
	"wps":                "WPS网盘",
	"mopan":              "移动云盘",
	"mobile_cloud":       "移动云盘",
	"china_mobile_cloud": "移动云盘",
	"unicom_cloud":       "联通云盘",
	"china_unicom_cloud": "联通云盘",
	"wo_cloud":           "联通云盘",
	"onedrive":           "OneDrive",
	"onedriveapp":        "OneDrive App",
	"googledrive":        "Google Drive",
	"google_drive":       "Google Drive",
	"googlephoto":        "Google Photos",
	"googlephotoapp":     "Google Photos",
	"mega":               "MEGA",
	"mediafire":          "MediaFire",
	"protondrive":        "Proton Drive",
	"dropbox":            "Dropbox",
	"github":             "GitHub",
}

func normalizeProviderToken(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

// 动态计算的并行解密数，根据 CPU 核心数自动调整
var maxParallelDecrypt = func() int {
	numCPU := runtime.NumCPU()
	if numCPU <= 0 {
		// 无法获取核心数，使用默认值
		return defaultParallelDecrypt
	}
	// 并发数 = CPU 核心数 * 2，范围 [4, maxParallelDecryptLimit]
	parallel := numCPU * 2
	if parallel < 4 {
		parallel = 4
	}
	if parallel > maxParallelDecryptLimit {
		parallel = maxParallelDecryptLimit
	}
	log.Infof("[%s] Auto-detected %d CPU cores, using %d parallel decrypt workers", internal.TagServer, numCPU, parallel)
	return parallel
}()

func (p *ProxyServer) parallelDecryptLimit() int {
	limit := maxParallelDecrypt
	if p != nil && p.config != nil && p.config.ParallelDecryptConcurrency > 0 {
		limit = p.config.ParallelDecryptConcurrency
	}
	if limit < 1 {
		limit = 1
	}
	if limit > maxParallelDecryptLimit {
		limit = maxParallelDecryptLimit
	}
	return limit
}

// 常见视频封面文件扩展名
var coverExtensions = map[string]bool{
	".jpg": true, ".jpeg": true, ".png": true,
	".webp": true, ".gif": true, ".bmp": true,
}

// 分级缓冲区池，根据文件大小选择合适的缓冲区
var (
	// largeBufferPool 大文件缓冲区池 (512KB)
	largeBufferPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, streamBufferSize)
			return &buf
		},
	}
	// mediumBufferPool 中等文件缓冲区池 (128KB)
	mediumBufferPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, mediumBufferSize)
			return &buf
		},
	}
	// smallBufferPool 小文件缓冲区池 (32KB)
	smallBufferPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, smallBufferSize)
			return &buf
		},
	}
)

// ErrStopRedirect 用于停止自动重定向跟随
var ErrStopRedirect = errors.New("redirect stopped")

var startTime = time.Now()

const cacheShardCount = 64

func (s *upstreamHTTPStats) record(d time.Duration, err error, statusCode int) {
	if s == nil {
		return
	}
	s.requests.Add(1)
	s.totalLatencyNs.Add(d.Nanoseconds())
	if err != nil || statusCode >= 500 {
		s.errors.Add(1)
	}
}

func (s *upstreamHTTPStats) snapshot() map[string]interface{} {
	if s == nil {
		return map[string]interface{}{}
	}
	req := s.requests.Load()
	errCnt := s.errors.Load()
	total := s.totalLatencyNs.Load()
	avgMs := int64(0)
	if req > 0 {
		avgMs = (total / req) / int64(time.Millisecond)
	}
	return map[string]interface{}{
		"requests":       req,
		"errors":         errCnt,
		"avg_latency_ms": avgMs,
	}
}

func (rt *instrumentedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	resp, err := rt.base.RoundTrip(req)
	statusCode := 0
	if resp != nil {
		statusCode = resp.StatusCode
	}
	rt.stats.record(time.Since(start), err, statusCode)
	return resp, err
}

func newShardedAnyMap(shards int) *shardedAnyMap {
	if shards <= 0 {
		shards = cacheShardCount
	}
	out := &shardedAnyMap{shards: make([]mapShard, shards)}
	for i := range out.shards {
		out.shards[i].m = make(map[string]interface{})
	}
	return out
}

func (m *shardedAnyMap) shardFor(key string) *mapShard {
	if m == nil || len(m.shards) == 0 {
		return nil
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return &m.shards[int(h.Sum32())%len(m.shards)]
}

func (m *shardedAnyMap) Set(key string, val interface{}) {
	s := m.shardFor(key)
	if s == nil {
		return
	}
	s.mu.Lock()
	s.m[key] = val
	s.mu.Unlock()
}

// Store provides sync.Map-like compatibility for tests/callers.
func (m *shardedAnyMap) Store(key string, val interface{}) {
	m.Set(key, val)
}

func (m *shardedAnyMap) Get(key string) (interface{}, bool) {
	s := m.shardFor(key)
	if s == nil {
		return nil, false
	}
	s.mu.RLock()
	v, ok := s.m[key]
	s.mu.RUnlock()
	return v, ok
}

// Load provides sync.Map-like compatibility for tests/callers.
func (m *shardedAnyMap) Load(key string) (interface{}, bool) {
	return m.Get(key)
}

func (m *shardedAnyMap) Delete(key string) {
	s := m.shardFor(key)
	if s == nil {
		return
	}
	s.mu.Lock()
	delete(s.m, key)
	s.mu.Unlock()
}

func (m *shardedAnyMap) Len() int {
	if m == nil {
		return 0
	}
	total := 0
	for i := range m.shards {
		s := &m.shards[i]
		s.mu.RLock()
		total += len(s.m)
		s.mu.RUnlock()
	}
	return total
}

func (m *shardedAnyMap) Range(fn func(string, interface{}) bool) {
	if m == nil || fn == nil {
		return
	}
	for i := range m.shards {
		s := &m.shards[i]
		s.mu.RLock()
		items := make(map[string]interface{}, len(s.m))
		for k, v := range s.m {
			items[k] = v
		}
		s.mu.RUnlock()

		for k, v := range items {
			if !fn(k, v) {
				return
			}
		}
	}
}

// ProbeMethod 探测方法类型
type ProbeMethod string

const (
	ProbeMethodRange  ProbeMethod = "range"  // Range=0-0 请求（兼容性更好）
	ProbeMethodHead   ProbeMethod = "head"   // HEAD 请求（传统方式）
	ProbeMethodWebDAV ProbeMethod = "webdav" // WebDAV PROPFIND
)

// probeStrategyCache 探测策略缓存（按盘/路径 scope）
// key: path=<encryptPattern>|host=<upstreamHost>
// value: *ProbeStrategy
var probeStrategyCache sync.Map
var probeMethodStats = &ProbeMethodStats{
	byScope: make(map[string]map[ProbeMethod]*ProbeMethodCounter),
}

// ProbeStrategy 探测策略（学习到的成功方法）
type ProbeStrategy struct {
	Method       ProbeMethod // 成功的探测方法
	SuccessCount int64       // 连续成功次数
	FailCount    int64       // 连续失败次数
	UpdatedAt    time.Time   // 最近更新（用于 TTL）
	mutex        sync.Mutex
}

type ProbeMethodCounter struct {
	Success  int64 `json:"success"`
	Fail     int64 `json:"fail"`
	CacheHit int64 `json:"cache_hit"`
}

func (s *ProbeMethodStats) record(scopeKey string, method ProbeMethod, success bool, cacheHit bool) {
	if s == nil || scopeKey == "" || method == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byScope == nil {
		s.byScope = make(map[string]map[ProbeMethod]*ProbeMethodCounter)
	}
	scope := s.byScope[scopeKey]
	if scope == nil {
		scope = make(map[ProbeMethod]*ProbeMethodCounter)
		s.byScope[scopeKey] = scope
	}
	counter := scope[method]
	if counter == nil {
		counter = &ProbeMethodCounter{}
		scope[method] = counter
	}
	if success {
		counter.Success++
	} else {
		counter.Fail++
	}
	if cacheHit {
		counter.CacheHit++
	}
}

func (s *ProbeMethodStats) counter(scopeKey string, method ProbeMethod) ProbeMethodCounter {
	if s == nil || scopeKey == "" || method == "" {
		return ProbeMethodCounter{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byScope == nil {
		return ProbeMethodCounter{}
	}
	scope := s.byScope[scopeKey]
	if scope == nil {
		return ProbeMethodCounter{}
	}
	counter := scope[method]
	if counter == nil {
		return ProbeMethodCounter{}
	}
	return *counter
}

func (s *ProbeMethodStats) snapshot() map[string]map[ProbeMethod]ProbeMethodCounter {
	result := make(map[string]map[ProbeMethod]ProbeMethodCounter)
	if s == nil {
		return result
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for scopeKey, scope := range s.byScope {
		copied := make(map[ProbeMethod]ProbeMethodCounter)
		for method, counter := range scope {
			if counter == nil {
				continue
			}
			copied[method] = *counter
		}
		result[scopeKey] = copied
	}
	return result
}

const (
	defaultProbeStrategyTTLMinutes       = 30 * 24 * 60
	defaultProbeStrategyStableThreshold  = 2
	defaultProbeStrategyFailureThreshold = 2
	defaultSizeMapTTLMinutes             = 365 * 24 * 60
	defaultRangeCompatTTLMinutes         = 30 * 24 * 60
	defaultLocalSizeRetentionDays        = 365
	defaultLocalStrategyRetentionDays    = 30
)

// RedirectInfo 重定向信息，用于缓存和代理重定向
type RedirectInfo struct {
	RedirectURL string       `json:"redirectUrl"` // 实际重定向目标
	PasswdInfo  *EncryptPath `json:"passwdInfo"`  // 加密配置
	FileSize    int64        `json:"fileSize"`    // 文件大小
	OriginalURL string       `json:"originalUrl"` // 原始请求URL
	Headers     http.Header  `json:"headers"`     // 原始请求头
	Provider    string       `json:"provider,omitempty"`
	Driver      string       `json:"driver,omitempty"`
}

// SizeMapEntry represents a persistent file size mapping
type SizeMapEntry struct {
	Size      int64     `json:"size"`
	UpdatedAt time.Time `json:"updated_at"`
}

type encryptPrefixRule struct {
	prefix string
	ep     *EncryptPath
}

// ProxyConfig 代理配置
type ProxyConfig struct {
	AlistHost  string `json:"alistHost"`  // Alist 服务地址
	AlistPort  int    `json:"alistPort"`  // Alist 服务端口
	AlistHttps bool   `json:"alistHttps"` // 是否使用 HTTPS
	ProxyPort  int    `json:"proxyPort"`  // 代理服务端口
	// UpstreamTimeoutSeconds: UI/API 转发超时（秒）
	UpstreamTimeoutSeconds int `json:"upstreamTimeoutSeconds,omitempty"`
	// ProbeTimeoutSeconds: 单次探测请求超时（秒）
	ProbeTimeoutSeconds int `json:"probeTimeoutSeconds,omitempty"`
	// ProbeBudgetSeconds: 单次文件大小探测总预算（秒）
	ProbeBudgetSeconds int `json:"probeBudgetSeconds,omitempty"`
	// UpstreamBackoffSeconds: 上游失败后快速失败窗口（秒）
	UpstreamBackoffSeconds int `json:"upstreamBackoffSeconds,omitempty"`
	// EnableLocalBypass: 对 localhost/私网地址绕过环境代理
	EnableLocalBypass bool `json:"enableLocalBypass,omitempty"`
	// RoutingMode: 路由模式，off 或 by_provider
	RoutingMode string `json:"routingMode,omitempty"`
	// ProviderRuleSource: provider 路由规则来源（预留）
	ProviderRuleSource string `json:"providerRuleSource,omitempty"`
	// RoutingUnmatchedDefault: 未命中 provider/driver 规则时默认动作（direct/proxy）
	RoutingUnmatchedDefault string `json:"routingUnmatchedDefault,omitempty"`
	// ProviderCatalogEnabled: 启用 provider 目录缓存
	ProviderCatalogEnabled bool `json:"providerCatalogEnabled,omitempty"`
	// ProviderCatalogTTLMinutes: provider 目录后台刷新周期
	ProviderCatalogTTLMinutes int `json:"providerCatalogTtlMinutes,omitempty"`
	// ProviderCatalogBootstrapOnStart: 启动时后台刷新 provider 目录
	ProviderCatalogBootstrapOnStart bool `json:"providerCatalogBootstrapOnStart,omitempty"`
	// StorageMapRefreshMinutes: storage driver 映射缓存刷新周期
	StorageMapRefreshMinutes int `json:"storageMapRefreshMinutes,omitempty"`
	// ProviderRoutingRules: provider/driver 分流规则
	ProviderRoutingRules []ProviderRoutingRule `json:"providerRoutingRules,omitempty"`
	EncryptPaths         []*EncryptPath        `json:"encryptPaths"`  // 加密路径配置
	AdminPassword        string                `json:"adminPassword"` // 管理密码
	// ProbeOnDownload: attempt HEAD or Range=0-0 to discover remote file size when missing
	ProbeOnDownload bool `json:"probeOnDownload"`
	// EnableH2C: 启用 H2C (HTTP/2 Cleartext) 连接到后端，需要后端 OpenList 也开启 enable_h2c
	EnableH2C bool `json:"enableH2C"`
	// FileCacheTTL: 文件信息缓存过期时间（分钟），默认 10 分钟，视频/大文件场景可延长
	FileCacheTTL int `json:"fileCacheTTL,omitempty"`
	// ProbeStrategy: 文件大小探测策略 "range"(默认，兼容性更好) 或 "head"(传统方式)
	ProbeStrategy string `json:"probeStrategy,omitempty"`
	// ProbeStrategyTTLMinutes: 探测策略学习缓存有效期（分钟）
	ProbeStrategyTTLMinutes int `json:"probeStrategyTtlMinutes,omitempty"`
	// ProbeStrategyStableThreshold: 探测策略连续成功达到该阈值后视为稳定
	ProbeStrategyStableThreshold int `json:"probeStrategyStableThreshold,omitempty"`
	// ProbeStrategyFailureThreshold: 稳定策略连续失败达到该阈值后触发重学
	ProbeStrategyFailureThreshold int `json:"probeStrategyFailureThreshold,omitempty"`
	// EnableSizeMap: 启用长期文件大小映射缓存
	EnableSizeMap bool `json:"enableSizeMap"`
	// SizeMapTTL: 文件大小映射缓存时间（分钟）
	SizeMapTTL int `json:"sizeMapTtlMinutes,omitempty"`
	// EnableRangeCompatCache: 记录不支持 Range 的上游
	EnableRangeCompatCache bool `json:"enableRangeCompatCache"`
	// RangeCompatTTL: Range 兼容缓存时间（分钟）
	RangeCompatTTL int `json:"rangeCompatTtlMinutes,omitempty"`
	// RangeCompatMinFailures: 标记上游不兼容 Range 前需要连续失败次数
	RangeCompatMinFailures int `json:"rangeCompatMinFailures,omitempty"`
	// RangeSkipMaxBytes: 上游忽略 Range 时，本地跳过字节的上限
	RangeSkipMaxBytes int64 `json:"rangeSkipMaxBytes,omitempty"`
	// PlayFirstFallback: 解密失败时优先兜底直连，保证可播放
	PlayFirstFallback bool `json:"playFirstFallback"`
	// WebDAVNegativeCacheTTLMinutes: WebDAV 404 负缓存时间（分钟）
	WebDAVNegativeCacheTTLMinutes int `json:"webdavNegativeCacheTtlMinutes,omitempty"`
	// RedirectCacheTTLMinutes: redirect 缓存时间（分钟）
	RedirectCacheTTLMinutes int `json:"redirectCacheTtlMinutes,omitempty"`
	// EnableParallelDecrypt: 启用并行解密（大文件）
	EnableParallelDecrypt bool `json:"enableParallelDecrypt"`
	// ParallelDecryptConcurrency: 并行解密并发数
	ParallelDecryptConcurrency int `json:"parallelDecryptConcurrency,omitempty"`
	// StreamBufferKB: 流式解密缓冲区大小（KB）
	StreamBufferKB int `json:"streamBufferKb,omitempty"`
	// StreamEngineVersion: 播放内核版本，1=legacy，2=v2
	StreamEngineVersion int `json:"streamEngineVersion,omitempty"`
	// EnableDBExportSync: 启用通过 DB_EXPORT_API 拉取元数据到本地数据库
	EnableDBExportSync bool `json:"enableDbExportSync,omitempty"`
	// DBExportBaseURL: 远端加密服务地址，例如 http://127.0.0.1:5344
	DBExportBaseURL string `json:"dbExportBaseUrl,omitempty"`
	// DBExportSyncIntervalSeconds: 增量同步轮询间隔（秒）
	DBExportSyncIntervalSeconds int `json:"dbExportSyncIntervalSeconds,omitempty"`
	// DBExportAuthEnabled: 是否启用登录鉴权
	DBExportAuthEnabled bool `json:"dbExportAuthEnabled,omitempty"`
	// DBExportUsername: 登录用户名
	DBExportUsername string `json:"dbExportUsername,omitempty"`
	// DBExportPassword: 登录密码
	DBExportPassword string `json:"dbExportPassword,omitempty"`
	// DebugEnabled: 启用调试日志增强
	DebugEnabled bool `json:"debugEnabled,omitempty"`
	// DebugLevel: 调试级别，支持 info/debug/trace（预留）
	DebugLevel string `json:"debugLevel,omitempty"`
	// DebugModules: 调试模块过滤，空表示全部
	DebugModules []string `json:"debugModules,omitempty"`
	// DebugMaskSensitive: 调试日志中是否对敏感信息脱敏
	DebugMaskSensitive bool `json:"debugMaskSensitive,omitempty"`
	// DebugSampleRate: 调试日志采样率（1-100）
	DebugSampleRate int `json:"debugSampleRate,omitempty"`
	// DebugLogBodyBytes: 调试时记录响应体前 N 字节（0=关闭）
	DebugLogBodyBytes int `json:"debugLogBodyBytes,omitempty"`
	// LocalSizeRetentionDays: 本地事实缓存（size）保留天数
	LocalSizeRetentionDays int `json:"localSizeRetentionDays,omitempty"`
	// LocalStrategyRetentionDays: 本地策略缓存（strategy）保留天数
	LocalStrategyRetentionDays int `json:"localStrategyRetentionDays,omitempty"`
	// ConfigPath: 配置文件路径（运行时注入，不序列化）
	ConfigPath string `json:"-"`
}

// FileInfo 文件信息
type FileInfo struct {
	Name     string `json:"name"`
	Size     int64  `json:"size"`
	IsDir    bool   `json:"is_dir"`
	Modified string `json:"modified"`
	Path     string `json:"path"`
	RawURL   string `json:"raw_url"`
	Sign     string `json:"sign"`
}

var (
// 保留全局 redirectCache 以兼容现有代码，但新代码使用 ProxyServer.redirectCache
)

func applyLearningDefaults(cfg *ProxyConfig) {
	if cfg == nil {
		return
	}
	if cfg.ProbeStrategyTTLMinutes <= 0 {
		cfg.ProbeStrategyTTLMinutes = defaultProbeStrategyTTLMinutes
	}
	if cfg.ProbeStrategyStableThreshold <= 0 {
		cfg.ProbeStrategyStableThreshold = int(defaultProbeStrategyStableThreshold)
	}
	if cfg.ProbeStrategyFailureThreshold <= 0 {
		cfg.ProbeStrategyFailureThreshold = int(defaultProbeStrategyFailureThreshold)
	}
	if cfg.SizeMapTTL <= 0 {
		cfg.SizeMapTTL = defaultSizeMapTTLMinutes
	}
	if cfg.RangeCompatTTL <= 0 {
		cfg.RangeCompatTTL = defaultRangeCompatTTLMinutes
	}
	if cfg.RangeCompatMinFailures <= 0 {
		cfg.RangeCompatMinFailures = 2
	}
	if cfg.RangeSkipMaxBytes <= 0 {
		cfg.RangeSkipMaxBytes = defaultRangeSkipMaxBytes
	}
	if cfg.ParallelDecryptConcurrency <= 0 {
		cfg.ParallelDecryptConcurrency = 8
	}
	if cfg.StreamBufferKB <= 0 {
		cfg.StreamBufferKB = 1024
	}
	if cfg.StreamEngineVersion <= 0 {
		cfg.StreamEngineVersion = defaultStreamEngineVersion
	}
	// 旧配置兼容：缺省时启用播放优先兜底
	if !cfg.PlayFirstFallback && cfg.WebDAVNegativeCacheTTLMinutes == 0 && cfg.ProbeStrategy == "" {
		cfg.PlayFirstFallback = true
	}
	if cfg.WebDAVNegativeCacheTTLMinutes <= 0 {
		cfg.WebDAVNegativeCacheTTLMinutes = 10
	}
	if cfg.LocalSizeRetentionDays <= 0 {
		cfg.LocalSizeRetentionDays = defaultLocalSizeRetentionDays
	}
	if cfg.LocalStrategyRetentionDays <= 0 {
		cfg.LocalStrategyRetentionDays = defaultLocalStrategyRetentionDays
	}
	cfg.RoutingMode = normalizeRoutingMode(cfg.RoutingMode)
	if strings.TrimSpace(cfg.ProviderRuleSource) == "" {
		cfg.ProviderRuleSource = "builtin+custom"
	}
	cfg.RoutingUnmatchedDefault = normalizeRoutingUnmatchedDefault(cfg.RoutingUnmatchedDefault)
	if !cfg.ProviderCatalogEnabled && cfg.ProviderCatalogTTLMinutes == 0 && cfg.StorageMapRefreshMinutes == 0 {
		cfg.ProviderCatalogEnabled = true
	}
	if cfg.ProviderCatalogTTLMinutes <= 0 {
		cfg.ProviderCatalogTTLMinutes = 720
	}
	if !cfg.ProviderCatalogBootstrapOnStart && cfg.ProviderCatalogTTLMinutes == 720 {
		cfg.ProviderCatalogBootstrapOnStart = true
	}
	if cfg.StorageMapRefreshMinutes <= 0 {
		cfg.StorageMapRefreshMinutes = 30
	}
	for i := range cfg.ProviderRoutingRules {
		cfg.ProviderRoutingRules[i].MatchType = normalizeRoutingMatchType(cfg.ProviderRoutingRules[i].MatchType)
		cfg.ProviderRoutingRules[i].Action = normalizeRoutingAction(cfg.ProviderRoutingRules[i].Action)
		cfg.ProviderRoutingRules[i].MatchValues = normalizeRoutingMatchValues(&cfg.ProviderRoutingRules[i])
	}
}

func (p *ProxyServer) markWebdavNegative(requestPath string) {
	key := p.webdavNegativeKey(requestPath)
	if key == "" {
		return
	}
	p.webdavNegativeMu.Lock()
	defer p.webdavNegativeMu.Unlock()
	p.webdavNegativeCache[key] = time.Now().Add(p.webdavNegativeTTL())
}

func (p *ProxyServer) clearWebdavNegative(requestPath string) {
	key := p.webdavNegativeKey(requestPath)
	if key == "" {
		return
	}
	p.webdavNegativeMu.Lock()
	defer p.webdavNegativeMu.Unlock()
	delete(p.webdavNegativeCache, key)
}

func normalizeRulePrefix(raw string) (string, bool) {
	if raw == "" || strings.HasPrefix(raw, "^") {
		return "", false
	}
	base := raw
	if strings.HasSuffix(base, "/*") {
		base = strings.TrimSuffix(base, "/*")
	} else if strings.HasSuffix(base, "/") {
		base = strings.TrimSuffix(base, "/")
	}
	if base == "" {
		return "/", true
	}
	if strings.ContainsAny(base, "*?[](){}+|\\") {
		return "", false
	}
	if !strings.HasPrefix(base, "/") {
		base = "/" + base
	}
	return path.Clean(base), true
}

func convertRealNameByRule(ep *EncryptPath, pathText string) string {
	if ep == nil {
		return path.Base(pathText)
	}
	return ConvertRealNameWithSuffix(ep.Password, ep.EncType, pathText, ep.EncSuffix)
}

func convertShowNameByRule(ep *EncryptPath, pathText string) string {
	if ep == nil {
		return path.Base(pathText)
	}
	return ConvertShowNameWithSuffix(ep.Password, ep.EncType, pathText, ep.EncSuffix)
}

func (p *ProxyServer) initSizeMap() {
	if p.config == nil || !p.config.EnableSizeMap {
		return
	}
	p.sizeMap = make(map[string]SizeMapEntry)
	if p.sizeMapPath == "" && p.config.ConfigPath != "" {
		p.sizeMapPath = filepath.Join(filepath.Dir(p.config.ConfigPath), "size_map.json")
	}
	p.loadSizeMap()
	if p.sizeMapDone == nil {
		p.sizeMapDone = make(chan struct{})
		go p.sizeMapLoop()
	}
}

func (p *ProxyServer) sizeMapLoop() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			p.flushSizeMap(false)
		case <-p.sizeMapDone:
			p.flushSizeMap(true)
			return
		}
	}
}

func (p *ProxyServer) loadSizeMap() {
	if p.sizeMapPath == "" {
		return
	}
	data, err := os.ReadFile(p.sizeMapPath)
	if err != nil {
		return
	}
	var raw map[string]SizeMapEntry
	if err := json.Unmarshal(data, &raw); err != nil {
		log.Warnf("[%s] Failed to load size map: %v", internal.TagCache, err)
		return
	}
	p.sizeMapMu.Lock()
	for k, v := range raw {
		p.sizeMap[k] = v
	}
	p.sizeMapMu.Unlock()
}

func (p *ProxyServer) flushSizeMap(force bool) {
	if p.sizeMapPath == "" {
		return
	}
	p.sizeMapMu.RLock()
	if !force && !p.sizeMapDirty {
		p.sizeMapMu.RUnlock()
		return
	}
	copyMap := make(map[string]SizeMapEntry, len(p.sizeMap))
	for k, v := range p.sizeMap {
		copyMap[k] = v
	}
	p.sizeMapMu.RUnlock()

	data, err := json.MarshalIndent(copyMap, "", "  ")
	if err != nil {
		log.Warnf("[%s] Failed to marshal size map: %v", internal.TagCache, err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(p.sizeMapPath), 0755); err != nil {
		log.Warnf("[%s] Failed to create size map dir: %v", internal.TagCache, err)
		return
	}
	if err := os.WriteFile(p.sizeMapPath, data, 0644); err != nil {
		log.Warnf("[%s] Failed to write size map: %v", internal.TagCache, err)
		return
	}
	p.sizeMapMu.Lock()
	p.sizeMapDirty = false
	p.sizeMapMu.Unlock()
}

func (p *ProxyServer) updateSizeMap(path string, size int64) {
	if p.config == nil || !p.config.EnableSizeMap || size <= 0 || p.sizeMap == nil {
		return
	}
	key := normalizeCacheKey(path)
	p.sizeMapMu.Lock()
	p.sizeMap[key] = SizeMapEntry{Size: size, UpdatedAt: time.Now()}
	p.sizeMapDirty = true
	p.sizeMapMu.Unlock()
}

func (p *ProxyServer) getSizeMap(path string) (SizeMapEntry, bool) {
	if p.config == nil || !p.config.EnableSizeMap || p.sizeMap == nil {
		return SizeMapEntry{}, false
	}
	key := normalizeCacheKey(path)
	p.sizeMapMu.RLock()
	entry, ok := p.sizeMap[key]
	p.sizeMapMu.RUnlock()
	if !ok || entry.Size <= 0 {
		return SizeMapEntry{}, false
	}
	if p.config.SizeMapTTL > 0 {
		if time.Since(entry.UpdatedAt) > time.Duration(p.config.SizeMapTTL)*time.Minute {
			p.sizeMapMu.Lock()
			delete(p.sizeMap, key)
			p.sizeMapDirty = true
			p.sizeMapMu.Unlock()
			return SizeMapEntry{}, false
		}
	}
	return entry, true
}

func (p *ProxyServer) initRangeCompat() {
	if p.config == nil || !p.config.EnableRangeCompatCache {
		return
	}
	p.rangeCompatMu.Lock()
	if p.rangeCompat == nil {
		p.rangeCompat = make(map[string]time.Time)
	}
	if p.rangeCompatFailures == nil {
		p.rangeCompatFailures = make(map[string]int)
	}
	p.rangeCompatMu.Unlock()
	if p.localStore != nil {
		if records, err := p.localStore.LoadRangeCompat(time.Now()); err != nil {
			log.Warnf("[%s] load range compat cache failed: %v", internal.TagCache, err)
		} else if len(records) > 0 {
			p.rangeCompatMu.Lock()
			for key, blockedUntil := range records {
				p.rangeCompat[key] = blockedUntil
			}
			p.rangeCompatMu.Unlock()
		}
	}
}

func (p *ProxyServer) rangeCompatKey(targetURL, sourcePath string) string {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return ""
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if host == "" {
		host = strings.ToLower(strings.TrimSpace(parsed.Host))
	}
	if host == "" {
		return ""
	}
	scope := pathScopeKey(sourcePath)
	if scope == "/" {
		scope = pathScopeKey(parsed.Path)
	}
	return host + "|" + scope
}

func (p *ProxyServer) rangeCompatTTL() time.Duration {
	if p.config == nil || p.config.RangeCompatTTL <= 0 {
		return 0
	}
	return time.Duration(p.config.RangeCompatTTL) * time.Minute
}

func (p *ProxyServer) shouldSkipRange(targetURL, sourcePath string) bool {
	if p.config == nil || !p.config.EnableRangeCompatCache {
		return false
	}
	ttl := p.rangeCompatTTL()
	if ttl <= 0 {
		return false
	}
	key := p.rangeCompatKey(targetURL, sourcePath)
	if key == "" {
		return false
	}
	p.rangeCompatMu.RLock()
	expireAt, ok := p.rangeCompat[key]
	p.rangeCompatMu.RUnlock()
	if !ok {
		return false
	}
	if time.Now().After(expireAt) {
		p.rangeCompatMu.Lock()
		delete(p.rangeCompat, key)
		p.rangeCompatMu.Unlock()
		if p.localStore != nil {
			_ = p.localStore.DeleteRangeCompat(key)
		}
		return false
	}
	return true
}

func (p *ProxyServer) rangeCompatMinFailures() int {
	if p == nil || p.config == nil || p.config.RangeCompatMinFailures <= 0 {
		return 2
	}
	return p.config.RangeCompatMinFailures
}

func (p *ProxyServer) rangeSkipMaxBytes() int64 {
	if p == nil || p.config == nil || p.config.RangeSkipMaxBytes <= 0 {
		return defaultRangeSkipMaxBytes
	}
	return p.config.RangeSkipMaxBytes
}

func (p *ProxyServer) markRangeIncompatible(targetURL, sourcePath string) {
	if p.config == nil || !p.config.EnableRangeCompatCache {
		return
	}
	ttl := p.rangeCompatTTL()
	if ttl <= 0 {
		return
	}
	key := p.rangeCompatKey(targetURL, sourcePath)
	if key == "" {
		return
	}
	p.rangeCompatMu.Lock()
	if p.rangeCompat == nil {
		p.rangeCompat = make(map[string]time.Time)
	}
	if p.rangeCompatFailures == nil {
		p.rangeCompatFailures = make(map[string]int)
	}
	p.rangeCompatFailures[key]++
	failures := p.rangeCompatFailures[key]
	threshold := p.rangeCompatMinFailures()
	if failures >= p.rangeCompatMinFailures() {
		p.rangeCompat[key] = time.Now().Add(ttl)
		p.rangeCompatFailures[key] = 0
	}
	blockedUntil := p.rangeCompat[key]
	p.rangeCompatMu.Unlock()
	if p.localStore != nil {
		if failures >= threshold {
			_ = p.localStore.UpsertRangeCompat(key, blockedUntil, 0)
		} else {
			_ = p.localStore.UpsertRangeCompat(key, time.Time{}, failures)
		}
	}
	p.registerRangeProbeTarget(targetURL, sourcePath, failures >= threshold)
	p.debugf("range", "mark incompatible key=%s failures=%d ttl=%s", key, failures, ttl.String())
}

func (p *ProxyServer) markRangeCompatible(targetURL, sourcePath string) {
	if p.config == nil || !p.config.EnableRangeCompatCache {
		return
	}
	key := p.rangeCompatKey(targetURL, sourcePath)
	if key == "" {
		return
	}
	p.rangeCompatMu.Lock()
	delete(p.rangeCompat, key)
	if p.rangeCompatFailures != nil {
		delete(p.rangeCompatFailures, key)
	}
	p.rangeCompatMu.Unlock()
	if p.localStore != nil {
		_ = p.localStore.DeleteRangeCompat(key)
	}
	p.registerRangeProbeTarget(targetURL, sourcePath, false)
	p.debugf("range", "mark compatible key=%s", key)
}

func (p *ProxyServer) markUpstreamFailure(err error) {
	if p == nil {
		return
	}
	p.upstreamMu.Lock()
	defer p.upstreamMu.Unlock()
	p.upstreamFailures++
	if err != nil {
		p.upstreamError = err.Error()
	}
	if p.upstreamFailures < upstreamFailureThreshold {
		return
	}
	p.upstreamDownAt = time.Now().Add(p.upstreamBackoff())
}

func (p *ProxyServer) markUpstreamSuccess() {
	if p == nil {
		return
	}
	p.upstreamMu.Lock()
	defer p.upstreamMu.Unlock()
	p.upstreamDownAt = time.Time{}
	p.upstreamError = ""
	p.upstreamFailures = 0
}

func (p *ProxyServer) upstreamBackoffState() (active bool, remain time.Duration, reason string) {
	if p == nil {
		return false, 0, ""
	}
	p.upstreamMu.RLock()
	defer p.upstreamMu.RUnlock()
	reason = p.upstreamError
	if p.upstreamDownAt.IsZero() {
		return false, 0, reason
	}
	remain = time.Until(p.upstreamDownAt)
	if remain <= 0 {
		return false, 0, reason
	}
	return true, remain, reason
}

func (p *ProxyServer) shouldFastFailUpstream() bool {
	active, _, _ := p.upstreamBackoffState()
	return active
}

func (p *ProxyServer) writeUpstreamUnavailable(w http.ResponseWriter) {
	active, remain, reason := p.upstreamBackoffState()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"code":                    http.StatusServiceUnavailable,
		"message":                 "upstream unavailable",
		"upstream_backoff_active": active,
		"backoff_remaining_ms":    remain.Milliseconds(),
		"reason":                  reason,
	})
}

// IsRunning 检查是否运行中
func (p *ProxyServer) IsRunning() bool {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.running
}

func (p *ProxyServer) persistConfigSnapshot() error {
	p.mutex.RLock()
	if p.config == nil || strings.TrimSpace(p.config.ConfigPath) == "" {
		p.mutex.RUnlock()
		return nil
	}
	cfg := *p.config
	cfgPaths := make([]*EncryptPath, len(p.config.EncryptPaths))
	for i, ep := range p.config.EncryptPaths {
		if ep == nil {
			continue
		}
		epCopy := *ep
		cfgPaths[i] = &epCopy
	}
	cfg.EncryptPaths = cfgPaths
	if len(p.config.ProviderRoutingRules) > 0 {
		cfgRules := make([]ProviderRoutingRule, len(p.config.ProviderRoutingRules))
		copy(cfgRules, p.config.ProviderRoutingRules)
		cfg.ProviderRoutingRules = cfgRules
	}
	configPath := cfg.ConfigPath
	p.mutex.RUnlock()

	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(&cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, data, 0644)
}

// getAlistURL 获取 Alist 服务 URL
func (p *ProxyServer) getAlistURL() string {
	protocol := "http"
	if p.config.AlistHttps {
		protocol = "https"
	}
	return fmt.Sprintf("%s://%s:%d", protocol, p.config.AlistHost, p.config.AlistPort)
}

// getProbeStrategy 获取加密路径的探测策略（如果已学习）
func (p *ProxyServer) probeStrategyTTL() time.Duration {
	if p != nil && p.config != nil && p.config.ProbeStrategyTTLMinutes > 0 {
		return time.Duration(p.config.ProbeStrategyTTLMinutes) * time.Minute
	}
	return time.Duration(defaultProbeStrategyTTLMinutes) * time.Minute
}

func (p *ProxyServer) probeStrategyStableThreshold() int64 {
	if p != nil && p.config != nil && p.config.ProbeStrategyStableThreshold > 0 {
		return int64(p.config.ProbeStrategyStableThreshold)
	}
	return defaultProbeStrategyStableThreshold
}

func (p *ProxyServer) probeStrategyFailureThreshold() int64 {
	if p != nil && p.config != nil && p.config.ProbeStrategyFailureThreshold > 0 {
		return int64(p.config.ProbeStrategyFailureThreshold)
	}
	return defaultProbeStrategyFailureThreshold
}

func (p *ProxyServer) probeScopeKey(encPathPattern string, targetURL string) string {
	pattern := strings.TrimSpace(encPathPattern)
	if pattern == "" {
		pattern = "*"
	}
	host := "*"
	if parsed, err := url.Parse(targetURL); err == nil {
		h := strings.TrimSpace(strings.ToLower(parsed.Hostname()))
		if h != "" {
			host = h
		}
	}
	return "path=" + pattern + "|host=" + host
}

func (p *ProxyServer) probeMethodScore(scopeKey string, method ProbeMethod) int64 {
	counter := probeMethodStats.counter(scopeKey, method)
	return counter.Success*4 + counter.CacheHit*2 - counter.Fail*3
}

func (p *ProxyServer) prioritizeProbeMethods(scopeKey string, methods []ProbeMethod) []ProbeMethod {
	if len(methods) <= 1 {
		return methods
	}
	prioritized := append([]ProbeMethod(nil), methods...)
	sort.SliceStable(prioritized, func(i, j int) bool {
		return p.probeMethodScore(scopeKey, prioritized[i]) > p.probeMethodScore(scopeKey, prioritized[j])
	})
	return prioritized
}

func (p *ProxyServer) probeWithMethodCtx(ctx context.Context, method ProbeMethod, targetURL string, headers http.Header) int64 {
	switch method {
	case ProbeMethodRange:
		return p.probeWithRangeCtx(ctx, targetURL, headers)
	case ProbeMethodHead:
		return p.probeWithHeadCtx(ctx, targetURL, headers)
	case ProbeMethodWebDAV:
		return p.fetchWebDAVFileSizeCtx(ctx, targetURL, headers)
	default:
		return 0
	}
}

// getProbeStrategy 获取加密路径的探测策略（如果已学习）
func (p *ProxyServer) getProbeStrategy(encPathPattern string) *ProbeStrategy {
	if encPathPattern == "" {
		return nil
	}
	val, ok := probeStrategyCache.Load(encPathPattern)
	if !ok {
		return nil
	}
	strategy := val.(*ProbeStrategy)
	strategy.mutex.Lock()
	expired := strategy.UpdatedAt.IsZero() || time.Since(strategy.UpdatedAt) > p.probeStrategyTTL()
	strategy.mutex.Unlock()
	if expired {
		probeStrategyCache.Delete(encPathPattern)
		return nil
	}
	return strategy
}

// updateProbeStrategy 更新探测策略（学习成功的方法）
func (p *ProxyServer) updateProbeStrategy(encPathPattern string, method ProbeMethod) {
	if encPathPattern == "" {
		return
	}
	val, _ := probeStrategyCache.LoadOrStore(encPathPattern, &ProbeStrategy{
		Method:       method,
		SuccessCount: 0,
		FailCount:    0,
		UpdatedAt:    time.Now(),
	})
	strategy := val.(*ProbeStrategy)
	strategy.mutex.Lock()
	defer strategy.mutex.Unlock()
	if strategy.Method == method {
		strategy.SuccessCount++
	} else {
		// 方法变化，重置计数
		strategy.Method = method
		strategy.SuccessCount = 1
	}
	strategy.FailCount = 0
	strategy.UpdatedAt = time.Now()
}

func (p *ProxyServer) markProbeStrategyFailure(encPathPattern string, method ProbeMethod) {
	if encPathPattern == "" {
		return
	}
	val, ok := probeStrategyCache.Load(encPathPattern)
	if !ok {
		return
	}
	strategy := val.(*ProbeStrategy)
	shouldDelete := false
	strategy.mutex.Lock()
	if strategy.Method == method {
		strategy.FailCount++
		strategy.UpdatedAt = time.Now()
		if strategy.FailCount >= p.probeStrategyFailureThreshold() {
			shouldDelete = true
		}
	}
	strategy.mutex.Unlock()
	if shouldDelete {
		probeStrategyCache.Delete(encPathPattern)
	}
}

// clearProbeStrategy 清除加密路径的探测策略缓存
func (p *ProxyServer) clearProbeStrategy(encPathPattern string) {
	probeStrategyCache.Delete(encPathPattern)
}

// ClearAllProbeStrategies 清除所有探测策略缓存（用于调试/管理）
func ClearAllProbeStrategies() {
	probeStrategyCache.Range(func(key, value interface{}) bool {
		probeStrategyCache.Delete(key)
		return true
	})
	if probeMethodStats != nil {
		probeMethodStats.mu.Lock()
		probeMethodStats.byScope = make(map[string]map[ProbeMethod]*ProbeMethodCounter)
		probeMethodStats.mu.Unlock()
	}
	log.Info("[" + internal.TagCache + "] All probe strategy cache cleared")
}

// probeWithHead 使用 HEAD 请求探测文件大小
func (p *ProxyServer) probeWithHeadCtx(ctx context.Context, targetURL string, headers http.Header) int64 {
	req, err := http.NewRequestWithContext(ctx, "HEAD", targetURL, nil)
	if err != nil {
		return 0
	}
	for key, values := range headers {
		if key == "Host" {
			continue
		}
		for _, v := range values {
			req.Header.Add(key, v)
		}
	}
	client := p.probeClient
	if client == nil {
		client = p.httpClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()

	// 尝试 Content-Length
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		if size, err := strconv.ParseInt(cl, 10, 64); err == nil && size > 0 {
			return size
		}
	}
	// 尝试 Content-Range
	if cr := resp.Header.Get("Content-Range"); cr != "" {
		if idx := strings.LastIndex(cr, "/"); idx != -1 {
			totalStr := cr[idx+1:]
			if totalStr != "*" {
				if total, err := strconv.ParseInt(totalStr, 10, 64); err == nil && total > 0 {
					return total
				}
			}
		}
	}
	return 0
}

func (p *ProxyServer) probeWithHead(targetURL string, headers http.Header) int64 {
	ctx, cancel := context.WithTimeout(context.Background(), p.probeTimeout())
	defer cancel()
	return p.probeWithHeadCtx(ctx, targetURL, headers)
}

// probeWithRange 使用 Range=0-0 请求探测文件大小
func (p *ProxyServer) probeWithRangeCtx(ctx context.Context, targetURL string, headers http.Header) int64 {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return 0
	}
	for key, values := range headers {
		if key == "Host" {
			continue
		}
		for _, v := range values {
			req.Header.Add(key, v)
		}
	}
	req.Header.Set("Range", "bytes=0-0")
	client := p.probeClient
	if client == nil {
		client = p.httpClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()

	// 优先解析 Content-Range
	if cr := resp.Header.Get("Content-Range"); cr != "" {
		if idx := strings.LastIndex(cr, "/"); idx != -1 {
			totalStr := cr[idx+1:]
			if totalStr != "*" {
				if total, err := strconv.ParseInt(totalStr, 10, 64); err == nil && total > 0 {
					return total
				}
			}
		}
	}
	// 某些服务器不支持 Range，会返回完整文件的 Content-Length
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		if size, err := strconv.ParseInt(cl, 10, 64); err == nil && size > 0 {
			// 如果状态码是 200（不是 206），说明返回的是完整文件
			if resp.StatusCode == http.StatusOK {
				return size
			}
		}
	}
	return 0
}

func (p *ProxyServer) probeWithRange(targetURL string, headers http.Header) int64 {
	ctx, cancel := context.WithTimeout(context.Background(), p.probeTimeout())
	defer cancel()
	return p.probeWithRangeCtx(ctx, targetURL, headers)
}

// forceProbeRemoteFileSize 强制探测远程文件大小（不受 ProbeOnDownload 配置限制）
// 用于加密文件解密场景：没有 fileSize 就无法生成密钥，解密必然失败
func (p *ProxyServer) forceProbeRemoteFileSize(targetURL string, headers http.Header) int64 {
	return p.forceProbeRemoteFileSizeWithPath(targetURL, headers, "")
}

// probeRemoteFileSize 尝试通过 HEAD 或 Range 请求获取远程文件总大小
// 支持探测策略学习：首次按顺序尝试，后续使用学习到的成功方法
func (p *ProxyServer) probeRemoteFileSize(targetURL string, headers http.Header) int64 {
	return p.probeRemoteFileSizeWithPath(targetURL, headers, "")
}

// fetchWebDAVFileSize 通过 PROPFIND 获取文件大小（Depth: 0）
func (p *ProxyServer) fetchWebDAVFileSize(targetURL string, headers http.Header) int64 {
	ctx, cancel := context.WithTimeout(context.Background(), p.probeTimeout())
	defer cancel()
	return p.fetchWebDAVFileSizeCtx(ctx, targetURL, headers)
}

func (p *ProxyServer) fetchWebDAVFileSizeCtx(ctx context.Context, targetURL string, headers http.Header) int64 {
	body := `<?xml version="1.0" encoding="utf-8" ?><D:propfind xmlns:D="DAV:"><D:prop><D:getcontentlength/></D:prop></D:propfind>`
	req, err := http.NewRequestWithContext(ctx, "PROPFIND", targetURL, strings.NewReader(body))
	if err != nil {
		return 0
	}
	for key, values := range headers {
		if key == "Host" || strings.EqualFold(key, "Content-Length") {
			continue
		}
		for _, v := range values {
			req.Header.Add(key, v)
		}
	}
	req.Header.Set("Depth", "0")
	req.Header.Set("Content-Type", "application/xml; charset=utf-8")

	client := p.probeClient
	if client == nil {
		client = p.httpClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0
	}

	dec := xml.NewDecoder(resp.Body)
	for {
		tok, err := dec.Token()
		if err != nil {
			return 0
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if strings.EqualFold(t.Name.Local, "getcontentlength") {
				if t2, err := dec.Token(); err == nil {
					if cd, ok := t2.(xml.CharData); ok {
						s := strings.TrimSpace(string(cd))
						if s != "" {
							if v, err := strconv.ParseInt(s, 10, 64); err == nil && v > 0 {
								return v
							}
						}
					}
				}
			}
		}
	}
}

// processPropfindResponse 解析并替换 PROPFIND XML 中的 href/displayname，并缓存文件信息
func (p *ProxyServer) processPropfindResponse(body io.Reader, w io.Writer, encPath *EncryptPath) error {
	dec := xml.NewDecoder(body)
	enc := xml.NewEncoder(w)

	inResponse := false
	var curHref string
	var curHrefShow string
	var curSize int64 = -1

	for {
		t, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		switch tok := t.(type) {
		case xml.StartElement:
			if strings.EqualFold(tok.Name.Local, "response") {
				inResponse = true
				curHref = ""
				curHrefShow = ""
				curSize = -1
			}
			if err := enc.EncodeToken(tok); err != nil {
				return err
			}

			if inResponse && strings.EqualFold(tok.Name.Local, "href") {
				t2, err := dec.Token()
				if err != nil {
					return err
				}
				if cd, ok := t2.(xml.CharData); ok {
					content := string(cd)
					decodedPath, err := url.PathUnescape(content)
					if err == nil {
						curHref = decodedPath
						curHrefShow = decodedPath
						fileName := path.Base(decodedPath)
						if fileName != "/" && fileName != "." && !strings.HasPrefix(fileName, "orig_") {
							// 仅对“看起来像文件”的名称进行解密（与 alist-encrypt 行为一致，避免误判目录）
							ext := path.Ext(fileName)
							if ext != "" {
								showName := convertShowNameByRule(encPath, fileName)
								if showName != fileName && !strings.HasPrefix(showName, "orig_") {
									newPath := path.Join(path.Dir(decodedPath), showName)
									curHrefShow = newPath
									content = (&url.URL{Path: newPath}).EscapedPath()
								}
							}
						}
					}
					if err := enc.EncodeToken(xml.CharData([]byte(content))); err != nil {
						return err
					}
				} else {
					if err := enc.EncodeToken(t2); err != nil {
						return err
					}
				}
				continue
			}

			if inResponse && strings.EqualFold(tok.Name.Local, "displayname") {
				t2, err := dec.Token()
				if err != nil {
					return err
				}
				if cd, ok := t2.(xml.CharData); ok {
					content := string(cd)
					decodedName, err := url.PathUnescape(content)
					if err == nil {
						fileName := decodedName
						if fileName != "/" && fileName != "." && !strings.HasPrefix(fileName, "orig_") {
							ext := path.Ext(fileName)
							if ext != "" {
								showName := convertShowNameByRule(encPath, fileName)
								if showName != fileName && !strings.HasPrefix(showName, "orig_") {
									content = showName
								}
							}
						}
					}
					if err := enc.EncodeToken(xml.CharData([]byte(content))); err != nil {
						return err
					}
				} else {
					if err := enc.EncodeToken(t2); err != nil {
						return err
					}
				}
				continue
			}

			if inResponse && strings.EqualFold(tok.Name.Local, "getcontentlength") {
				t2, err := dec.Token()
				if err != nil {
					return err
				}
				if cd, ok := t2.(xml.CharData); ok {
					s := strings.TrimSpace(string(cd))
					if s != "" {
						if v, err := strconv.ParseInt(s, 10, 64); err == nil {
							curSize = v
						}
					}
					if err := enc.EncodeToken(xml.CharData([]byte(s))); err != nil {
						return err
					}
				} else {
					if err := enc.EncodeToken(t2); err != nil {
						return err
					}
				}
				continue
			}

		case xml.EndElement:
			if err := enc.EncodeToken(tok); err != nil {
				return err
			}
			if inResponse && strings.EqualFold(tok.Name.Local, "response") {
				if curHref != "" {
					name := path.Base(curHref)
					isDir := false
					size := curSize
					if size <= 0 {
						isDir = true
						size = 0
					}
					// 使用带 TTL 的缓存（同时缓存密文与明文路径，便于 WebDAV GET 命中）
					p.storeFileCache(curHref, &FileInfo{Name: name, Size: size, IsDir: isDir, Path: curHref})
					if curHrefShow != "" && curHrefShow != curHref {
						p.storeFileCache(curHrefShow, &FileInfo{Name: path.Base(curHrefShow), Size: size, IsDir: isDir, Path: curHrefShow})
					}
				}
				inResponse = false
			}
		default:
			if err := enc.EncodeToken(tok); err != nil {
				return err
			}
		}
	}
	return enc.Flush()
}

// applyFolderOverride 按 alist-encrypt 逻辑解析目录名中的加密配置
func (p *ProxyServer) applyFolderOverride(ep *EncryptPath, filePath string) *EncryptPath {
	if ep == nil {
		return nil
	}
	folders := strings.Split(filePath, "/")
	for _, folder := range folders {
		if folder == "" {
			continue
		}
		decodedFolder, err := url.PathUnescape(folder)
		if err == nil {
			folder = decodedFolder
		}
		if encType, passwd, ok := DecodeFolderName(ep.Password, ep.EncType, folder); ok {
			newEp := *ep
			newEp.EncType = encType
			newEp.Password = passwd
			return &newEp
		}
	}
	return ep
}

// handlePing 处理 ping 请求
func (p *ProxyServer) handlePing(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"version": "1.0.0",
		"time":    time.Now().Unix(),
	})
}

func (p *ProxyServer) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	active, remain, reason := p.upstreamBackoffState()
	reachable := false
	ctx, cancel := context.WithTimeout(r.Context(), 1500*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.getAlistURL()+"/ping", nil)
	if err == nil {
		if resp, reqErr := p.httpClient.Do(req); reqErr == nil {
			reachable = resp.StatusCode >= 200 && resp.StatusCode < 500
			resp.Body.Close()
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"proxy": map[string]interface{}{
			"running": p.IsRunning(),
			"port":    p.config.ProxyPort,
		},
		"upstream": map[string]interface{}{
			"url":                       p.getAlistURL(),
			"reachable":                 reachable,
			"backoff_active":            active,
			"backoff_remaining_seconds": int(remain.Seconds()),
			"last_error":                reason,
		},
	})
}

// handleRoot 处理根路径
func (p *ProxyServer) handleRoot(w http.ResponseWriter, r *http.Request) {
	log.Debugf("[%s] Handling root request: %s", internal.TagProxy, r.URL.Path)
	// 直接代理到 OpenList (Alist)
	p.handleProxy(w, r)
}

// handleUserInfo 处理用户信息请求
func (p *ProxyServer) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	userInfo := map[string]interface{}{
		"username": "admin",
		"avatar":   "",
	}
	roles := []string{"admin"}
	codes := []string{}
	version := "0.1.0"
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 200,
		"data": map[string]interface{}{
			"userInfo": userInfo,
			"roles":    roles,
			"codes":    codes,
			"version":  version,
		},
		// 兼容旧前端：直接返回顶层字段
		"userInfo": userInfo,
		"roles":    roles,
		"codes":    codes,
		"version":  version,
	})
}

// handleConfig 处理配置 API
func (p *ProxyServer) handleConfig(w http.ResponseWriter, r *http.Request) {
	// 支持 GET 返回当前配置，支持 POST 保存配置（兼容前端多种请求场景）
	if r.Method == http.MethodGet {
		// 转换为前端期望的格式
		passwdList := make([]map[string]interface{}, 0)
		for _, ep := range p.config.EncryptPaths {
			encType := string(ep.EncType)
			if encType == "aes-ctr" {
				encType = "aesctr"
			} else if encType == "rc4md5" {
				encType = "rc4"
			}

			passwdList = append(passwdList, map[string]interface{}{
				"encPath":   []string{ep.Path},
				"password":  ep.Password,
				"encType":   encType,
				"encName":   ep.EncName,
				"encSuffix": ep.EncSuffix,
				"enable":    ep.Enable,
			})
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 200,
			"data": map[string]interface{}{
				"alistHost":                       p.config.AlistHost,
				"alistPort":                       p.config.AlistPort,
				"https":                           p.config.AlistHttps,
				"alistHttps":                      p.config.AlistHttps,
				"proxyPort":                       p.config.ProxyPort,
				"upstreamTimeoutSeconds":          p.config.UpstreamTimeoutSeconds,
				"probeTimeoutSeconds":             p.config.ProbeTimeoutSeconds,
				"probeBudgetSeconds":              p.config.ProbeBudgetSeconds,
				"upstreamBackoffSeconds":          p.config.UpstreamBackoffSeconds,
				"enableLocalBypass":               p.config.EnableLocalBypass,
				"routingMode":                     p.config.RoutingMode,
				"providerRuleSource":              p.config.ProviderRuleSource,
				"routingUnmatchedDefault":         p.config.RoutingUnmatchedDefault,
				"providerCatalogEnabled":          p.config.ProviderCatalogEnabled,
				"providerCatalogTtlMinutes":       p.config.ProviderCatalogTTLMinutes,
				"providerCatalogBootstrapOnStart": p.config.ProviderCatalogBootstrapOnStart,
				"passwdList":                      passwdList,
				"probeOnDownload":                 p.config.ProbeOnDownload,
				"probeStrategyTtlMinutes":         p.config.ProbeStrategyTTLMinutes,
				"probeStrategyStableThreshold":    p.config.ProbeStrategyStableThreshold,
				"probeStrategyFailureThreshold":   p.config.ProbeStrategyFailureThreshold,
				"enableSizeMap":                   p.config.EnableSizeMap,
				"sizeMapTtlMinutes":               p.config.SizeMapTTL,
				"enableRangeCompatCache":          p.config.EnableRangeCompatCache,
				"rangeCompatTtlMinutes":           p.config.RangeCompatTTL,
				"rangeCompatMinFailures":          p.config.RangeCompatMinFailures,
				"rangeSkipMaxBytes":               p.config.RangeSkipMaxBytes,
				"playFirstFallback":               p.config.PlayFirstFallback,
				"webdavNegativeCacheTtlMinutes":   p.config.WebDAVNegativeCacheTTLMinutes,
				"redirectCacheTtlMinutes":         p.config.RedirectCacheTTLMinutes,
				"enableParallelDecrypt":           p.config.EnableParallelDecrypt,
				"parallelDecryptConcurrency":      p.config.ParallelDecryptConcurrency,
				"streamBufferKb":                  p.config.StreamBufferKB,
				"streamEngineVersion":             p.config.StreamEngineVersion,
				"debugEnabled":                    p.config.DebugEnabled,
				"debugLevel":                      p.config.DebugLevel,
				"debugModules":                    p.config.DebugModules,
				"debugMaskSensitive":              p.config.DebugMaskSensitive,
				"debugSampleRate":                 p.config.DebugSampleRate,
				"debugLogBodyBytes":               p.config.DebugLogBodyBytes,
				"localSizeRetentionDays":          p.config.LocalSizeRetentionDays,
				"localStrategyRetentionDays":      p.config.LocalStrategyRetentionDays,
				"enableDbExportSync":              p.config.EnableDBExportSync,
				"dbExportBaseUrl":                 p.config.DBExportBaseURL,
				"dbExportSyncIntervalSeconds":     p.config.DBExportSyncIntervalSeconds,
				"dbExportAuthEnabled":             p.config.DBExportAuthEnabled,
				"dbExportUsername":                p.config.DBExportUsername,
				"dbExportPassword":                p.config.DBExportPassword,
			},
		})
		return
	}

	if r.Method == http.MethodPost {
		// 尝试解析为通用保存结构：优先处理 encryptPaths（前端路径保存），其次处理 saveAlistConfig 兼容格式
		var bodyMap map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&bodyMap); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		existingPasswords := make(map[string]string)
		p.mutex.RLock()
		for _, ep := range p.config.EncryptPaths {
			if ep == nil || strings.TrimSpace(ep.Path) == "" || strings.TrimSpace(ep.Password) == "" {
				continue
			}
			existingPasswords[strings.TrimSpace(ep.Path)] = ep.Password
		}
		p.mutex.RUnlock()
		keepPassword := func(rulePath, incoming string) string {
			if strings.TrimSpace(incoming) != "" {
				return incoming
			}
			if preserved, ok := existingPasswords[strings.TrimSpace(rulePath)]; ok {
				return preserved
			}
			return incoming
		}

		// 更新 ProbeOnDownload 如果存在
		if v, ok := bodyMap["probeOnDownload"]; ok {
			if b, ok2 := v.(bool); ok2 {
				p.mutex.Lock()
				p.config.ProbeOnDownload = b
				p.mutex.Unlock()
			}
		}
		if v, ok := bodyMap["probeStrategyTtlMinutes"]; ok {
			switch vt := v.(type) {
			case float64:
				p.mutex.Lock()
				p.config.ProbeStrategyTTLMinutes = int(vt)
				p.mutex.Unlock()
			case string:
				if val, err := strconv.Atoi(vt); err == nil {
					p.mutex.Lock()
					p.config.ProbeStrategyTTLMinutes = val
					p.mutex.Unlock()
				}
			}
		}
		if v, ok := bodyMap["probeStrategyStableThreshold"]; ok {
			switch vt := v.(type) {
			case float64:
				p.mutex.Lock()
				p.config.ProbeStrategyStableThreshold = int(vt)
				p.mutex.Unlock()
			case string:
				if val, err := strconv.Atoi(vt); err == nil {
					p.mutex.Lock()
					p.config.ProbeStrategyStableThreshold = val
					p.mutex.Unlock()
				}
			}
		}
		if v, ok := bodyMap["probeStrategyFailureThreshold"]; ok {
			switch vt := v.(type) {
			case float64:
				p.mutex.Lock()
				p.config.ProbeStrategyFailureThreshold = int(vt)
				p.mutex.Unlock()
			case string:
				if val, err := strconv.Atoi(vt); err == nil {
					p.mutex.Lock()
					p.config.ProbeStrategyFailureThreshold = val
					p.mutex.Unlock()
				}
			}
		}
		if v, ok := bodyMap["enableSizeMap"]; ok {
			if b, ok2 := v.(bool); ok2 {
				p.mutex.Lock()
				p.config.EnableSizeMap = b
				p.mutex.Unlock()
			}
		}
		if v, ok := bodyMap["sizeMapTtlMinutes"]; ok {
			switch vt := v.(type) {
			case float64:
				p.mutex.Lock()
				p.config.SizeMapTTL = int(vt)
				p.mutex.Unlock()
			case string:
				if val, err := strconv.Atoi(vt); err == nil {
					p.mutex.Lock()
					p.config.SizeMapTTL = val
					p.mutex.Unlock()
				}
			}
		}
		if v, ok := bodyMap["enableRangeCompatCache"]; ok {
			if b, ok2 := v.(bool); ok2 {
				p.mutex.Lock()
				p.config.EnableRangeCompatCache = b
				p.mutex.Unlock()
			}
		}
		if v, ok := bodyMap["rangeCompatTtlMinutes"]; ok {
			switch vt := v.(type) {
			case float64:
				p.mutex.Lock()
				p.config.RangeCompatTTL = int(vt)
				p.mutex.Unlock()
			case string:
				if val, err := strconv.Atoi(vt); err == nil {
					p.mutex.Lock()
					p.config.RangeCompatTTL = val
					p.mutex.Unlock()
				}
			}
		}
		if v, ok := bodyMap["rangeCompatMinFailures"]; ok {
			switch vt := v.(type) {
			case float64:
				p.mutex.Lock()
				p.config.RangeCompatMinFailures = int(vt)
				p.mutex.Unlock()
			case string:
				if val, err := strconv.Atoi(vt); err == nil {
					p.mutex.Lock()
					p.config.RangeCompatMinFailures = val
					p.mutex.Unlock()
				}
			}
		}
		if v, ok := bodyMap["rangeSkipMaxBytes"]; ok {
			switch vt := v.(type) {
			case float64:
				p.mutex.Lock()
				p.config.RangeSkipMaxBytes = int64(vt)
				p.mutex.Unlock()
			case string:
				if val, err := strconv.ParseInt(vt, 10, 64); err == nil {
					p.mutex.Lock()
					p.config.RangeSkipMaxBytes = val
					p.mutex.Unlock()
				}
			}
		}
		if v, ok := bodyMap["playFirstFallback"]; ok {
			if b, ok2 := v.(bool); ok2 {
				p.mutex.Lock()
				p.config.PlayFirstFallback = b
				p.mutex.Unlock()
			}
		}
		if v, ok := bodyMap["webdavNegativeCacheTtlMinutes"]; ok {
			switch vt := v.(type) {
			case float64:
				p.mutex.Lock()
				p.config.WebDAVNegativeCacheTTLMinutes = int(vt)
				p.mutex.Unlock()
			case string:
				if val, err := strconv.Atoi(vt); err == nil {
					p.mutex.Lock()
					p.config.WebDAVNegativeCacheTTLMinutes = val
					p.mutex.Unlock()
				}
			}
		}
		if v, ok := bodyMap["redirectCacheTtlMinutes"]; ok {
			switch vt := v.(type) {
			case float64:
				p.mutex.Lock()
				p.config.RedirectCacheTTLMinutes = int(vt)
				p.mutex.Unlock()
			case string:
				if val, err := strconv.Atoi(vt); err == nil {
					p.mutex.Lock()
					p.config.RedirectCacheTTLMinutes = val
					p.mutex.Unlock()
				}
			}
		}
		if v, ok := bodyMap["localSizeRetentionDays"]; ok {
			switch vt := v.(type) {
			case float64:
				p.mutex.Lock()
				p.config.LocalSizeRetentionDays = int(vt)
				p.mutex.Unlock()
			case string:
				if val, err := strconv.Atoi(vt); err == nil {
					p.mutex.Lock()
					p.config.LocalSizeRetentionDays = val
					p.mutex.Unlock()
				}
			}
		}
		if v, ok := bodyMap["localStrategyRetentionDays"]; ok {
			switch vt := v.(type) {
			case float64:
				p.mutex.Lock()
				p.config.LocalStrategyRetentionDays = int(vt)
				p.mutex.Unlock()
			case string:
				if val, err := strconv.Atoi(vt); err == nil {
					p.mutex.Lock()
					p.config.LocalStrategyRetentionDays = val
					p.mutex.Unlock()
				}
			}
		}
		if v, ok := bodyMap["enableParallelDecrypt"]; ok {
			if b, ok2 := v.(bool); ok2 {
				p.mutex.Lock()
				p.config.EnableParallelDecrypt = b
				p.mutex.Unlock()
			}
		}
		if v, ok := bodyMap["parallelDecryptConcurrency"]; ok {
			switch vt := v.(type) {
			case float64:
				p.mutex.Lock()
				p.config.ParallelDecryptConcurrency = int(vt)
				p.mutex.Unlock()
			case string:
				if val, err := strconv.Atoi(vt); err == nil {
					p.mutex.Lock()
					p.config.ParallelDecryptConcurrency = val
					p.mutex.Unlock()
				}
			}
		}
		if v, ok := bodyMap["streamBufferKb"]; ok {
			switch vt := v.(type) {
			case float64:
				p.mutex.Lock()
				p.config.StreamBufferKB = int(vt)
				p.mutex.Unlock()
			case string:
				if val, err := strconv.Atoi(vt); err == nil {
					p.mutex.Lock()
					p.config.StreamBufferKB = val
					p.mutex.Unlock()
				}
			}
			if v, ok := bodyMap["streamEngineVersion"]; ok {
				switch vt := v.(type) {
				case float64:
					p.mutex.Lock()
					p.config.StreamEngineVersion = int(vt)
					p.mutex.Unlock()
				case string:
					if val, err := strconv.Atoi(vt); err == nil {
						p.mutex.Lock()
						p.config.StreamEngineVersion = val
						p.mutex.Unlock()
					}
				}
			}
		}
		if v, ok := bodyMap["debugEnabled"]; ok {
			if b, ok2 := v.(bool); ok2 {
				p.mutex.Lock()
				p.config.DebugEnabled = b
				p.mutex.Unlock()
			}
		}
		if v, ok := bodyMap["debugLevel"]; ok {
			if s, ok2 := v.(string); ok2 {
				p.mutex.Lock()
				p.config.DebugLevel = strings.TrimSpace(s)
				p.mutex.Unlock()
			}
		}
		if v, ok := bodyMap["debugModules"]; ok {
			modules := make([]string, 0)
			switch vt := v.(type) {
			case []interface{}:
				for _, item := range vt {
					if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
						modules = append(modules, strings.TrimSpace(s))
					}
				}
			case []string:
				for _, s := range vt {
					if strings.TrimSpace(s) != "" {
						modules = append(modules, strings.TrimSpace(s))
					}
				}
			}
			p.mutex.Lock()
			p.config.DebugModules = modules
			p.mutex.Unlock()
		}
		if v, ok := bodyMap["debugMaskSensitive"]; ok {
			if b, ok2 := v.(bool); ok2 {
				p.mutex.Lock()
				p.config.DebugMaskSensitive = b
				p.mutex.Unlock()
			}
		}
		if v, ok := bodyMap["debugSampleRate"]; ok {
			switch vt := v.(type) {
			case float64:
				p.mutex.Lock()
				p.config.DebugSampleRate = int(vt)
				p.mutex.Unlock()
			case string:
				if val, err := strconv.Atoi(vt); err == nil {
					p.mutex.Lock()
					p.config.DebugSampleRate = val
					p.mutex.Unlock()
				}
			}
		}
		if v, ok := bodyMap["debugLogBodyBytes"]; ok {
			switch vt := v.(type) {
			case float64:
				p.mutex.Lock()
				p.config.DebugLogBodyBytes = int(vt)
				p.mutex.Unlock()
			case string:
				if val, err := strconv.Atoi(vt); err == nil {
					p.mutex.Lock()
					p.config.DebugLogBodyBytes = val
					p.mutex.Unlock()
				}
			}
		}
		if v, ok := bodyMap["enableDbExportSync"]; ok {
			if b, ok2 := v.(bool); ok2 {
				p.mutex.Lock()
				p.config.EnableDBExportSync = b
				p.mutex.Unlock()
			}
		}
		if v, ok := bodyMap["dbExportBaseUrl"]; ok {
			if s, ok2 := v.(string); ok2 {
				p.mutex.Lock()
				p.config.DBExportBaseURL = strings.TrimSpace(s)
				p.mutex.Unlock()
			}
		}
		if v, ok := bodyMap["dbExportSyncIntervalSeconds"]; ok {
			switch vt := v.(type) {
			case float64:
				p.mutex.Lock()
				p.config.DBExportSyncIntervalSeconds = int(vt)
				p.mutex.Unlock()
			case string:
				if val, err := strconv.Atoi(vt); err == nil {
					p.mutex.Lock()
					p.config.DBExportSyncIntervalSeconds = val
					p.mutex.Unlock()
				}
			}
		}
		if v, ok := bodyMap["dbExportAuthEnabled"]; ok {
			if b, ok2 := v.(bool); ok2 {
				p.mutex.Lock()
				p.config.DBExportAuthEnabled = b
				p.mutex.Unlock()
			}
		}
		if v, ok := bodyMap["dbExportUsername"]; ok {
			if s, ok2 := v.(string); ok2 {
				p.mutex.Lock()
				p.config.DBExportUsername = s
				p.mutex.Unlock()
			}
		}
		if v, ok := bodyMap["dbExportPassword"]; ok {
			if s, ok2 := v.(string); ok2 {
				p.mutex.Lock()
				if strings.TrimSpace(s) != "" {
					p.config.DBExportPassword = s
				}
				p.mutex.Unlock()
			}
		}

		// 更新 Alist / Proxy 基本配置（如果前端提交）
		if v, ok := bodyMap["alistHost"]; ok {
			if s, ok2 := v.(string); ok2 {
				p.mutex.Lock()
				p.config.AlistHost = s
				p.mutex.Unlock()
			}
		}
		if v, ok := bodyMap["alistPort"]; ok {
			switch vt := v.(type) {
			case float64:
				p.mutex.Lock()
				p.config.AlistPort = int(vt)
				p.mutex.Unlock()
			case string:
				if port, err := strconv.Atoi(vt); err == nil {
					p.mutex.Lock()
					p.config.AlistPort = port
					p.mutex.Unlock()
				}
			}
		}
		if v, ok := bodyMap["alistHttps"]; ok {
			if b, ok2 := v.(bool); ok2 {
				p.mutex.Lock()
				p.config.AlistHttps = b
				p.mutex.Unlock()
			}
		}
		if v, ok := bodyMap["https"]; ok {
			if b, ok2 := v.(bool); ok2 {
				p.mutex.Lock()
				p.config.AlistHttps = b
				p.mutex.Unlock()
			}
		}
		if v, ok := bodyMap["proxyPort"]; ok {
			switch vt := v.(type) {
			case float64:
				p.mutex.Lock()
				p.config.ProxyPort = int(vt)
				p.mutex.Unlock()
			case string:
				if port, err := strconv.Atoi(vt); err == nil {
					p.mutex.Lock()
					p.config.ProxyPort = port
					p.mutex.Unlock()
				}
			}
		}
		if v, ok := bodyMap["upstreamTimeoutSeconds"]; ok {
			switch vt := v.(type) {
			case float64:
				p.mutex.Lock()
				p.config.UpstreamTimeoutSeconds = int(vt)
				p.mutex.Unlock()
			case string:
				if val, err := strconv.Atoi(vt); err == nil {
					p.mutex.Lock()
					p.config.UpstreamTimeoutSeconds = val
					p.mutex.Unlock()
				}
			}
		}
		if v, ok := bodyMap["probeTimeoutSeconds"]; ok {
			switch vt := v.(type) {
			case float64:
				p.mutex.Lock()
				p.config.ProbeTimeoutSeconds = int(vt)
				p.mutex.Unlock()
			case string:
				if val, err := strconv.Atoi(vt); err == nil {
					p.mutex.Lock()
					p.config.ProbeTimeoutSeconds = val
					p.mutex.Unlock()
				}
			}
		}
		if v, ok := bodyMap["probeBudgetSeconds"]; ok {
			switch vt := v.(type) {
			case float64:
				p.mutex.Lock()
				p.config.ProbeBudgetSeconds = int(vt)
				p.mutex.Unlock()
			case string:
				if val, err := strconv.Atoi(vt); err == nil {
					p.mutex.Lock()
					p.config.ProbeBudgetSeconds = val
					p.mutex.Unlock()
				}
			}
		}
		if v, ok := bodyMap["upstreamBackoffSeconds"]; ok {
			switch vt := v.(type) {
			case float64:
				p.mutex.Lock()
				p.config.UpstreamBackoffSeconds = int(vt)
				p.mutex.Unlock()
			case string:
				if val, err := strconv.Atoi(vt); err == nil {
					p.mutex.Lock()
					p.config.UpstreamBackoffSeconds = val
					p.mutex.Unlock()
				}
			}
		}
		if v, ok := bodyMap["enableLocalBypass"]; ok {
			if b, ok2 := v.(bool); ok2 {
				p.mutex.Lock()
				p.config.EnableLocalBypass = b
				p.mutex.Unlock()
			}
		}
		if v, ok := bodyMap["routingUnmatchedDefault"]; ok {
			if s, ok2 := v.(string); ok2 {
				p.mutex.Lock()
				p.config.RoutingUnmatchedDefault = normalizeRoutingUnmatchedDefault(s)
				p.mutex.Unlock()
			}
		}
		if v, ok := bodyMap["providerCatalogEnabled"]; ok {
			if b, ok2 := v.(bool); ok2 {
				p.mutex.Lock()
				p.config.ProviderCatalogEnabled = b
				p.mutex.Unlock()
			}
		}
		if v, ok := bodyMap["providerCatalogTtlMinutes"]; ok {
			switch vt := v.(type) {
			case float64:
				p.mutex.Lock()
				p.config.ProviderCatalogTTLMinutes = int(vt)
				p.mutex.Unlock()
			case string:
				if val, err := strconv.Atoi(vt); err == nil {
					p.mutex.Lock()
					p.config.ProviderCatalogTTLMinutes = val
					p.mutex.Unlock()
				}
			}
		}
		if v, ok := bodyMap["providerCatalogBootstrapOnStart"]; ok {
			if b, ok2 := v.(bool); ok2 {
				p.mutex.Lock()
				p.config.ProviderCatalogBootstrapOnStart = b
				p.mutex.Unlock()
			}
		}

		// 如果前端直接提交 encryptPaths（来自页面保存路径）
		if v, ok := bodyMap["encryptPaths"]; ok {
			if arr, ok2 := v.([]interface{}); ok2 {
				var newPaths []*EncryptPath
				for _, item := range arr {
					if m, ok3 := item.(map[string]interface{}); ok3 {
						pathStr, _ := m["path"].(string)
						pwd, _ := m["password"].(string)
						pwd = keepPassword(pathStr, pwd)
						encTypeStr, _ := m["encType"].(string)
						encName, _ := m["encName"].(bool)
						encSuffix, _ := m["encSuffix"].(string)
						enable, okEnable := m["enable"].(bool)
						if !okEnable {
							enable = true
						}
						var encType EncryptionType
						switch encTypeStr {
						case "aes-ctr", "aesctr":
							encType = EncTypeAESCTR
						case "rc4md5", "rc4":
							encType = EncTypeRC4
						case "mix":
							encType = EncTypeMix
						default:
							encType = EncryptionType(encTypeStr)
						}
						newPaths = append(newPaths, &EncryptPath{
							Path:      pathStr,
							Password:  pwd,
							EncType:   encType,
							EncName:   encName,
							EncSuffix: NormalizeEncSuffix(encSuffix),
							Enable:    enable,
						})
					}
				}
				// assign and compile regex using safe wildcard->regex conversion
				wildcardToRegex := func(raw string) string {
					a := "__AST__"
					q := "__QST__"
					tmp := strings.ReplaceAll(raw, "*", a)
					tmp = strings.ReplaceAll(tmp, "?", q)
					tmp = regexp.QuoteMeta(tmp)
					tmp = strings.ReplaceAll(tmp, a, ".*")
					tmp = strings.ReplaceAll(tmp, q, ".")
					return tmp
				}

				p.mutex.Lock()
				p.config.EncryptPaths = newPaths
				for _, ep := range p.config.EncryptPaths {
					if ep.Path == "" {
						continue
					}
					ep.EncSuffix = NormalizeEncSuffix(ep.EncSuffix)
					raw := ep.Path
					if strings.HasSuffix(raw, "/*") {
						base := strings.TrimSuffix(raw, "/*")
						converted := wildcardToRegex(base)
						var pattern string
						if strings.HasPrefix(base, "/") {
							pattern = "^" + converted + "(/.*)?$"
						} else {
							pattern = "^/?" + converted + "(/.*)?$"
						}
						if reg, err := regexp.Compile(pattern); err == nil {
							ep.regex = reg
						}
						continue
					}

					converted := wildcardToRegex(raw)
					var pattern string
					if strings.HasPrefix(raw, "^") {
						pattern = converted
					} else if strings.HasPrefix(raw, "/") {
						pattern = "^" + converted + "(/.*)?$"
					} else {
						pattern = "^/?" + converted + "(/.*)?$"
					}
					if reg, err := regexp.Compile(pattern); err == nil {
						ep.regex = reg
					}
				}
				p.mutex.Unlock()
			}
		}

		// 兼容旧的 saveAlistConfig 格式（passwdList 等）
		if v, ok := bodyMap["passwdList"]; ok {
			if arr, ok2 := v.([]interface{}); ok2 {
				var newPaths []*EncryptPath
				for _, item := range arr {
					if m, ok3 := item.(map[string]interface{}); ok3 {
						// encPath may be array or string
						if epv, ok4 := m["encPath"]; ok4 {
							switch vv := epv.(type) {
							case string:
								parts := strings.Split(vv, ",")
								for _, pstr := range parts {
									pstr = strings.TrimSpace(pstr)
									if pstr == "" {
										continue
									}
									pwd, _ := m["password"].(string)
									pwd = keepPassword(pstr, pwd)
									encTypeStr, _ := m["encType"].(string)
									encName, _ := m["encName"].(bool)
									encSuffix, _ := m["encSuffix"].(string)
									var encType EncryptionType
									switch encTypeStr {
									case "aesctr":
										encType = EncTypeAESCTR
									case "rc4":
										encType = EncTypeRC4
									case "mix":
										encType = EncTypeMix
									default:
										encType = EncryptionType(encTypeStr)
									}
									newPaths = append(newPaths, &EncryptPath{
										Path:      pstr,
										Password:  pwd,
										EncType:   encType,
										EncName:   encName,
										EncSuffix: NormalizeEncSuffix(encSuffix),
										Enable:    true,
									})
								}
							case []interface{}:
								for _, epp := range vv {
									if s, ok5 := epp.(string); ok5 {
										pwd, _ := m["password"].(string)
										pwd = keepPassword(s, pwd)
										encTypeStr, _ := m["encType"].(string)
										encName, _ := m["encName"].(bool)
										encSuffix, _ := m["encSuffix"].(string)
										var encType EncryptionType
										switch encTypeStr {
										case "aesctr":
											encType = EncTypeAESCTR
										case "rc4":
											encType = EncTypeRC4
										case "mix":
											encType = EncTypeMix
										default:
											encType = EncryptionType(encTypeStr)
										}
										newPaths = append(newPaths, &EncryptPath{
											Path:      s,
											Password:  pwd,
											EncType:   encType,
											EncName:   encName,
											EncSuffix: NormalizeEncSuffix(encSuffix),
											Enable:    true,
										})
									}
								}
							}
						}
					}
				}
				// assign and compile regex using safe wildcard->regex conversion (same as above)
				wildcardToRegex := func(raw string) string {
					a := "__AST__"
					q := "__QST__"
					tmp := strings.ReplaceAll(raw, "*", a)
					tmp = strings.ReplaceAll(tmp, "?", q)
					tmp = regexp.QuoteMeta(tmp)
					tmp = strings.ReplaceAll(tmp, a, ".*")
					tmp = strings.ReplaceAll(tmp, q, ".")
					return tmp
				}

				p.mutex.Lock()
				p.config.EncryptPaths = newPaths
				for _, ep := range p.config.EncryptPaths {
					if ep.Path == "" {
						continue
					}
					ep.EncSuffix = NormalizeEncSuffix(ep.EncSuffix)
					raw := ep.Path
					if strings.HasSuffix(raw, "/*") {
						base := strings.TrimSuffix(raw, "/*")
						converted := wildcardToRegex(base)
						var pattern string
						if strings.HasPrefix(base, "/") {
							pattern = "^" + converted + "(/.*)?$"
						} else {
							pattern = "^/?" + converted + "(/.*)?$"
						}
						if reg, err := regexp.Compile(pattern); err == nil {
							ep.regex = reg
						}
						continue
					}
					converted := wildcardToRegex(raw)
					var pattern string
					if strings.HasPrefix(raw, "^") {
						pattern = converted
					} else if strings.HasPrefix(raw, "/") {
						pattern = "^" + converted + "(/.*)?$"
					} else {
						pattern = "^/?" + converted + "(/.*)?$"
					}
					if reg, err := regexp.Compile(pattern); err == nil {
						ep.regex = reg
					}
				}
				p.mutex.Unlock()
			}
		}

		p.mutex.Lock()
		if p.config.RangeCompatMinFailures <= 0 {
			p.config.RangeCompatMinFailures = 2
		}
		if p.config.RangeSkipMaxBytes <= 0 {
			p.config.RangeSkipMaxBytes = defaultRangeSkipMaxBytes
		}
		if p.config.ParallelDecryptConcurrency <= 0 {
			p.config.ParallelDecryptConcurrency = 8
		}
		if p.config.StreamBufferKB <= 0 {
			p.config.StreamBufferKB = 1024
		}
		if p.config.StreamEngineVersion <= 0 {
			p.config.StreamEngineVersion = defaultStreamEngineVersion
		}
		if p.config.RedirectCacheTTLMinutes <= 0 {
			p.config.RedirectCacheTTLMinutes = int(redirectCacheTTL / time.Minute)
		}
		if p.config.DebugLevel == "" {
			p.config.DebugLevel = "info"
		}
		if p.config.DebugSampleRate <= 0 || p.config.DebugSampleRate > 100 {
			p.config.DebugSampleRate = 100
		}
		applyLearningDefaults(p.config)
		p.mutex.Unlock()
		if err := p.persistConfigSnapshot(); err != nil {
			log.Warnf("[%s] Failed to persist config snapshot: %v", internal.TagConfig, err)
		} else {
			p.mutex.RLock()
			rangeEnabled := p.config != nil && p.config.EnableRangeCompatCache
			rangeTTL := 0
			rangeMinFailures := 0
			rangeSkipMaxBytes := int64(0)
			parallelEnabled := p.config != nil && p.config.EnableParallelDecrypt
			parallelConc := 0
			streamBufferKB := 0
			if p.config != nil {
				rangeTTL = p.config.RangeCompatTTL
				rangeMinFailures = p.config.RangeCompatMinFailures
				rangeSkipMaxBytes = p.config.RangeSkipMaxBytes
				parallelConc = p.config.ParallelDecryptConcurrency
				streamBufferKB = p.config.StreamBufferKB
			}
			p.mutex.RUnlock()
			p.debugf("config", "persisted advanced config: rangeCompat=%v ttl=%d minFailures=%d skipMaxBytes=%d parallel=%v parallelConc=%d streamBufferKb=%d",
				rangeEnabled,
				rangeTTL,
				rangeMinFailures,
				rangeSkipMaxBytes,
				parallelEnabled,
				parallelConc,
				streamBufferKB,
			)
		}

		json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "message": "Config updated"})
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// handleRedirectLegacy 保留历史执行链，供 V2 orchestrator 调用
func (p *ProxyServer) handleRedirectLegacy(w http.ResponseWriter, r *http.Request) {
	if p.shouldFastFailUpstream() {
		_, remain, reason := p.upstreamBackoffState()
		retryAfter := int(remain.Seconds())
		if retryAfter < 1 {
			retryAfter = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		http.Error(w, "upstream temporarily unavailable: "+reason, http.StatusServiceUnavailable)
		return
	}
	// 获取重定向 key
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 3 {
		http.Error(w, "Invalid redirect key", http.StatusBadRequest)
		return
	}
	key := parts[2]

	// 从缓存获取重定向信息（使用带 TTL 的缓存方法）
	info, ok := p.loadRedirectCache(key)
	if !ok {
		http.Error(w, "Redirect key not found or expired", http.StatusNotFound)
		return
	}

	ctx := r.Context()
	log.Infof("%s handleRedirect: key=%s, fileSize=%d, encType=%s, url=%s",
		internal.LogPrefix(ctx, internal.TagDownload), key, info.FileSize, info.PasswdInfo.EncType, info.RedirectURL)

	// 获取 Range 头
	clientRangeHeader := r.Header.Get("Range")
	upstreamRangeHeader := clientRangeHeader
	var startPos int64 = 0
	if parsedStart, ok := parseRangeStart(clientRangeHeader); ok {
		startPos = parsedStart
		log.Infof("%s handleRedirect: Range header=%s, startPos=%d", internal.LogPrefix(ctx, internal.TagDownload), clientRangeHeader, startPos)
	}

	rangeSuppressedByStrategy := false
	if clientRangeHeader != "" && startPos < rangePreferUpstreamStartBytes {
		if strategy, ok := p.lookupLocalStrategy(info.RedirectURL, info.OriginalURL); ok && strategy == StreamStrategyChunked {
			rangeSuppressedByStrategy = true
		}
	}
	if clientRangeHeader != "" && (rangeSuppressedByStrategy || p.shouldSkipRange(info.RedirectURL, info.OriginalURL)) {
		upstreamRangeHeader = ""
	}

	// 创建到实际资源的请求
	req, err := http.NewRequestWithContext(r.Context(), "GET", info.RedirectURL, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	p.applyRoutingHints(req, info.Provider, info.Driver)

	// 复制请求头，但排除一些可能导致问题的头
	for key, values := range r.Header {
		lowerKey := strings.ToLower(key)
		// 不复制 Host 头
		if lowerKey == "host" {
			continue
		}
		// 阿里云盘不允许 referer，会返回 403
		if lowerKey == "referer" {
			continue
		}
		// authorization 是 alist 网页版的 token，不是存储的，删除它可以修复天翼云等无法获取资源的问题
		if lowerKey == "authorization" {
			continue
		}
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	if upstreamRangeHeader == "" {
		req.Header.Del("Range")
	} else {
		req.Header.Set("Range", upstreamRangeHeader)
	}

	// 百度云盘需要特殊的 User-Agent
	if strings.Contains(info.RedirectURL, "baidupcs.com") {
		req.Header.Set("User-Agent", "pan.baidu.com")
	}

	// 发送请求
	// Use streamClient for downloads to avoid client-side timeouts for large/long streams
	resp, err := p.streamClient.Do(req)
	if err != nil {
		log.Errorf("%s handleRedirect: request failed: %v", internal.LogPrefix(ctx, internal.TagDownload), err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	p.debugf("redirect", "%s handleRedirect: response status=%d, content-length=%s",
		internal.LogPrefix(ctx, internal.TagDownload), resp.StatusCode, resp.Header.Get("Content-Length"))

	statusCode := resp.StatusCode
	if resp.StatusCode == http.StatusOK && resp.Header.Get("Content-Range") != "" {
		statusCode = http.StatusPartialContent
	}
	upstreamIsRange := resp.StatusCode == http.StatusPartialContent || resp.Header.Get("Content-Range") != ""
	if clientRangeHeader != "" && !upstreamIsRange {
		p.markRangeIncompatible(info.RedirectURL, info.OriginalURL)
	} else if clientRangeHeader != "" && upstreamIsRange {
		p.markRangeCompatible(info.RedirectURL, info.OriginalURL)
	}

	// 复制响应头
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// 下载时解密文件名（修改 Content-Disposition，与 alist-encrypt 一致）
	lastUrl := r.URL.Query().Get("lastUrl")
	if lastUrl != "" && info.PasswdInfo != nil && info.PasswdInfo.EncName {
		if decoded, err := url.QueryUnescape(lastUrl); err == nil {
			lastUrl = decoded
		}
		fileName := path.Base(lastUrl)
		if decoded, err := url.PathUnescape(fileName); err == nil {
			fileName = decoded
		}
		ext := path.Ext(fileName)
		baseName := strings.TrimSuffix(fileName, ext)
		decryptedName := DecodeName(info.PasswdInfo.Password, info.PasswdInfo.EncType, baseName)
		if decryptedName != "" {
			cd := w.Header().Get("Content-Disposition")
			if cd != "" {
				cd = regexp.MustCompile(`filename\*?=[^;]*;?\s*`).ReplaceAllString(cd, "")
			}
			if cd == "" {
				cd = "attachment; "
			} else if !strings.HasSuffix(cd, "; ") && !strings.HasSuffix(cd, ";") {
				cd += "; "
			}
			w.Header().Set("Content-Disposition", cd+fmt.Sprintf("filename*=UTF-8''%s", url.PathEscape(decryptedName)))
			log.Debugf("%s Decrypted filename in redirect Content-Disposition: %s -> %s", internal.LogPrefix(ctx, internal.TagDecrypt), fileName, decryptedName)
		}
	}

	// 检查是否需要解密
	decode := r.URL.Query().Get("decode")
	if decode != "0" && info.PasswdInfo != nil {
		fileSize := info.FileSize

		// 如果 fileSize 为 0，尝试多种方式获取（修复 WebDAV 播放问题）
		if fileSize == 0 {
			if size, ok := p.lookupLocalSize(info.RedirectURL, info.OriginalURL); ok {
				fileSize = size
			}
		}
		if fileSize == 0 {
			// 1. 首先尝试从缓存中查找（使用多种路径变体）
			if info.OriginalURL != "" {
				origPath := info.OriginalURL
				if u, err := url.Parse(info.OriginalURL); err == nil {
					origPath = u.Path
				}
				// 尝试多种路径变体查找缓存
				pathVariants := []string{
					origPath,
					strings.TrimPrefix(origPath, "/dav"),
					"/dav" + strings.TrimPrefix(origPath, "/dav"),
				}
				for _, cachePath := range pathVariants {
					if cachePath == "" {
						continue
					}
					if cached, ok := p.loadFileCache(cachePath); ok && !cached.IsDir && cached.Size > 0 {
						fileSize = cached.Size
						log.Infof("%s handleRedirect: got fileSize from cache (%s): %d", internal.LogPrefix(ctx, internal.TagFileSize), cachePath, fileSize)
						break
					}
				}
			}

			// 2. 尝试从 Content-Range 获取总大小 (格式: bytes start-end/total)
			if fileSize == 0 {
				if cr := resp.Header.Get("Content-Range"); cr != "" {
					if idx := strings.LastIndex(cr, "/"); idx != -1 {
						totalStr := cr[idx+1:]
						if totalStr != "*" {
							if total, err := strconv.ParseInt(totalStr, 10, 64); err == nil && total > 0 {
								fileSize = total
								log.Infof("%s handleRedirect: got fileSize from Content-Range: %d", internal.LogPrefix(ctx, internal.TagFileSize), fileSize)
							}
						}
					}
				}
			}

			// 3. 如果 Content-Range 没有总大小，尝试 Content-Length（仅当没有 Range 请求时有效）
			if fileSize == 0 && clientRangeHeader == "" {
				if cl := resp.Header.Get("Content-Length"); cl != "" {
					if parsedSize, err := strconv.ParseInt(cl, 10, 64); err == nil && parsedSize > 0 {
						fileSize = parsedSize
						log.Infof("%s handleRedirect: using Content-Length as fileSize: %d", internal.LogPrefix(ctx, internal.TagFileSize), fileSize)
					}
				}
			}

			// 4. 尝试通过 WebDAV PROPFIND 获取文件大小
			if fileSize == 0 && info.OriginalURL != "" {
				origPath := info.OriginalURL
				if u, err := url.Parse(info.OriginalURL); err == nil {
					origPath = u.Path
				}
				// 构建 WebDAV URL
				webdavPath := origPath
				if !strings.HasPrefix(webdavPath, "/dav") {
					webdavPath = "/dav" + webdavPath
				}
				webdavURL := p.getAlistURL() + webdavPath
				if size := p.fetchWebDAVFileSizeWithPath(webdavURL, info.Headers, info.PasswdInfo.Path); size > 0 {
					fileSize = size
					log.Infof("%s handleRedirect: got fileSize from WebDAV PROPFIND: %d", internal.LogPrefix(ctx, internal.TagFileSize), fileSize)
				}
			}

			// 5. 如果仍然为 0，强制探测远程文件大小（加密文件没有 fileSize 无法解密）
			if fileSize == 0 {
				probed := p.forceProbeRemoteFileSizeWithPath(info.RedirectURL, req.Header, info.PasswdInfo.Path)
				if probed > 0 {
					fileSize = probed
					log.Infof("%s handleRedirect: probed remote fileSize=%d", internal.LogPrefix(ctx, internal.TagFileSize), fileSize)
					// 重新请求以获取新鲜的流
					resp.Body.Close()
					req2, _ := http.NewRequestWithContext(r.Context(), "GET", info.RedirectURL, nil)
					p.applyRoutingHints(req2, info.Provider, info.Driver)
					for key, values := range r.Header {
						lowerKey := strings.ToLower(key)
						if lowerKey == "host" || lowerKey == "referer" || lowerKey == "authorization" {
							continue
						}
						for _, value := range values {
							req2.Header.Add(key, value)
						}
					}
					// 百度云盘需要特殊的 User-Agent
					if strings.Contains(info.RedirectURL, "baidupcs.com") {
						req2.Header.Set("User-Agent", "pan.baidu.com")
					}
					resp, err = p.streamClient.Do(req2)
					if err != nil {
						http.Error(w, err.Error(), http.StatusBadGateway)
						return
					}
					defer resp.Body.Close()
					// 重新复制响应头
					for key := range w.Header() {
						w.Header().Del(key)
					}
					for key, values := range resp.Header {
						for _, value := range values {
							w.Header().Add(key, value)
						}
					}
				}
			}
		}

		if clientRangeHeader != "" && !upstreamIsRange && startPos > 0 && fileSize > 0 {
			// Upstream ignored Range; serve a local range with correct headers.
			endPos := fileSize - 1
			if endPos >= startPos {
				statusCode = http.StatusPartialContent
				w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", startPos, endPos, fileSize))
				w.Header().Set("Content-Length", strconv.FormatInt(fileSize-startPos, 10))
				w.Header().Set("Accept-Ranges", "bytes")
			} else {
				startPos = 0
			}
		}

		observedStrategy := StreamStrategyChunked
		if upstreamIsRange {
			observedStrategy = StreamStrategyRange
		}
		p.recordLocalObservation(info.RedirectURL, info.OriginalURL, fileSize, resp.StatusCode, resp.Header.Get("Content-Type"), observedStrategy)

		// 如果仍然为 0，跳过解密直接代理（记录更详细的警告信息）
		if fileSize == 0 {
			log.Warnf("%s handleRedirect: fileSize is 0, skipping decryption. originalURL=%s, redirectURL=%s", internal.LogPrefix(ctx, internal.TagDownload), info.OriginalURL, info.RedirectURL)
			w.WriteHeader(statusCode)
			copyWithBuffer(w, resp.Body)
			return
		}

		// 创建解密器
		encryptor, err := NewFlowEncryptor(info.PasswdInfo.Password, info.PasswdInfo.EncType, fileSize)
		if err != nil {
			log.Errorf("%s handleRedirect: failed to create encryptor: %v", internal.LogPrefix(ctx, internal.TagDecrypt), err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		upstreamIsRange := resp.StatusCode == http.StatusPartialContent || resp.Header.Get("Content-Range") != ""
		if clientRangeHeader != "" && !upstreamIsRange {
			p.markRangeIncompatible(info.RedirectURL, info.OriginalURL)
		} else if clientRangeHeader != "" && upstreamIsRange {
			p.markRangeCompatible(info.RedirectURL, info.OriginalURL)
		}
		if startPos > 0 {
			if upstreamIsRange {
				encryptor.SetPosition(startPos)
			} else {
				if startPos > p.rangeSkipMaxBytes() {
					log.Warnf("%s handleRedirect: skip exceeds limit start=%d limit=%d upstreamRange=%v status=%d contentRange=%q",
						internal.LogPrefix(ctx, internal.TagDecrypt), startPos, p.rangeSkipMaxBytes(), upstreamIsRange, resp.StatusCode, resp.Header.Get("Content-Range"))
					http.Error(w, "range skip exceeds limit", http.StatusRequestedRangeNotSatisfiable)
					return
				}
				if _, err := io.CopyN(io.Discard, resp.Body, startPos); err != nil {
					log.Warnf("%s handleRedirect: skip encrypted prefix failed: %v", internal.LogPrefix(ctx, internal.TagDecrypt), err)
				}
				encryptor.SetPosition(startPos)
			}
		}

		// 创建解密读取器
		decryptReader := NewDecryptReader(resp.Body, encryptor)

		w.WriteHeader(statusCode)
		copyWithBuffer(w, decryptReader)
	} else {
		w.WriteHeader(statusCode)
		copyWithBuffer(w, resp.Body)
	}
}

func writeJSONScalarToken(w *bufio.Writer, tok interface{}) error {
	b, err := json.Marshal(tok)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func writeJSONStringToken(w *bufio.Writer, s string) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func copyJSONValue(dec *json.Decoder, w *bufio.Writer) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); ok {
		switch d {
		case '{':
			if _, err := w.WriteString("{"); err != nil {
				return err
			}
			first := true
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := keyTok.(string)
				if !ok {
					return errors.New("invalid object key token")
				}
				if !first {
					if _, err := w.WriteString(","); err != nil {
						return err
					}
				}
				first = false
				if err := writeJSONStringToken(w, key); err != nil {
					return err
				}
				if _, err := w.WriteString(":"); err != nil {
					return err
				}
				if err := copyJSONValue(dec, w); err != nil {
					return err
				}
			}
			endTok, err := dec.Token()
			if err != nil {
				return err
			}
			endDelim, ok := endTok.(json.Delim)
			if !ok || endDelim != '}' {
				return errors.New("invalid object end token")
			}
			_, err = w.WriteString("}")
			return err
		case '[':
			if _, err := w.WriteString("["); err != nil {
				return err
			}
			first := true
			for dec.More() {
				if !first {
					if _, err := w.WriteString(","); err != nil {
						return err
					}
				}
				first = false
				if err := copyJSONValue(dec, w); err != nil {
					return err
				}
			}
			endTok, err := dec.Token()
			if err != nil {
				return err
			}
			endDelim, ok := endTok.(json.Delim)
			if !ok || endDelim != ']' {
				return errors.New("invalid array end token")
			}
			_, err = w.WriteString("]")
			return err
		default:
			return errors.New("unexpected json delimiter")
		}
	}
	return writeJSONScalarToken(w, tok)
}

func (p *ProxyServer) streamRewriteFsListResponse(w http.ResponseWriter, body io.Reader, dirPath string, parentEncPath *EncryptPath) ([]string, error) {
	dec := json.NewDecoder(body)
	bw := bufio.NewWriterSize(w, mediumBufferSize)
	prefetchDirs := make([]string, 0, 8)

	startTok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	startDelim, ok := startTok.(json.Delim)
	if !ok || startDelim != '{' {
		return nil, errors.New("invalid fs list response: expected object")
	}
	if _, err := bw.WriteString("{"); err != nil {
		return nil, err
	}

	firstField := true
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, errors.New("invalid top-level key token")
		}
		if !firstField {
			if _, err := bw.WriteString(","); err != nil {
				return nil, err
			}
		}
		firstField = false
		if err := writeJSONStringToken(bw, key); err != nil {
			return nil, err
		}
		if _, err := bw.WriteString(":"); err != nil {
			return nil, err
		}

		if key != "data" {
			if err := copyJSONValue(dec, bw); err != nil {
				return nil, err
			}
			continue
		}

		nextTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		nextDelim, isDelim := nextTok.(json.Delim)
		if !isDelim || nextDelim != '{' {
			if err := writeJSONScalarToken(bw, nextTok); err != nil {
				return nil, err
			}
			continue
		}
		if _, err := bw.WriteString("{"); err != nil {
			return nil, err
		}

		firstDataField := true
		for dec.More() {
			dataKeyTok, err := dec.Token()
			if err != nil {
				return nil, err
			}
			dataKey, ok := dataKeyTok.(string)
			if !ok {
				return nil, errors.New("invalid data key token")
			}
			if !firstDataField {
				if _, err := bw.WriteString(","); err != nil {
					return nil, err
				}
			}
			firstDataField = false
			if err := writeJSONStringToken(bw, dataKey); err != nil {
				return nil, err
			}
			if _, err := bw.WriteString(":"); err != nil {
				return nil, err
			}

			if dataKey != "content" {
				if err := copyJSONValue(dec, bw); err != nil {
					return nil, err
				}
				continue
			}

			contentTok, err := dec.Token()
			if err != nil {
				return nil, err
			}
			contentDelim, isContentDelim := contentTok.(json.Delim)
			if !isContentDelim || contentDelim != '[' {
				if err := writeJSONScalarToken(bw, contentTok); err != nil {
					return nil, err
				}
				continue
			}
			if _, err := bw.WriteString("["); err != nil {
				return nil, err
			}

			firstItem := true
			for dec.More() {
				var item map[string]interface{}
				if err := dec.Decode(&item); err != nil {
					return nil, err
				}
				name, _ := item["name"].(string)
				size, _ := item["size"].(float64)
				isDir, _ := item["is_dir"].(bool)

				filePath := path.Join(dirPath, name)
				if apiPath, ok := item["path"].(string); ok && apiPath != "" {
					filePath = apiPath
				}

				p.storeFileCache(filePath, &FileInfo{
					Name:  name,
					Size:  int64(size),
					IsDir: isDir,
					Path:  filePath,
				})

				fileEncPath := p.findEncryptPath(filePath)
				if parentEncPath != nil && isDir && len(prefetchDirs) < encryptedPrefetchMaxDirs {
					prefetchDirs = append(prefetchDirs, filePath)
				}
				if fileEncPath != nil && fileEncPath.EncName && !isDir {
					showName := convertShowNameByRule(fileEncPath, name)
					item["name"] = showName
					normalizeDecryptedMediaFields(item, showName)
				}
				delete(item, "path")

				if !firstItem {
					if _, err := bw.WriteString(","); err != nil {
						return nil, err
					}
				}
				firstItem = false
				itemBytes, err := json.Marshal(item)
				if err != nil {
					return nil, err
				}
				if _, err := bw.Write(itemBytes); err != nil {
					return nil, err
				}
			}
			endContentTok, err := dec.Token()
			if err != nil {
				return nil, err
			}
			endContentDelim, ok := endContentTok.(json.Delim)
			if !ok || endContentDelim != ']' {
				return nil, errors.New("invalid content array end token")
			}
			if _, err := bw.WriteString("]"); err != nil {
				return nil, err
			}
		}

		endDataTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		endDataDelim, ok := endDataTok.(json.Delim)
		if !ok || endDataDelim != '}' {
			return nil, errors.New("invalid data object end token")
		}
		if _, err := bw.WriteString("}"); err != nil {
			return nil, err
		}
	}

	endTok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	endDelim, ok := endTok.(json.Delim)
	if !ok || endDelim != '}' {
		return nil, errors.New("invalid fs list response end token")
	}
	if _, err := bw.WriteString("}"); err != nil {
		return nil, err
	}
	if err := bw.Flush(); err != nil {
		return nil, err
	}
	return prefetchDirs, nil
}

// parallelDecryptFileNames 并行解密文件名（旧版本，使用统一的 encPath）
func (p *ProxyServer) parallelDecryptFileNames(tasks []fileDecryptTask, encPath *EncryptPath) {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, p.parallelDecryptLimit())

	for _, task := range tasks {
		wg.Add(1)
		go func(t fileDecryptTask) {
			defer wg.Done()
			semaphore <- struct{}{}        // 获取信号量
			defer func() { <-semaphore }() // 释放信号量

			showName := convertShowNameByRule(encPath, t.name)
			if showName != t.name && !strings.HasPrefix(showName, "orig_") {
				log.Debugf("[%s] Parallel decrypt filename: %s -> %s", internal.TagDecrypt, t.name, showName)
			}
			t.fileMap["name"] = showName
			normalizeDecryptedMediaFields(t.fileMap, showName)
			if _, ok := t.fileMap["path"].(string); (!ok || t.fileMap["path"] == "") && t.filePath != "" {
				t.fileMap["path"] = path.Join(path.Dir(t.filePath), showName)
			}
		}(task)
	}
	wg.Wait()
}

// parallelDecryptFileNamesV2 并行解密文件名（新版本，每个文件使用自己的 encPath）
func (p *ProxyServer) parallelDecryptFileNamesV2(tasks []fileDecryptTask) {
	workers := p.parallelDecryptLimit()
	if workers <= 0 {
		workers = 1
	}
	if workers > len(tasks) {
		workers = len(tasks)
	}
	if workers <= 0 {
		return
	}

	taskCh := make(chan fileDecryptTask, workers*2)
	var wg sync.WaitGroup
	workerFn := func() {
		defer wg.Done()
		for t := range taskCh {
			if t.encPath == nil {
				continue
			}
			showName := convertShowNameByRule(t.encPath, t.name)
			if showName != t.name && !strings.HasPrefix(showName, "orig_") {
				log.Debugf("[%s] Parallel decrypt filename: %s -> %s", internal.TagDecrypt, t.name, showName)
			}
			t.fileMap["name"] = showName
			normalizeDecryptedMediaFields(t.fileMap, showName)
			if _, ok := t.fileMap["path"].(string); (!ok || t.fileMap["path"] == "") && t.filePath != "" {
				t.fileMap["path"] = path.Join(path.Dir(t.filePath), showName)
			}
		}
	}
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go workerFn()
	}
	for _, task := range tasks {
		taskCh <- task
	}
	close(taskCh)
	wg.Wait()
}

// fileDecryptTask 文件解密任务
type fileDecryptTask struct {
	index    int
	fileMap  map[string]interface{}
	name     string
	filePath string
	encPath  *EncryptPath // 每个文件的加密配置
}

// normalizeDecryptedMediaFields keeps preview-related fields aligned with decrypted name.
// This avoids frontend strategy mismatch when encrypted suffix hides the real extension.
func normalizeDecryptedMediaFields(fileMap map[string]interface{}, showName string) {
	if fileMap == nil || showName == "" {
		return
	}
	if pathStr, ok := fileMap["path"].(string); ok && pathStr != "" {
		fileMap["path"] = path.Join(path.Dir(pathStr), showName)
	}
	ext := strings.ToLower(path.Ext(showName))
	if videoExtensions[ext] {
		fileMap["type"] = float64(2)
		return
	}
	if coverExtensions[ext] || ext == ".svg" || ext == ".avif" {
		fileMap["type"] = float64(5)
	}
}

// 常见视频扩展名
var videoExtensions = map[string]bool{
	".mp4": true, ".mkv": true, ".avi": true, ".mov": true,
	".wmv": true, ".flv": true, ".webm": true, ".m4v": true,
	".ts": true, ".rmvb": true, ".rm": true, ".3gp": true,
}

// processCoverFiles 处理封面文件：将与视频同名的图片隐藏并设置为视频的 thumb
func (p *ProxyServer) processCoverFiles(content []interface{}) []interface{} {
	// 构建视频文件名映射（不含扩展名 -> 文件信息）
	videoMap := make(map[string]map[string]interface{})
	coverFiles := make([]int, 0)

	for i, item := range content {
		if fileMap, ok := item.(map[string]interface{}); ok {
			name, _ := fileMap["name"].(string)
			isDir, _ := fileMap["is_dir"].(bool)
			if isDir || name == "" {
				continue
			}

			ext := strings.ToLower(path.Ext(name))
			baseName := strings.TrimSuffix(name, ext)

			if videoExtensions[ext] {
				videoMap[baseName] = fileMap
			} else if coverExtensions[ext] {
				coverFiles = append(coverFiles, i)
			}
		}
	}

	// 将封面文件与视频匹配
	omitIndices := make(map[int]bool)
	for _, idx := range coverFiles {
		if fileMap, ok := content[idx].(map[string]interface{}); ok {
			name, _ := fileMap["name"].(string)
			ext := strings.ToLower(path.Ext(name))
			baseName := strings.TrimSuffix(name, ext)

			// 查找同名视频
			if videoFileMap, exists := videoMap[baseName]; exists {
				// 设置视频的 thumb 为封面的 path
				if coverPath, ok := fileMap["path"].(string); ok && coverPath != "" {
					videoFileMap["thumb"] = coverPath
					omitIndices[idx] = true
					log.Debugf("[%s] Cover auto-hide: %s -> thumb for video %s", internal.TagList, name, baseName)
				}
			}
		}
	}

	// 从列表中移除被隐藏的封面（从后向前删除以保持索引正确）
	if len(omitIndices) == 0 {
		return content
	}
	filtered := make([]interface{}, 0, len(content)-len(omitIndices))
	for i, item := range content {
		if omitIndices[i] {
			continue
		}
		filtered = append(filtered, item)
	}
	return filtered
}

func anyToStringSlice(v interface{}) []string {
	switch vt := v.(type) {
	case []string:
		return vt
	case []interface{}:
		out := make([]string, 0, len(vt))
		for _, item := range vt {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func (p *ProxyServer) noteProviderCandidate(provider string) {
	token := normalizeProviderToken(provider)
	if token == "" || p == nil {
		return
	}
	p.routingMu.Lock()
	if p.seenProviders == nil {
		p.seenProviders = make(map[string]time.Time)
	}
	p.seenProviders[token] = time.Now()
	p.routingMu.Unlock()
	p.mergeProviderCatalog(token, buildProviderLabel(token), providerSourceSeen)
}

func (p *ProxyServer) noteDriverCandidate(driver string) {
	token := normalizeProviderToken(driver)
	if token == "" || p == nil {
		return
	}
	p.routingMu.Lock()
	if p.seenDrivers == nil {
		p.seenDrivers = make(map[string]time.Time)
	}
	p.seenDrivers[token] = time.Now()
	p.routingMu.Unlock()
	p.mergeProviderCatalog(token, buildProviderLabel(token), providerSourceStorage)
}

func (p *ProxyServer) refreshStorageDriverMapIfNeeded(ctx context.Context, srcHeaders http.Header) {
	if p == nil || p.config == nil || p.httpClient == nil {
		return
	}
	p.routingMu.RLock()
	expired := time.Now().After(p.storageMapExpireAt)
	p.routingMu.RUnlock()
	if !expired {
		return
	}

	reqURL := p.getAlistURL() + "/api/admin/storage/list?page=1&per_page=1000"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return
	}
	for key, values := range srcHeaders {
		if strings.EqualFold(key, "Host") || strings.EqualFold(key, "Content-Length") {
			continue
		}
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return
	}
	data, _ := result["data"].(map[string]interface{})
	content, _ := data["content"].([]interface{})
	if len(content) == 0 {
		return
	}
	nextMap := make(map[string]string, len(content))
	for _, raw := range content {
		item, _ := raw.(map[string]interface{})
		if item == nil {
			continue
		}
		mountPath, _ := item["mount_path"].(string)
		driver, _ := item["driver"].(string)
		mp := mapPathToMountPrefix(mountPath)
		dv := normalizeProviderToken(driver)
		if mp == "" || dv == "" {
			continue
		}
		nextMap[mp] = dv
		p.noteDriverCandidate(dv)
	}
	if len(nextMap) == 0 {
		return
	}
	refreshMinutes := 30
	if p.config.StorageMapRefreshMinutes > 0 {
		refreshMinutes = p.config.StorageMapRefreshMinutes
	}
	p.routingMu.Lock()
	p.storageDriverMap = nextMap
	p.storageMapExpireAt = time.Now().Add(time.Duration(refreshMinutes) * time.Minute)
	p.routingMu.Unlock()
}

func buildProviderLabel(provider string) string {
	key := normalizeProviderToken(provider)
	if key == "" {
		return ""
	}
	if label, ok := providerLabelMap[key]; ok && strings.TrimSpace(label) != "" {
		return label
	}
	if strings.Contains(key, "mobile") && strings.Contains(key, "cloud") {
		return "移动云盘"
	}
	if strings.Contains(key, "unicom") && strings.Contains(key, "cloud") {
		return "联通云盘"
	}
	if strings.Contains(key, "googledrive") || strings.Contains(key, "google_drive") {
		return "Google Drive"
	}
	if strings.Contains(key, "google") && strings.Contains(key, "photo") {
		return "Google Photos"
	}
	if strings.Contains(key, "google") && strings.Contains(key, "drive") {
		return "Google Drive"
	}
	if strings.Contains(key, "移动") && strings.Contains(key, "云") {
		return "移动云盘"
	}
	if strings.Contains(key, "联通") && strings.Contains(key, "云") {
		return "联通云盘"
	}
	return ""
}

func (p *ProxyServer) fetchAdminDriverNames(ctx context.Context, srcHeaders http.Header) ([]string, bool) {
	if p == nil || p.httpClient == nil {
		return nil, true
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.getAlistURL()+"/api/admin/driver/names", nil)
	if err != nil {
		return nil, true
	}
	copyForwardHeaders(req.Header, srcHeaders)
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, true
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, true
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, true
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, true
	}
	data, ok := payload["data"].([]interface{})
	if !ok {
		return nil, true
	}
	names := make([]string, 0, len(data))
	for _, raw := range data {
		name, ok := raw.(string)
		if !ok {
			continue
		}
		name = normalizeProviderToken(name)
		if name == "" {
			continue
		}
		names = append(names, name)
	}
	return names, false
}

func copyForwardHeaders(dst, src http.Header) {
	for key, values := range src {
		if strings.EqualFold(key, "Host") || strings.EqualFold(key, "Content-Length") {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func (p *ProxyServer) proxyFSJSON(w http.ResponseWriter, r *http.Request, apiPath string, body []byte) {
	req, err := http.NewRequestWithContext(r.Context(), r.Method, p.getAlistURL()+apiPath, bytes.NewReader(body))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for key, values := range r.Header {
		if strings.EqualFold(key, "Host") || strings.EqualFold(key, "Content-Length") {
			continue
		}
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.httpClient.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	copyWithBuffer(w, resp.Body)
}

func (p *ProxyServer) doFSRemoveRequest(ctx context.Context, srcHeaders http.Header, reqData map[string]interface{}) (int, []byte, error) {
	body, _ := json.Marshal(reqData)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.getAlistURL()+"/api/fs/remove", bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	for key, values := range srcHeaders {
		if strings.EqualFold(key, "Host") || strings.EqualFold(key, "Content-Length") {
			continue
		}
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, respBody, nil
}

func fsRemoveNotFound(status int, body []byte) bool {
	if status == http.StatusBadRequest || status == http.StatusNotFound {
		return true
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return false
	}
	if code, ok := payload["code"].(float64); ok {
		if int(code) == http.StatusBadRequest || int(code) == http.StatusNotFound {
			return true
		}
	}
	msg, _ := payload["message"].(string)
	msg = strings.ToLower(strings.TrimSpace(msg))
	return strings.Contains(msg, "not found") || strings.Contains(msg, "object not found")
}

func (p *ProxyServer) buildRemoveNameCandidates(encPath *EncryptPath, dirPath, name string) []string {
	if strings.TrimSpace(name) == "" {
		return nil
	}
	inputPath := path.Join(dirPath, name)
	pathCandidates := buildRealPathCandidates(encPath, inputPath)
	seen := make(map[string]struct{}, len(pathCandidates))
	out := make([]string, 0, len(pathCandidates))
	for _, item := range pathCandidates {
		base := strings.TrimSpace(path.Base(item))
		if base == "" || base == "." || base == "/" {
			continue
		}
		if _, ok := seen[base]; ok {
			continue
		}
		seen[base] = struct{}{}
		out = append(out, base)
	}
	return out
}

// handleWebDAVLegacy 保留历史执行链，供 V2 orchestrator 调用
func (p *ProxyServer) handleWebDAVLegacy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if p.shouldFastFailUpstream() {
		_, remain, reason := p.upstreamBackoffState()
		retryAfter := int(remain.Seconds())
		if retryAfter < 1 {
			retryAfter = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		http.Error(w, "upstream temporarily unavailable: "+reason, http.StatusServiceUnavailable)
		return
	}
	// 1. 查找加密配置
	filePath := r.URL.Path
	matchPath := filePath
	if strings.HasPrefix(matchPath, "/dav/") {
		matchPath = strings.TrimPrefix(matchPath, "/dav")
	} else if matchPath == "/dav" {
		matchPath = "/"
	}

	encPath := p.findEncryptPath(matchPath)
	if encPath == nil && matchPath != filePath {
		encPath = p.findEncryptPath(filePath)
	}
	rangeHeader := r.Header.Get("Range")
	clientRangeHeader := rangeHeader
	upstreamRangeHeader := clientRangeHeader

	// 记录 WebDAV 请求关键日志
	if encPath != nil {
		log.Infof("%s WebDAV: method=%s path=%s match=%s encName=%v", internal.LogPrefix(ctx, internal.TagProxy), r.Method, filePath, matchPath, encPath.EncName)
	}

	// 2. 转换请求路径中的文件名 (Client明文 -> Server密文)
	targetURLPath := r.URL.Path
	originalTargetURLPath := targetURLPath
	convertedTargetURL := false
	fileName := path.Base(filePath)

	// 与 alist-encrypt 一致的逻辑：
	// - GET, PUT, DELETE, COPY, MOVE, HEAD, POST: 直接转换文件名
	// - PROPFIND: 只有当文件缓存中存在且不是目录时才转换
	//   这是因为 PROPFIND 既可能是请求目录列表，也可能是请求单个文件元数据
	//   alist-encrypt 使用 getFileInfo 查询缓存来判断
	methodNeedConvert := r.Method == "GET" || r.Method == "PUT" || r.Method == "DELETE" ||
		r.Method == "COPY" || r.Method == "MOVE" || r.Method == "HEAD" || r.Method == "POST"

	// PROPFIND 特殊处理：检查文件缓存来判断是否是文件
	if r.Method == "PROPFIND" && encPath != nil && encPath.EncName {
		// 先计算加密后的路径用于缓存查找
		// alist-encrypt: const realName = convertRealName(passwdInfo.password, passwdInfo.encType, url)
		//                const sourceUrl = path.dirname(url) + '/' + realName
		//                const sourceFileInfo = await getFileInfo(sourceUrl)
		if fileName != "/" && fileName != "." {
			realName := convertRealNameByRule(encPath, filePath)
			// 缓存中存储的是完整路径（包含 /dav 前缀），所以查找时也用完整路径
			sourceUrl := path.Join(path.Dir(filePath), realName)
			if !strings.HasPrefix(sourceUrl, "/") {
				sourceUrl = "/" + sourceUrl
			}
			// 检查缓存：如果缓存中存在且不是目录，才转换 URL
			if cached, ok := p.loadFileCache(sourceUrl); ok && !cached.IsDir {
				log.Debugf("%s PROPFIND: found file in cache: %s (isDir=%v)", internal.LogPrefix(ctx, internal.TagCache), sourceUrl, cached.IsDir)
				methodNeedConvert = true
			} else {
				// 也尝试不带 /dav 前缀的路径
				sourceUrlNoPrefix := path.Join(path.Dir(matchPath), realName)
				if !strings.HasPrefix(sourceUrlNoPrefix, "/") {
					sourceUrlNoPrefix = "/" + sourceUrlNoPrefix
				}
				if cached, ok := p.loadFileCache(sourceUrlNoPrefix); ok && !cached.IsDir {
					log.Debugf("%s PROPFIND: found file in cache (no /dav): %s (isDir=%v)", internal.LogPrefix(ctx, internal.TagCache), sourceUrlNoPrefix, cached.IsDir)
					methodNeedConvert = true
				} else {
					log.Debugf("%s PROPFIND: not in cache or is dir: %s or %s", internal.LogPrefix(ctx, internal.TagCache), sourceUrl, sourceUrlNoPrefix)
				}
			}
		}
	}
	if r.Method == "PROPFIND" && encPath != nil && encPath.EncName {
		log.Infof("%s WebDAV PROPFIND planning: path=%s match=%s methodNeedConvert=%v candidates=%v",
			internal.LogPrefix(ctx, internal.TagProxy), filePath, matchPath, methodNeedConvert, buildRealPathCandidates(encPath, filePath))
	}

	if methodNeedConvert && encPath != nil && encPath.EncName {
		if fileName != "/" && fileName != "." {
			realName := convertRealNameByRule(encPath, filePath)
			newPath := path.Join(path.Dir(filePath), realName)
			// 确保路径以 / 开头
			if !strings.HasPrefix(newPath, "/") {
				newPath = "/" + newPath
			}
			targetURLPath = newPath
			convertedTargetURL = targetURLPath != originalTargetURLPath
			log.Debugf("%s Convert real name URL (%s): %s -> %s", internal.LogPrefix(ctx, internal.TagEncrypt), r.Method, r.URL.Path, targetURLPath)
		}
	}

	// For GET/HEAD, use /d/ prefix instead of /dav/ — upstream alist serves files via /d/.
	if (r.Method == "GET" || r.Method == "HEAD") && strings.HasPrefix(targetURLPath, "/dav/") {
		targetURLPath = "/d" + strings.TrimPrefix(targetURLPath, "/dav")
	} else if (r.Method == "GET" || r.Method == "HEAD") && targetURLPath == "/dav" {
		targetURLPath = "/d"
	}

	targetURL := p.getAlistURL() + targetURLPath
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}
	negativeCachePath := targetURLPath
	if strings.HasPrefix(negativeCachePath, "/dav") {
		negativeCachePath = strings.TrimPrefix(negativeCachePath, "/dav")
		if negativeCachePath == "" {
			negativeCachePath = "/"
		}
	}
	if r.Method == "PROPFIND" && p.webdavNegativeBlocked(negativeCachePath) {
		log.Warnf("%s WebDAV negative cache hit: path=%s negativePath=%s", internal.LogPrefix(ctx, internal.TagProxy), filePath, negativeCachePath)
		http.Error(w, "object not found", http.StatusNotFound)
		return
	}

	rangeSuppressedByStrategy := false
	if r.Method == "GET" && clientRangeHeader != "" {
		rangeStart, hasRangeStart := parseRangeStart(clientRangeHeader)
		if (!hasRangeStart || rangeStart < rangePreferUpstreamStartBytes) && func() bool {
			if strategy, ok := p.lookupLocalStrategy(targetURL, filePath); ok && strategy == StreamStrategyChunked {
				return true
			}
			return false
		}() {
			rangeSuppressedByStrategy = true
		}
	}
	if r.Method == "GET" && clientRangeHeader != "" && (rangeSuppressedByStrategy || p.shouldSkipRange(targetURL, filePath)) {
		upstreamRangeHeader = ""
	}
	p.debugf("range", "webdav method=%s path=%s clientRange=%q upstreamRange=%q suppressedByStrategy=%v",
		r.Method, filePath, clientRangeHeader, upstreamRangeHeader, rangeSuppressedByStrategy)

	var body io.Reader = nil
	if r.Body != nil {
		body = r.Body
	}

	// 3. 处理 PUT 加密上传
	if r.Method == "PUT" && encPath != nil {
		contentLength := r.ContentLength
		// 尝试从 header 获取长度 (兼容 chunked transfer)
		if contentLength <= 0 {
			if l := r.Header.Get("X-Expected-Entity-Length"); l != "" {
				contentLength, _ = strconv.ParseInt(l, 10, 64)
			}
		}
		if contentLength <= 0 {
			if l := r.Header.Get("Content-Length"); l != "" {
				contentLength, _ = strconv.ParseInt(l, 10, 64)
			}
		}

		if contentLength > 0 {
			encryptor, err := NewFlowEncryptor(encPath.Password, encPath.EncType, contentLength)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			body = NewEncryptReader(r.Body, encryptor)

			// 缓存原始文件信息（与 alist-encrypt 一致：上传前缓存，便于 rclone 的 PROPFIND）
			originalFileName := path.Base(filePath)
			p.storeFileCache(filePath, &FileInfo{
				Name:  originalFileName,
				Size:  contentLength,
				IsDir: false,
				Path:  filePath,
			})
			// 同时缓存不带 /dav 前缀的路径
			if strings.HasPrefix(filePath, "/dav/") {
				noDav := strings.TrimPrefix(filePath, "/dav")
				p.storeFileCache(noDav, &FileInfo{
					Name:  originalFileName,
					Size:  contentLength,
					IsDir: false,
					Path:  noDav,
				})
			}
		} else {
			log.Warnf("%s PUT request encryption skipped: missing content length for %s", internal.LogPrefix(ctx, internal.TagUpload), r.URL.Path)
		}
	}

	reqCtx := r.Context()
	var cancel context.CancelFunc
	if r.Method != http.MethodGet {
		reqCtx, cancel = context.WithTimeout(r.Context(), p.upstreamTimeout())
		defer cancel()
	}
	req, err := http.NewRequestWithContext(reqCtx, r.Method, targetURL, body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 复制请求头
	for key, values := range r.Header {
		if key != "Host" {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
	}

	// 4. 处理 Destination 头 (COPY/MOVE)
	if (r.Method == "COPY" || r.Method == "MOVE") && r.Header.Get("Destination") != "" {
		dest := r.Header.Get("Destination")
		u, err := url.Parse(dest)
		if err == nil {
			destPath := u.Path
			// 同样尝试去前缀匹配配置
			destMatchPath := destPath
			if strings.HasPrefix(destMatchPath, "/dav/") {
				destMatchPath = strings.TrimPrefix(destMatchPath, "/dav")
			} else if destMatchPath == "/dav" {
				destMatchPath = "/"
			}
			destEncPath := p.findEncryptPath(destMatchPath)
			if destEncPath == nil && destMatchPath != destPath {
				destEncPath = p.findEncryptPath(destPath)
			}

			// 如果目标路径需要加密文件名
			if destEncPath != nil && destEncPath.EncName {
				destName := path.Base(destPath)
				if destName != "/" && destName != "." {
					realDestName := convertRealNameByRule(destEncPath, destPath)
					newDestPath := path.Join(path.Dir(destPath), realDestName)
					if !strings.HasPrefix(newDestPath, "/") {
						newDestPath = "/" + newDestPath
					}
					destPath = newDestPath
					log.Debugf("%s Convert real name Destination: %s -> %s", internal.LogPrefix(ctx, internal.TagEncrypt), u.Path, destPath)
				}
			}

			// 重组 Destination
			newDest := p.getAlistURL() + destPath
			req.Header.Set("Destination", newDest)
		}
	}
	if r.Method == "GET" && clientRangeHeader != "" {
		if upstreamRangeHeader == "" {
			req.Header.Del("Range")
		} else {
			req.Header.Set("Range", upstreamRangeHeader)
		}
	}

	// 备份 Body 以便可能的重试 (针对 PROPFIND)
	var reqBodyBytes []byte
	if r.Method == "PROPFIND" && r.Body != nil {
		reqBodyBytes, _ = io.ReadAll(r.Body)
		// 恢复原始 req 的 Body (如果之前读取过)
		// 注意：这里的 r.Body 已经被 upstream passed to NewRequest.
		// 我们需要确保 req.Body 是可读的。
		// 在 NewRequest 时如果传入了 body io.Reader，它会被赋给 req.Body.
		// 如果 body 之前是 r.Body (http.Request)，它可能只能读一次。
		// 我们前面: if r.Body != nil { body = r.Body }
		// 所以 req.Body 指向了 socket。如果读得动的话。
		// 为了安全，我们最好在这里用 bytes 重建 req.Body
		if len(reqBodyBytes) > 0 {
			req.Body = io.NopCloser(bytes.NewReader(reqBodyBytes))
		}
	}

	client := p.httpClient
	if r.Method == http.MethodGet {
		client = p.streamClient
	}
	resp, err := client.Do(req)
	if err != nil {
		p.markUpstreamFailure(err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	p.markUpstreamSuccess()
	if convertedTargetURL && (r.Method == "GET" || r.Method == "HEAD" || r.Method == "POST") && resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		fallbackPaths := make([]string, 0, 2)
		if encPath != nil && encPath.EncName && encPath.EncSuffix != "" {
			noSuffixRealName := ConvertRealNameWithSuffix(encPath.Password, encPath.EncType, filePath, "")
			noSuffixPath := path.Join(path.Dir(filePath), noSuffixRealName)
			if !strings.HasPrefix(noSuffixPath, "/") {
				noSuffixPath = "/" + noSuffixPath
			}
			if noSuffixPath != targetURLPath && noSuffixPath != originalTargetURLPath {
				fallbackPaths = append(fallbackPaths, noSuffixPath)
			}
		}
		fallbackPaths = append(fallbackPaths, originalTargetURLPath)
		for _, fallbackPath := range fallbackPaths {
			p.debugf("filename", "webdav fallback path method=%s from=%s to=%s", r.Method, targetURLPath, fallbackPath)
			fallbackTargetURL := p.getAlistURL() + fallbackPath
			if r.URL.RawQuery != "" {
				fallbackTargetURL += "?" + r.URL.RawQuery
			}
			retryReq, err := http.NewRequestWithContext(reqCtx, r.Method, fallbackTargetURL, nil)
			if err != nil {
				continue
			}
			for key, values := range r.Header {
				if key != "Host" {
					for _, value := range values {
						retryReq.Header.Add(key, value)
					}
				}
			}
			if r.Method == "GET" && clientRangeHeader != "" {
				if upstreamRangeHeader == "" {
					retryReq.Header.Del("Range")
				} else {
					retryReq.Header.Set("Range", upstreamRangeHeader)
				}
			}
			if len(reqBodyBytes) > 0 {
				retryReq.Body = io.NopCloser(bytes.NewReader(reqBodyBytes))
			}
			resp2, err2 := client.Do(retryReq)
			if err2 != nil {
				continue
			}
			resp = resp2
			targetURL = fallbackTargetURL
			targetURLPath = fallbackPath
			break
		}
	}

	// 添加调试日志：记录后端响应状态码和内容长度
	log.Infof("%s WebDAV backend response: method=%s path=%s statusCode=%d contentLength=%s contentType=%s",
		internal.LogPrefix(ctx, internal.TagProxy), r.Method, filePath, resp.StatusCode, resp.Header.Get("Content-Length"), resp.Header.Get("Content-Type"))
	if r.Method == "PROPFIND" {
		if resp.StatusCode == http.StatusNotFound {
			p.markWebdavNegative(negativeCachePath)
		} else if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			p.clearWebdavNegative(negativeCachePath)
		}
	}

	// PROPFIND 404 重试机制 (因为我们不知道请求的是目录还是加密文件)
	// 候选顺序：带后缀密文 -> 无后缀密文（仅配置了后缀）-> 原始路径
	if r.Method == "PROPFIND" && resp.StatusCode == 404 && encPath != nil && encPath.EncName &&
		shouldRetryPropfind404(r.Header.Get("Depth"), filePath) {
		// 关闭首个 404 响应体
		resp.Body.Close()
		fileName := path.Base(filePath)
		if fileName != "/" && fileName != "." {
			type propfindCandidate struct {
				path  string
				stage string
			}
			candidates := make([]propfindCandidate, 0, 3)
			seen := make(map[string]bool, 3)
			addCandidate := func(candidatePath, stage string) {
				if candidatePath == "" {
					return
				}
				if !strings.HasPrefix(candidatePath, "/") {
					candidatePath = "/" + candidatePath
				}
				if seen[candidatePath] {
					return
				}
				seen[candidatePath] = true
				candidates = append(candidates, propfindCandidate{path: candidatePath, stage: stage})
			}

			realName := convertRealNameByRule(encPath, filePath)
			addCandidate(path.Join(path.Dir(filePath), realName), "fallback-encrypted-with-suffix")
			if encPath.EncSuffix != "" {
				noSuffixRealName := ConvertRealNameWithSuffix(encPath.Password, encPath.EncType, filePath, "")
				addCandidate(path.Join(path.Dir(filePath), noSuffixRealName), "fallback-encrypted-no-suffix")
			}
			addCandidate(originalTargetURLPath, "fallback-original-path")

			for i, candidate := range candidates {
				if candidate.path == targetURLPath {
					continue
				}
				retryTargetURL := p.getAlistURL() + candidate.path
				if r.URL.RawQuery != "" {
					retryTargetURL += "?" + r.URL.RawQuery
				}
				p.debugf("webdav", "PROPFIND 404 retry attempt=%d stage=%s from=%s to=%s", i+1, candidate.stage, targetURLPath, candidate.path)

				var retryBody io.Reader
				if len(reqBodyBytes) > 0 {
					retryBody = bytes.NewReader(reqBodyBytes)
				}
				retryCtx, retryCancel := context.WithTimeout(r.Context(), p.propfindRetryTimeout())
				retryReq, reqErr := http.NewRequestWithContext(retryCtx, r.Method, retryTargetURL, retryBody)
				if reqErr != nil {
					retryCancel()
					continue
				}
				for key, values := range r.Header {
					if key != "Host" {
						for _, value := range values {
							retryReq.Header.Add(key, value)
						}
					}
				}
				resp, err = client.Do(retryReq)
				retryCancel()
				if err != nil {
					p.debugf("webdav", "PROPFIND retry failed stage=%s path=%s err=%v", candidate.stage, candidate.path, err)
					if i == len(candidates)-1 {
						p.markUpstreamFailure(err)
						http.Error(w, err.Error(), http.StatusBadGateway)
						return
					}
					continue
				}
				p.markUpstreamSuccess()
				p.debugf("webdav", "PROPFIND retry response stage=%s path=%s status=%d", candidate.stage, candidate.path, resp.StatusCode)
				log.Infof("%s WebDAV PROPFIND retry: stage=%s candidate=%s status=%d",
					internal.LogPrefix(ctx, internal.TagProxy), candidate.stage, candidate.path, resp.StatusCode)
				targetURLPath = candidate.path
				targetURL = retryTargetURL
				if resp.StatusCode >= 200 && resp.StatusCode < 300 {
					p.clearWebdavNegative(negativeCachePath)
					break
				}
				if i < len(candidates)-1 {
					resp.Body.Close()
				}
			}
		}
	}
	defer resp.Body.Close()

	// 5. 处理 PROPFIND 响应 (文件名解密)
	if r.Method == "PROPFIND" && encPath != nil && encPath.EncName {
		// Remove Content-Length so Go will use chunked transfer when streaming the modified output.
		for key, values := range resp.Header {
			if strings.ToLower(key) == "content-length" {
				continue
			}
			for _, v := range values {
				w.Header().Add(key, v)
			}
		}
		w.WriteHeader(resp.StatusCode)

		if err := p.processPropfindResponse(resp.Body, w, encPath); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// 复制响应头（排除 Location，后面可能需要修改）
	for key, values := range resp.Header {
		lowerKey := strings.ToLower(key)
		// 暂不复制 Location，后面处理重定向时可能需要修改
		if lowerKey == "location" {
			continue
		}
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	statusCode := resp.StatusCode
	if resp.StatusCode == http.StatusOK && resp.Header.Get("Content-Range") != "" {
		statusCode = http.StatusPartialContent
	}

	// 处理 302/303 重定向：对于需要解密的路径，创建代理重定向
	// 这模拟了 alist-encrypt 的行为，拦截重定向并通过 /redirect/ 端点处理
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		log.Infof("WebDAV backend redirect: method=%s path=%s statusCode=%d location=%s",
			r.Method, filePath, resp.StatusCode, location)

		if r.Method == "GET" && encPath != nil && encPath.Enable && location != "" {
			driver := p.inferDriverFromPath(ctx, filePath, r.Header)
			p.noteDriverCandidate(driver)
			// 对于需要解密的 GET 请求，创建代理重定向
			// 尝试获取文件大小（从缓存或响应头）
			var fileSize int64 = 0
			if cached, ok := p.loadFileCache(filePath); ok && !cached.IsDir && cached.Size > 0 {
				fileSize = cached.Size
			} else if strings.HasPrefix(filePath, "/dav/") {
				noDav := strings.TrimPrefix(filePath, "/dav")
				if cached, ok := p.loadFileCache(noDav); ok && !cached.IsDir && cached.Size > 0 {
					fileSize = cached.Size
				}
			}
			// 也尝试用密文路径查缓存
			if fileSize == 0 && encPath.EncName {
				realName := convertRealNameByRule(encPath, filePath)
				encPathFull := path.Join(path.Dir(filePath), realName)
				if !strings.HasPrefix(encPathFull, "/") {
					encPathFull = "/" + encPathFull
				}
				if cached, ok := p.loadFileCache(encPathFull); ok && !cached.IsDir && cached.Size > 0 {
					fileSize = cached.Size
				}
			}

			if fileSize == 0 {
				if size, ok := p.lookupLocalSize(location, filePath); ok {
					fileSize = size
				}
			}

			// 如果缓存中没有 fileSize，尝试通过 PROPFIND 获取（修复 WebDAV 播放问题）
			if fileSize == 0 {
				propfindURL := targetURL
				if size := p.fetchWebDAVFileSizeWithPath(propfindURL, r.Header, encPath.Path); size > 0 {
					fileSize = size
					log.Infof("%s WebDAV redirect: got fileSize from PROPFIND: %d for %s", internal.LogPrefix(ctx, internal.TagFileSize), fileSize, filePath)
					// 缓存文件大小
					p.storeFileCache(filePath, &FileInfo{Name: path.Base(filePath), Size: size, IsDir: false, Path: filePath})
					if strings.HasPrefix(filePath, "/dav/") {
						noDav := strings.TrimPrefix(filePath, "/dav")
						p.storeFileCache(noDav, &FileInfo{Name: path.Base(noDav), Size: size, IsDir: false, Path: noDav})
					}
				}
			}

			// 如果 PROPFIND 也获取不到，强制探测远程文件大小（加密文件没有 fileSize 无法解密）
			if fileSize == 0 {
				probed := p.forceProbeRemoteFileSizeWithPath(location, r.Header, encPath.Path)
				if probed > 0 {
					fileSize = probed
					log.Infof("WebDAV redirect: probed remote fileSize: %d for %s", fileSize, filePath)
				}
			}
			log.Infof("%s WebDAV redirect planning: path=%s location=%s fileSize=%d range=%q",
				internal.LogPrefix(ctx, internal.TagProxy), filePath, location, fileSize, clientRangeHeader)

			// 生成唯一的重定向 key
			redirectKey := fmt.Sprintf("%d-%s", time.Now().UnixNano(), path.Base(filePath))

			// 缓存重定向信息
			redirectInfo := &RedirectInfo{
				RedirectURL: location,
				PasswdInfo:  encPath,
				FileSize:    fileSize,
				OriginalURL: r.URL.String(),
				Headers:     r.Header.Clone(),
				Driver:      driver,
			}
			p.storeRedirectCache(redirectKey, redirectInfo)

			// 构建代理重定向 URL
			proxyLocation := fmt.Sprintf("/redirect/%s?decode=1&lastUrl=%s",
				redirectKey, url.QueryEscape(r.URL.Path))

			log.Infof("WebDAV proxy redirect: path=%s, original=%s, proxy=%s, fileSize=%d",
				filePath, location, proxyLocation, fileSize)

			// 返回修改后的重定向响应
			w.Header().Set("Location", proxyLocation)
			w.WriteHeader(resp.StatusCode)
			copyWithBuffer(w, resp.Body)
			return
		}

		// 对于不需要解密的请求，直接透传重定向
		w.Header().Set("Location", location)
		w.WriteHeader(statusCode)
		copyWithBuffer(w, resp.Body)
		return
	}

	// 6. 处理 GET 下载解密
	if r.Method == "GET" && encPath != nil {
		// 只有响应状态码是 2xx 时才尝试解密
		// 非 2xx 状态码（如 4xx、5xx 错误）直接透传，不尝试解密
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			log.Warnf("%s WebDAV GET non-2xx: path=%s target=%s status=%d contentType=%s",
				internal.LogPrefix(ctx, internal.TagProxy), filePath, targetURL, resp.StatusCode, resp.Header.Get("Content-Type"))
			w.WriteHeader(statusCode)
			copyWithBuffer(w, resp.Body)
			return
		}

		// 检查 Content-Type，避免解密错误页面或目录列表
		contentType := resp.Header.Get("Content-Type")
		if strings.Contains(contentType, "text/html") ||
			strings.Contains(contentType, "application/json") ||
			strings.Contains(contentType, "application/xml") {
			w.WriteHeader(statusCode)
			copyWithBuffer(w, resp.Body)
			return
		}

		// 尝试从缓存获取文件大小（WebDAV PROPFIND 已缓存）
		var fileSize int64 = 0
		if cached, ok := p.loadFileCache(filePath); ok && !cached.IsDir && cached.Size > 0 {
			fileSize = cached.Size
		} else {
			// 兼容不带 /dav 前缀的缓存键
			if strings.HasPrefix(filePath, "/dav/") {
				noDav := strings.TrimPrefix(filePath, "/dav")
				if cached, ok := p.loadFileCache(noDav); ok && !cached.IsDir && cached.Size > 0 {
					fileSize = cached.Size
				}
			}
		}

		// 进一步尝试：使用密文路径查缓存（对齐 alist-encrypt 的重试逻辑）
		if fileSize == 0 && encPath != nil && encPath.EncName {
			realName := convertRealNameByRule(encPath, filePath)
			encPathFull := path.Join(path.Dir(filePath), realName)
			if !strings.HasPrefix(encPathFull, "/") {
				encPathFull = "/" + encPathFull
			}
			if cached, ok := p.loadFileCache(encPathFull); ok && !cached.IsDir && cached.Size > 0 {
				fileSize = cached.Size
			} else if strings.HasPrefix(encPathFull, "/dav/") {
				noDav := strings.TrimPrefix(encPathFull, "/dav")
				if cached, ok := p.loadFileCache(noDav); ok && !cached.IsDir && cached.Size > 0 {
					fileSize = cached.Size
				}
			}
		}
		if fileSize == 0 {
			if size, ok := p.lookupLocalSize(targetURL, filePath); ok {
				fileSize = size
			}
		}

		// 尝试获取文件大小
		contentRange := resp.Header.Get("Content-Range")
		if contentRange != "" {
			// 格式: bytes start-end/total
			parts := strings.Split(contentRange, "/")
			if len(parts) == 2 {
				if total, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
					fileSize = total
				}
			}
		}

		// Range 请求下 Content-Length 只是分片大小，不能用作总大小
		if fileSize == 0 && clientRangeHeader == "" {
			if cl := resp.Header.Get("Content-Length"); cl != "" {
				fileSize, _ = strconv.ParseInt(cl, 10, 64)
			}
		}

		// 如果仍然未知，先尝试 WebDAV PROPFIND 获取大小
		if fileSize == 0 {
			if size := p.fetchWebDAVFileSizeWithPath(targetURL, req.Header, encPath.Path); size > 0 {
				fileSize = size
				p.storeFileCache(filePath, &FileInfo{Name: path.Base(filePath), Size: size, IsDir: false, Path: filePath})
				if strings.HasPrefix(filePath, "/dav/") {
					noDav := strings.TrimPrefix(filePath, "/dav")
					p.storeFileCache(noDav, &FileInfo{Name: path.Base(noDav), Size: size, IsDir: false, Path: noDav})
				}
				log.Infof("handleWebDAV: propfind fileSize=%d for %s", fileSize, targetURL)
			}
		}

		// 如果仍然未知，强制探测远程总大小（加密文件没有 fileSize 无法解密）
		if fileSize == 0 {
			probed := p.forceProbeRemoteFileSizeWithPath(targetURL, req.Header, encPath.Path)
			if probed > 0 {
				fileSize = probed
				log.Infof("handleWebDAV: probed remote fileSize=%d for %s", fileSize, targetURL)
			}
		}
		log.Infof("%s WebDAV GET planning: path=%s target=%s fileSize=%d range=%q contentRange=%q",
			internal.LogPrefix(ctx, internal.TagProxy), filePath, targetURL, fileSize, clientRangeHeader, resp.Header.Get("Content-Range"))

		// 只有当服务端返回了内容，且知道大小，才解密
		if fileSize > 0 {
			var startPos int64 = 0
			if parsedStart, ok := parseRangeStart(clientRangeHeader); ok {
				startPos = parsedStart
			}

			log.Infof("WebDAV decrypt: path=%s range=%q content-range=%q content-length=%q fileSize=%d start=%d",
				filePath, clientRangeHeader, resp.Header.Get("Content-Range"), resp.Header.Get("Content-Length"), fileSize, startPos)

			encryptor, err := NewFlowEncryptor(encPath.Password, encPath.EncType, fileSize)
			if err != nil {
				// 无法创建解密器(如未知算法)，直接透传
				log.Warnf("Failed to create encryptor for download: %v", err)
				if p.config != nil && p.config.PlayFirstFallback {
					atomic.AddUint64(&p.playFirstCount, 1)
					w.WriteHeader(statusCode)
					copyWithBuffer(w, resp.Body)
					return
				}
				w.WriteHeader(statusCode)
				copyWithBuffer(w, resp.Body)
				return
			}

			upstreamIsRange := resp.StatusCode == http.StatusPartialContent || resp.Header.Get("Content-Range") != ""
			if clientRangeHeader != "" && !upstreamIsRange {
				p.markRangeIncompatible(targetURL, filePath)
			} else if clientRangeHeader != "" && upstreamIsRange {
				p.markRangeCompatible(targetURL, filePath)
			}
			if clientRangeHeader != "" && !upstreamIsRange && startPos > 0 {
				endPos := fileSize - 1
				if endPos >= startPos {
					statusCode = http.StatusPartialContent
					w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", startPos, endPos, fileSize))
					w.Header().Set("Content-Length", strconv.FormatInt(fileSize-startPos, 10))
					w.Header().Set("Accept-Ranges", "bytes")
				} else {
					startPos = 0
				}
			}
			observedStrategy := StreamStrategyChunked
			if upstreamIsRange {
				observedStrategy = StreamStrategyRange
			}
			p.recordLocalObservation(targetURL, filePath, fileSize, resp.StatusCode, resp.Header.Get("Content-Type"), observedStrategy)
			if startPos > 0 {
				if upstreamIsRange {
					encryptor.SetPosition(startPos)
				} else {
					if startPos > p.rangeSkipMaxBytes() {
						log.Warnf("WebDAV decrypt: skip exceeds limit start=%d limit=%d upstreamRange=%v status=%d contentRange=%q path=%s",
							startPos, p.rangeSkipMaxBytes(), upstreamIsRange, resp.StatusCode, resp.Header.Get("Content-Range"), filePath)
						http.Error(w, "range skip exceeds limit", http.StatusRequestedRangeNotSatisfiable)
						return
					}
					if _, err := io.CopyN(io.Discard, resp.Body, startPos); err != nil {
						log.Warnf("WebDAV decrypt: skip encrypted prefix failed: %v", err)
					}
					encryptor.SetPosition(startPos)
				}
			}

			decryptReader := NewDecryptReader(resp.Body, encryptor)
			w.WriteHeader(statusCode)
			copyWithBuffer(w, decryptReader)
			return
		}
	}

	w.WriteHeader(statusCode)
	copyWithBuffer(w, resp.Body)
}

// handleProxy 处理通用代理请求
func (p *ProxyServer) handleProxy(w http.ResponseWriter, r *http.Request) {
	targetURL := p.getAlistURL() + r.URL.Path
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	log.Debugf("Proxying %s %s to %s", r.Method, r.URL.Path, targetURL)

	ctx, cancel := context.WithTimeout(r.Context(), p.upstreamTimeout())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, r.Method, targetURL, r.Body)
	if err != nil {
		log.Errorf("Failed to create request: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 复制请求头
	for key, values := range r.Header {
		if key != "Host" && key != "Accept-Encoding" {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		log.Errorf("Proxy request failed: %v", err)
		p.markUpstreamFailure(err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	p.markUpstreamSuccess()
	defer resp.Body.Close()

	log.Debugf("Proxy response status: %d", resp.StatusCode)

	var locationHeader string
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		if location != "" {
			if rewritten := rewriteProxyRedirectLocation(r, p.getAlistURL(), location); rewritten != "" {
				locationHeader = rewritten
			} else {
				locationHeader = location
			}
		}
	}

	// 复制响应头
	for key, values := range resp.Header {
		if strings.EqualFold(key, "Location") {
			continue
		}
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	if locationHeader != "" {
		w.Header().Set("Location", locationHeader)
	}

	w.WriteHeader(resp.StatusCode)

	// 直接复制响应体，不做 HTML 注入（加密配置已移至 App 前端）
	copyWithBuffer(w, resp.Body)
}

// generateRedirectKey 生成重定向 key
func generateRedirectKey() string {
	return fmt.Sprintf("%d%d", time.Now().UnixNano(), time.Now().UnixNano()%1000000)
}

func requestOriginFromProxyRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin != "" {
		return strings.TrimRight(origin, "/")
	}
	proto := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))
	if proto == "" {
		if r.TLS != nil {
			proto = "https"
		} else {
			proto = "http"
		}
	}
	host := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = strings.TrimSpace(r.Host)
	}
	if host == "" {
		return ""
	}
	return proto + "://" + host
}

func rewriteProxyRedirectLocation(r *http.Request, upstreamBaseURL, location string) string {
	location = strings.TrimSpace(location)
	if location == "" {
		return ""
	}

	parsedLoc, err := url.Parse(location)
	if err != nil {
		return location
	}
	if !parsedLoc.IsAbs() {
		return location
	}

	parsedUpstream, err := url.Parse(strings.TrimSpace(upstreamBaseURL))
	if err != nil || parsedUpstream.Host == "" {
		return location
	}
	if !strings.EqualFold(parsedLoc.Host, parsedUpstream.Host) {
		return location
	}

	origin := requestOriginFromProxyRequest(r)
	if origin == "" {
		return location
	}

	rewritten := parsedLoc.Path
	if rewritten == "" {
		rewritten = "/"
	}
	if parsedLoc.RawQuery != "" {
		rewritten += "?" + parsedLoc.RawQuery
	}
	if parsedLoc.Fragment != "" {
		rewritten += "#" + parsedLoc.Fragment
	}
	return origin + rewritten
}
