package encrypt

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/OpenListTeam/OpenList/v4/openlistlib/internal"
	log "github.com/sirupsen/logrus"
)

type configDocItem struct {
	Key         string      `json:"key"`
	Label       string      `json:"label"`
	Description string      `json:"description"`
	Min         interface{} `json:"min,omitempty"`
	Max         interface{} `json:"max,omitempty"`
	Default     interface{} `json:"default"`
	Unit        string      `json:"unit,omitempty"`
}

type configV2Path struct {
	Path      string `json:"path"`
	EncType   string `json:"encType"`
	EncName   bool   `json:"encName"`
	EncSuffix string `json:"encSuffix,omitempty"`
	Enable    bool   `json:"enable"`
}

type configV2Data struct {
	Version int            `json:"version"`
	Config  map[string]any `json:"config"`
}

type configV2ProviderRoutingRule struct {
	ID          string   `json:"id,omitempty"`
	MatchType   string   `json:"matchType"`
	MatchValue  string   `json:"matchValue,omitempty"`
	MatchValues []string `json:"matchValues,omitempty"`
	Action      string   `json:"action"`
	Enabled     bool     `json:"enabled"`
	Priority    int      `json:"priority"`
}

func configV2Docs() []configDocItem {
	defaults := DefaultConfig()
	return []configDocItem{
		{Key: "upstreamTimeoutSeconds", Label: "上游超时", Description: "OpenList UI/API 请求超时时间", Min: 2, Max: 120, Default: defaults.UpstreamTimeoutSeconds, Unit: "秒"},
		{Key: "probeTimeoutSeconds", Label: "探测超时", Description: "单次探测请求最大耗时", Min: 1, Max: 30, Default: defaults.ProbeTimeoutSeconds, Unit: "秒"},
		{Key: "probeBudgetSeconds", Label: "探测预算", Description: "一次探测流程总时间预算", Min: 1, Max: 60, Default: defaults.ProbeBudgetSeconds, Unit: "秒"},
		{Key: "upstreamBackoffSeconds", Label: "退避窗口", Description: "上游失败后的快速失败窗口", Min: 1, Max: 300, Default: defaults.UpstreamBackoffSeconds, Unit: "秒"},
		{Key: "storageMapRefreshMinutes", Label: "存储映射刷新", Description: "admin storage 列表缓存刷新周期", Min: 1, Max: 1440, Default: defaults.StorageMapRefreshMinutes, Unit: "分钟"},
		{Key: "routingUnmatchedDefault", Label: "未匹配默认动作", Description: "未命中 provider/driver 规则时默认 direct/proxy", Default: defaults.RoutingUnmatchedDefault},
		{Key: "providerCatalogEnabled", Label: "Provider目录缓存", Description: "启用 provider 目录缓存与后台刷新", Default: defaults.ProviderCatalogEnabled},
		{Key: "providerCatalogTtlMinutes", Label: "Provider目录TTL", Description: "provider 目录后台刷新周期", Min: 5, Max: 10080, Default: defaults.ProviderCatalogTTLMinutes, Unit: "分钟"},
		{Key: "providerCatalogBootstrapOnStart", Label: "启动刷新目录", Description: "服务启动后异步刷新 provider 目录", Default: defaults.ProviderCatalogBootstrapOnStart},
		{Key: "rangeCompatTtlMinutes", Label: "Range缓存TTL", Description: "Range不兼容缓存有效期", Min: 1, Max: 43200, Default: defaults.RangeCompatTTL, Unit: "分钟"},
		{Key: "rangeCompatMinFailures", Label: "Range失败阈值", Description: "连续失败达到该值后标记不兼容", Min: 1, Max: 20, Default: defaults.RangeCompatMinFailures, Unit: "次"},
		{Key: "rangeSkipMaxBytes", Label: "Range跳过上限", Description: "上游忽略Range时本地可跳过字节上限", Min: int64(1 << 20), Max: int64(2 << 30), Default: defaults.RangeSkipMaxBytes, Unit: "字节"},
		{Key: "parallelDecryptConcurrency", Label: "并行解密并发", Description: "大文件并行解密线程数", Min: 1, Max: 32, Default: defaults.ParallelDecryptConcurrency},
		{Key: "streamBufferKb", Label: "流缓冲", Description: "流式解密缓冲区大小", Min: 64, Max: 4096, Default: defaults.StreamBufferKB, Unit: "KB"},
		{Key: "webdavNegativeCacheTtlMinutes", Label: "WebDAV负缓存", Description: "WebDAV 404 负缓存时长", Min: 1, Max: 1440, Default: defaults.WebDAVNegativeCacheTTLMinutes, Unit: "分钟"},
		{Key: "dbExportSyncIntervalSeconds", Label: "同步周期", Description: "DB_EXPORT 增量同步轮询间隔", Min: minDBExportSyncIntervalSecs, Max: 3600, Default: defaults.DBExportSyncIntervalSeconds, Unit: "秒"},
		{Key: "localSizeRetentionDays", Label: "Size保留", Description: "本地 size 记录保留时长", Min: 1, Max: 3650, Default: defaults.LocalSizeRetentionDays, Unit: "天"},
		{Key: "localStrategyRetentionDays", Label: "策略保留", Description: "本地 strategy 记录保留时长", Min: 1, Max: 3650, Default: defaults.LocalStrategyRetentionDays, Unit: "天"},
		{Key: "debugSampleRate", Label: "调试采样率", Description: "调试日志采样比例", Min: 1, Max: 100, Default: defaults.DebugSampleRate, Unit: "%"},
	}
}

func (p *ProxyServer) exportConfigV2() map[string]any {
	paths := make([]configV2Path, 0)
	routingRules := make([]configV2ProviderRoutingRule, 0)
	if p != nil && p.config != nil {
		for _, ep := range p.config.EncryptPaths {
			if ep == nil {
				continue
			}
			paths = append(paths, configV2Path{Path: ep.Path, EncType: string(ep.EncType), EncName: ep.EncName, EncSuffix: ep.EncSuffix, Enable: ep.Enable})
		}
		for _, rr := range p.config.ProviderRoutingRules {
			matchValues := normalizeRoutingMatchValues(&rr)
			routingRules = append(routingRules, configV2ProviderRoutingRule{
				ID: rr.ID, MatchType: rr.MatchType, MatchValue: rr.MatchValue, MatchValues: matchValues, Action: rr.Action, Enabled: rr.Enabled, Priority: rr.Priority,
			})
		}
	}
	cfg := p.config
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return map[string]any{
		"alistHost":                       cfg.AlistHost,
		"alistPort":                       cfg.AlistPort,
		"alistHttps":                      cfg.AlistHttps,
		"proxyPort":                       cfg.ProxyPort,
		"upstreamTimeoutSeconds":          cfg.UpstreamTimeoutSeconds,
		"probeTimeoutSeconds":             cfg.ProbeTimeoutSeconds,
		"probeBudgetSeconds":              cfg.ProbeBudgetSeconds,
		"upstreamBackoffSeconds":          cfg.UpstreamBackoffSeconds,
		"enableLocalBypass":               cfg.EnableLocalBypass,
		"routingMode":                     cfg.RoutingMode,
		"providerRuleSource":              cfg.ProviderRuleSource,
		"routingUnmatchedDefault":         cfg.RoutingUnmatchedDefault,
		"providerCatalogEnabled":          cfg.ProviderCatalogEnabled,
		"providerCatalogTtlMinutes":       cfg.ProviderCatalogTTLMinutes,
		"providerCatalogBootstrapOnStart": cfg.ProviderCatalogBootstrapOnStart,
		"storageMapRefreshMinutes":        cfg.StorageMapRefreshMinutes,
		"providerRoutingRules":            routingRules,
		"playFirstFallback":               cfg.PlayFirstFallback,
		"enableRangeCompatCache":          cfg.EnableRangeCompatCache,
		"rangeCompatTtlMinutes":           cfg.RangeCompatTTL,
		"rangeCompatMinFailures":          cfg.RangeCompatMinFailures,
		"rangeSkipMaxBytes":               cfg.RangeSkipMaxBytes,
		"enableParallelDecrypt":           cfg.EnableParallelDecrypt,
		"parallelDecryptConcurrency":      cfg.ParallelDecryptConcurrency,
		"streamBufferKb":                  cfg.StreamBufferKB,
		"webdavNegativeCacheTtlMinutes":   cfg.WebDAVNegativeCacheTTLMinutes,
		"enableH2C":                       cfg.EnableH2C,
		"enableDbExportSync":              cfg.EnableDBExportSync,
		"dbExportBaseUrl":                 cfg.DBExportBaseURL,
		"dbExportSyncIntervalSeconds":     cfg.DBExportSyncIntervalSeconds,
		"dbExportAuthEnabled":             cfg.DBExportAuthEnabled,
		"dbExportUsername":                cfg.DBExportUsername,
		"dbExportPassword":                cfg.DBExportPassword,
		"enableSizeMap":                   cfg.EnableSizeMap,
		"sizeMapTtlMinutes":               cfg.SizeMapTTL,
		"streamEngineVersion":             cfg.StreamEngineVersion,
		"localSizeRetentionDays":          cfg.LocalSizeRetentionDays,
		"localStrategyRetentionDays":      cfg.LocalStrategyRetentionDays,
		"debugEnabled":                    cfg.DebugEnabled,
		"debugLevel":                      cfg.DebugLevel,
		"debugMaskSensitive":              cfg.DebugMaskSensitive,
		"debugSampleRate":                 cfg.DebugSampleRate,
		"debugLogBodyBytes":               cfg.DebugLogBodyBytes,
		"encryptPaths":                    paths,
	}
}

func parseIntAny(v any) (int, bool) {
	switch t := v.(type) {
	case float64:
		return int(t), true
	case int:
		return t, true
	case int64:
		return int(t), true
	case string:
		x, err := strconv.Atoi(strings.TrimSpace(t))
		return x, err == nil
	default:
		return 0, false
	}
}

func parseInt64Any(v any) (int64, bool) {
	switch t := v.(type) {
	case float64:
		return int64(t), true
	case int:
		return int64(t), true
	case int64:
		return t, true
	case string:
		x, err := strconv.ParseInt(strings.TrimSpace(t), 10, 64)
		return x, err == nil
	default:
		return 0, false
	}
}

func clampInt(v, minV, maxV int) int {
	if v < minV {
		return minV
	}
	if v > maxV {
		return maxV
	}
	return v
}

func clampInt64(v, minV, maxV int64) int64 {
	if v < minV {
		return minV
	}
	if v > maxV {
		return maxV
	}
	return v
}

func (p *ProxyServer) applyConfigV2Body(body map[string]any) {
	if p == nil || p.config == nil {
		return
	}
	if v, ok := body["alistHost"].(string); ok {
		p.config.AlistHost = strings.TrimSpace(v)
	}
	if v, ok := parseIntAny(body["alistPort"]); ok {
		p.config.AlistPort = clampInt(v, 1, 65535)
	}
	if v, ok := body["alistHttps"].(bool); ok {
		p.config.AlistHttps = v
	}
	if v, ok := parseIntAny(body["proxyPort"]); ok {
		p.config.ProxyPort = clampInt(v, 1, 65535)
	}
	if v, ok := parseIntAny(body["upstreamTimeoutSeconds"]); ok {
		p.config.UpstreamTimeoutSeconds = clampInt(v, 2, 120)
	}
	if v, ok := parseIntAny(body["probeTimeoutSeconds"]); ok {
		p.config.ProbeTimeoutSeconds = clampInt(v, 1, 30)
	}
	if v, ok := parseIntAny(body["probeBudgetSeconds"]); ok {
		p.config.ProbeBudgetSeconds = clampInt(v, 1, 60)
	}
	if v, ok := parseIntAny(body["upstreamBackoffSeconds"]); ok {
		p.config.UpstreamBackoffSeconds = clampInt(v, 1, 300)
	}
	if v, ok := body["enableLocalBypass"].(bool); ok {
		p.config.EnableLocalBypass = v
	}
	if v, ok := body["routingMode"].(string); ok {
		p.config.RoutingMode = normalizeRoutingMode(v)
	}
	if v, ok := body["providerRuleSource"].(string); ok {
		p.config.ProviderRuleSource = strings.TrimSpace(v)
	}
	if v, ok := body["routingUnmatchedDefault"].(string); ok {
		p.config.RoutingUnmatchedDefault = normalizeRoutingUnmatchedDefault(v)
	}
	if v, ok := body["providerCatalogEnabled"].(bool); ok {
		p.config.ProviderCatalogEnabled = v
	}
	if v, ok := parseIntAny(body["providerCatalogTtlMinutes"]); ok {
		p.config.ProviderCatalogTTLMinutes = clampInt(v, 5, 10080)
	}
	if v, ok := body["providerCatalogBootstrapOnStart"].(bool); ok {
		p.config.ProviderCatalogBootstrapOnStart = v
	}
	if v, ok := parseIntAny(body["storageMapRefreshMinutes"]); ok {
		p.config.StorageMapRefreshMinutes = clampInt(v, 1, 1440)
	}
	if v, ok := body["playFirstFallback"].(bool); ok {
		p.config.PlayFirstFallback = v
	}
	if v, ok := body["enableRangeCompatCache"].(bool); ok {
		p.config.EnableRangeCompatCache = v
	}
	if v, ok := parseIntAny(body["rangeCompatTtlMinutes"]); ok {
		p.config.RangeCompatTTL = clampInt(v, 1, 43200)
	}
	if v, ok := parseIntAny(body["rangeCompatMinFailures"]); ok {
		p.config.RangeCompatMinFailures = clampInt(v, 1, 20)
	}
	if v, ok := parseInt64Any(body["rangeSkipMaxBytes"]); ok {
		p.config.RangeSkipMaxBytes = clampInt64(v, 1<<20, 2<<30)
	}
	if v, ok := body["enableParallelDecrypt"].(bool); ok {
		p.config.EnableParallelDecrypt = v
	}
	if v, ok := parseIntAny(body["parallelDecryptConcurrency"]); ok {
		p.config.ParallelDecryptConcurrency = clampInt(v, 1, 32)
	}
	if v, ok := parseIntAny(body["streamBufferKb"]); ok {
		p.config.StreamBufferKB = clampInt(v, 64, 4096)
	}
	if v, ok := parseIntAny(body["webdavNegativeCacheTtlMinutes"]); ok {
		p.config.WebDAVNegativeCacheTTLMinutes = clampInt(v, 1, 1440)
	}
	if v, ok := body["enableH2C"].(bool); ok {
		p.config.EnableH2C = v
	}
	if v, ok := body["enableDbExportSync"].(bool); ok {
		p.config.EnableDBExportSync = v
	}
	if v, ok := body["dbExportBaseUrl"].(string); ok {
		p.config.DBExportBaseURL = strings.TrimSpace(v)
	}
	if v, ok := parseIntAny(body["dbExportSyncIntervalSeconds"]); ok {
		p.config.DBExportSyncIntervalSeconds = clampInt(v, minDBExportSyncIntervalSecs, 3600)
	}
	if v, ok := body["dbExportAuthEnabled"].(bool); ok {
		p.config.DBExportAuthEnabled = v
	}
	if v, ok := body["dbExportUsername"].(string); ok {
		p.config.DBExportUsername = strings.TrimSpace(v)
	}
	if v, ok := body["dbExportPassword"].(string); ok {
		p.config.DBExportPassword = v
	}
	if v, ok := body["enableSizeMap"].(bool); ok {
		p.config.EnableSizeMap = v
	}
	if v, ok := parseIntAny(body["sizeMapTtlMinutes"]); ok {
		p.config.SizeMapTTL = clampInt(v, 1, 43200)
	}
	if v, ok := parseIntAny(body["streamEngineVersion"]); ok {
		p.config.StreamEngineVersion = clampInt(v, 1, 2)
	}
	if v, ok := parseIntAny(body["localSizeRetentionDays"]); ok {
		p.config.LocalSizeRetentionDays = clampInt(v, 1, 3650)
	}
	if v, ok := parseIntAny(body["localStrategyRetentionDays"]); ok {
		p.config.LocalStrategyRetentionDays = clampInt(v, 1, 3650)
	}
	if v, ok := body["debugEnabled"].(bool); ok {
		p.config.DebugEnabled = v
	}
	if v, ok := body["debugLevel"].(string); ok {
		p.config.DebugLevel = strings.TrimSpace(v)
	}
	if v, ok := body["debugMaskSensitive"].(bool); ok {
		p.config.DebugMaskSensitive = v
	}
	if v, ok := parseIntAny(body["debugSampleRate"]); ok {
		p.config.DebugSampleRate = clampInt(v, 1, 100)
	}
	if v, ok := parseIntAny(body["debugLogBodyBytes"]); ok {
		p.config.DebugLogBodyBytes = clampInt(v, 0, 1<<20)
	}

	if paths, ok := body["encryptPaths"].([]interface{}); ok {
		next := make([]*EncryptPath, 0, len(paths))
		for _, raw := range paths {
			item, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			pathVal, _ := item["path"].(string)
			encType, _ := item["encType"].(string)
			encName, _ := item["encName"].(bool)
			encSuffix, _ := item["encSuffix"].(string)
			enable, _ := item["enable"].(bool)
			if strings.TrimSpace(pathVal) == "" {
				continue
			}
			next = append(next, &EncryptPath{
				Path:      strings.TrimSpace(pathVal),
				Password:  "",
				EncType:   EncryptionType(strings.TrimSpace(encType)),
				EncName:   encName,
				EncSuffix: strings.TrimSpace(encSuffix),
				Enable:    enable,
			})
		}
		if len(next) > 0 {
			for i := range next {
				if i < len(p.config.EncryptPaths) && p.config.EncryptPaths[i] != nil {
					next[i].Password = p.config.EncryptPaths[i].Password
				}
			}
			p.config.EncryptPaths = next
		}
	}

	if rules, ok := body["providerRoutingRules"].([]interface{}); ok {
		nextRules := make([]ProviderRoutingRule, 0, len(rules))
		for _, raw := range rules {
			item, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			matchType, _ := item["matchType"].(string)
			matchValue, _ := item["matchValue"].(string)
			matchValues := make([]string, 0, 4)
			if mv, ok := item["matchValues"].([]interface{}); ok {
				for _, rawValue := range mv {
					s, _ := rawValue.(string)
					s = normalizeProviderToken(s)
					if s == "" {
						continue
					}
					matchValues = append(matchValues, s)
				}
			}
			if len(matchValues) == 0 {
				matchValue = normalizeProviderToken(matchValue)
				if matchValue != "" {
					matchValues = append(matchValues, matchValue)
				}
			}
			action, _ := item["action"].(string)
			enabled, okEnabled := item["enabled"].(bool)
			if !okEnabled {
				enabled = true
			}
			priority, _ := parseIntAny(item["priority"])
			id, _ := item["id"].(string)
			if len(matchValues) == 0 {
				continue
			}
			nextRules = append(nextRules, ProviderRoutingRule{
				ID:          strings.TrimSpace(id),
				MatchType:   normalizeRoutingMatchType(matchType),
				MatchValue:  matchValues[0],
				MatchValues: matchValues,
				Action:      normalizeRoutingAction(action),
				Enabled:     enabled,
				Priority:    priority,
			})
		}
		p.config.ProviderRoutingRules = nextRules
	}

	applyLearningDefaults(p.config)
}

func (p *ProxyServer) handleConfigV2Schema(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 200,
		"data": map[string]interface{}{
			"version": 2,
			"docs":    configV2Docs(),
		},
	})
}

func (p *ProxyServer) handleConfigV2(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 200,
			"data": configV2Data{Version: 2, Config: p.exportConfigV2()},
		})
		return
	case http.MethodPost:
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		cfg := body
		if wrapped, ok := body["config"].(map[string]interface{}); ok {
			cfg = wrapped
		}
		p.mutex.Lock()
		if p.config == nil {
			p.config = DefaultConfig()
		}
		p.applyConfigV2Body(cfg)
		p.rebuildEncryptPathIndex()
		p.mutex.Unlock()

		if err := p.persistConfigSnapshot(); err != nil {
			log.Warnf("[%s] persist v2 config failed: %v", internal.TagConfig, err)
			http.Error(w, fmt.Sprintf("save config failed: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 200,
			"data": configV2Data{Version: 2, Config: p.exportConfigV2()},
		})
		return
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
}
