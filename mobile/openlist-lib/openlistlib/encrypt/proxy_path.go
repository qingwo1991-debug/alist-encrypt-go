package encrypt

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/OpenListTeam/OpenList/v4/openlistlib/internal"
	log "github.com/sirupsen/logrus"
)

// 流式传输优化常量

func normalizeRoutingUnmatchedDefault(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case routingActionDirect:
		return routingActionDirect
	default:
		return routingActionProxy
	}
}

func normalizeRoutingMode(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", routingModeByProvider:
		return routingModeByProvider
	case routingModeOff:
		return routingModeOff
	default:
		return routingModeByProvider
	}
}

func normalizeRoutingAction(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case routingActionProxy:
		return routingActionProxy
	default:
		return routingActionDirect
	}
}

func normalizeRoutingMatchType(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case routingMatchDriver:
		return routingMatchDriver
	default:
		return routingMatchProvider
	}
}

func normalizeRoutingMatchValues(rule *ProviderRoutingRule) []string {
	if rule == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(rule.MatchValues)+1)
	out := make([]string, 0, len(rule.MatchValues)+1)
	for _, raw := range rule.MatchValues {
		v := normalizeProviderToken(raw)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	legacy := normalizeProviderToken(rule.MatchValue)
	if legacy != "" {
		if _, ok := seen[legacy]; !ok {
			out = append(out, legacy)
		}
	}
	if len(out) > 0 {
		rule.MatchValue = out[0]
	} else {
		rule.MatchValue = ""
	}
	return out
}

func sortRoutingRules(rules []ProviderRoutingRule) {
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Priority == rules[j].Priority {
			return rules[i].ID < rules[j].ID
		}
		return rules[i].Priority < rules[j].Priority
	})
}

func matchRoutingRules(cfg *ProxyConfig, provider, driver string) (string, bool) {
	if cfg == nil || len(cfg.ProviderRoutingRules) == 0 {
		return "", false
	}
	rules := make([]ProviderRoutingRule, 0, len(cfg.ProviderRoutingRules))
	rules = append(rules, cfg.ProviderRoutingRules...)
	sortRoutingRules(rules)
	p := normalizeProviderToken(provider)
	d := normalizeProviderToken(driver)
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		matchType := normalizeRoutingMatchType(rule.MatchType)
		matchValues := normalizeRoutingMatchValues(&rule)
		if len(matchValues) == 0 {
			continue
		}
		for _, matchValue := range matchValues {
			switch matchType {
			case routingMatchDriver:
				if d == matchValue {
					return normalizeRoutingAction(rule.Action), true
				}
			default:
				if p == matchValue {
					return normalizeRoutingAction(rule.Action), true
				}
			}
		}
	}
	return "", false
}

func matchBuiltinRouting(provider, driver string) (string, bool) {
	p := normalizeProviderToken(provider)
	d := normalizeProviderToken(driver)
	if _, ok := builtinDirectProviders[p]; ok {
		return routingActionDirect, true
	}
	if _, ok := builtinProxyProviders[p]; ok {
		return routingActionProxy, true
	}
	if _, ok := builtinDirectProviders[d]; ok {
		return routingActionDirect, true
	}
	if _, ok := builtinProxyProviders[d]; ok {
		return routingActionProxy, true
	}
	return "", false
}

func newProxyResolver(config *ProxyConfig) func(*http.Request) (*url.URL, error) {
	envProxyFunc := http.ProxyFromEnvironment
	return func(req *http.Request) (*url.URL, error) {
		if req == nil || req.URL == nil {
			return nil, nil
		}
		if config == nil {
			return envProxyFunc(req)
		}
		mode := normalizeRoutingMode(config.RoutingMode)
		host := req.URL.Hostname()
		provider := req.Header.Get("X-Encrypt-Provider")
		driver := req.Header.Get("X-Encrypt-Driver")

		if config.EnableLocalBypass && isLocalOrPrivateHost(host) {
			return nil, nil
		}

		if mode != routingModeOff {
			if action, ok := matchRoutingRules(config, provider, driver); ok {
				if action == routingActionDirect {
					return nil, nil
				}
				return envProxyFunc(req)
			}
			if action, ok := matchBuiltinRouting(provider, driver); ok {
				if action == routingActionDirect {
					return nil, nil
				}
				return envProxyFunc(req)
			}
			if normalizeRoutingUnmatchedDefault(config.RoutingUnmatchedDefault) == routingActionDirect {
				return nil, nil
			}
		}

		return envProxyFunc(req)
	}
}

// EncryptPath 加密路径配置
type EncryptPath struct {
	Path      string         `json:"path"`                // 路径正则表达式
	Password  string         `json:"password"`            // 加密密码
	EncType   EncryptionType `json:"encType"`             // 加密类型
	EncName   bool           `json:"encName"`             // 是否加密文件名
	EncSuffix string         `json:"encSuffix,omitempty"` // 加密文件统一后缀（如 .bin）
	Enable    bool           `json:"enable"`              // 是否启用
	regex     *regexp.Regexp // 编译后的正则表达式
	prefix    string         // 可走快速前缀匹配的规则前缀
}

type ProviderRoutingRule struct {
	ID          string   `json:"id,omitempty"`
	MatchType   string   `json:"matchType"`
	MatchValue  string   `json:"matchValue"`
	MatchValues []string `json:"matchValues,omitempty"`
	Action      string   `json:"action"`
	Enabled     bool     `json:"enabled"`
	Priority    int      `json:"priority"`
}

func appendUniquePath(dst []string, seen map[string]struct{}, candidate string) []string {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return dst
	}
	candidate = path.Clean(candidate)
	if _, ok := seen[candidate]; ok {
		return dst
	}
	seen[candidate] = struct{}{}
	return append(dst, candidate)
}

func buildRealPathCandidates(ep *EncryptPath, inputPath string) []string {
	seen := make(map[string]struct{}, 8)
	candidates := make([]string, 0, 8)
	inputPath = strings.TrimSpace(inputPath)
	if inputPath == "" {
		return candidates
	}
	candidates = appendUniquePath(candidates, seen, inputPath)
	if decoded, err := url.PathUnescape(inputPath); err == nil && strings.TrimSpace(decoded) != "" {
		candidates = appendUniquePath(candidates, seen, decoded)
	}
	if ep == nil {
		return candidates
	}
	joinCandidate := func(sourcePath, candidateName string) string {
		candidateName = strings.TrimSpace(candidateName)
		if candidateName == "" {
			return ""
		}
		if strings.HasPrefix(candidateName, "/") {
			return candidateName
		}
		return path.Join(path.Dir(sourcePath), candidateName)
	}
	candidates = appendUniquePath(candidates, seen, joinCandidate(inputPath, convertRealNameByRule(ep, inputPath)))
	candidates = appendUniquePath(candidates, seen, joinCandidate(inputPath, ConvertRealNameWithSuffix(ep.Password, ep.EncType, inputPath, "")))

	dirPath := path.Dir(inputPath)
	fileName := path.Base(inputPath)
	ext := path.Ext(fileName)
	base := strings.TrimSuffix(fileName, ext)

	if idx := strings.Index(base, suffixMarker); idx != -1 {
		if endIdx := strings.Index(base[idx:], suffixMarkerEnd); endIdx != -1 {
			cleanBase := base[:idx] + base[idx+endIdx+1:]
			cleaned := path.Join(dirPath, cleanBase+ext)
			candidates = appendUniquePath(candidates, seen, cleaned)
			candidates = appendUniquePath(candidates, seen, joinCandidate(cleaned, convertRealNameByRule(ep, cleaned)))
			candidates = appendUniquePath(candidates, seen, joinCandidate(cleaned, ConvertRealNameWithSuffix(ep.Password, ep.EncType, cleaned, "")))
		}
	}

	strippedBase, suffix := stripExternalSuffix(base)
	if suffix != "" && strings.TrimSpace(strippedBase) != "" {
		stripped := path.Join(dirPath, strippedBase+ext)
		candidates = appendUniquePath(candidates, seen, stripped)
		candidates = appendUniquePath(candidates, seen, joinCandidate(stripped, convertRealNameByRule(ep, stripped)))
		candidates = appendUniquePath(candidates, seen, joinCandidate(stripped, ConvertRealNameWithSuffix(ep.Password, ep.EncType, stripped, "")))
	}
	return candidates
}

func (p *ProxyServer) rebuildEncryptPathIndex() {
	if p == nil || p.config == nil {
		return
	}
	rules := make([]encryptPrefixRule, 0, len(p.config.EncryptPaths))
	for _, ep := range p.config.EncryptPaths {
		if ep == nil || !ep.Enable || ep.prefix == "" {
			continue
		}
		rules = append(rules, encryptPrefixRule{prefix: ep.prefix, ep: ep})
	}
	sort.SliceStable(rules, func(i, j int) bool {
		return len(rules[i].prefix) > len(rules[j].prefix)
	})
	p.prefixRules = rules
}

func (p *ProxyServer) forceProbeRemoteFileSizeWithPath(targetURL string, headers http.Header, encPathPattern string) int64 {
	ctx, cancel := context.WithTimeout(context.Background(), p.probeBudget())
	defer cancel()
	scopeKey := p.probeScopeKey(encPathPattern, targetURL)
	methods := p.prioritizeProbeMethods(scopeKey, []ProbeMethod{ProbeMethodRange, ProbeMethodHead, ProbeMethodWebDAV})
	for _, method := range methods {
		size := p.probeWithMethodCtx(ctx, method, targetURL, headers)
		success := size > 0
		probeMethodStats.record(scopeKey, method, success, false)
		if success {
			p.updateProbeStrategy(scopeKey, method)
			return size
		}
		p.markProbeStrategyFailure(scopeKey, method)
		if ctx.Err() != nil {
			return 0
		}
	}
	return 0
}

// probeRemoteFileSizeWithPath 带加密路径的探测（支持策略学习）
func (p *ProxyServer) probeRemoteFileSizeWithPath(targetURL string, headers http.Header, encPathPattern string) int64 {
	if p.config != nil && !p.config.ProbeOnDownload {
		return 0
	}
	scopeKey := p.probeScopeKey(encPathPattern, targetURL)

	// 如果有学习到的策略，优先使用
	if strategy := p.getProbeStrategy(scopeKey); strategy != nil {
		strategy.mutex.Lock()
		method := strategy.Method
		successCount := strategy.SuccessCount
		strategy.mutex.Unlock()
		if successCount >= p.probeStrategyStableThreshold() {
			mctx, cancel := context.WithTimeout(context.Background(), p.probeTimeout())
			size := p.probeWithMethodCtx(mctx, method, targetURL, headers)
			cancel()
			if size > 0 {
				p.updateProbeStrategy(scopeKey, method)
				probeMethodStats.record(scopeKey, method, true, true)
				log.Debugf("[%s] Probe strategy cache hit: scope=%s method=%s size=%d", internal.TagCache, scopeKey, method, size)
				return size
			}
			// 策略失败，标记失败次数，达到阈值后清除并重学
			log.Debugf("[%s] Probe strategy cache miss (method failed): scope=%s method=%s", internal.TagCache, scopeKey, method)
			probeMethodStats.record(scopeKey, method, false, false)
			p.markProbeStrategyFailure(scopeKey, method)
		}
	}

	// 根据配置或默认策略决定尝试顺序
	// 默认使用 Range 优先（兼容性更好，大多数网盘都支持）
	rangeFirst := true
	if p.config != nil && p.config.ProbeStrategy == "head" {
		rangeFirst = false
	}

	methods := []ProbeMethod{ProbeMethodRange, ProbeMethodHead, ProbeMethodWebDAV}
	if rangeFirst {
		methods = []ProbeMethod{ProbeMethodRange, ProbeMethodHead, ProbeMethodWebDAV}
	} else {
		methods = []ProbeMethod{ProbeMethodHead, ProbeMethodRange, ProbeMethodWebDAV}
	}
	methods = p.prioritizeProbeMethods(scopeKey, methods)

	for _, method := range methods {
		mctx, cancel := context.WithTimeout(context.Background(), p.probeTimeout())
		size := p.probeWithMethodCtx(mctx, method, targetURL, headers)
		cancel()
		success := size > 0
		probeMethodStats.record(scopeKey, method, success, false)
		if success {
			// 学习成功的策略
			p.updateProbeStrategy(scopeKey, method)
			log.Debugf("[%s] Probe strategy learned: scope=%s method=%s size=%d", internal.TagCache, scopeKey, method, size)
			return size
		}
	}
	return 0
}

func (p *ProxyServer) fetchWebDAVFileSizeWithPath(targetURL string, headers http.Header, encPathPattern string) int64 {
	ctx, cancel := context.WithTimeout(context.Background(), p.probeTimeout())
	defer cancel()
	size := p.fetchWebDAVFileSizeCtx(ctx, targetURL, headers)
	scopeKey := p.probeScopeKey(encPathPattern, targetURL)
	success := size > 0
	probeMethodStats.record(scopeKey, ProbeMethodWebDAV, success, false)
	if success {
		p.updateProbeStrategy(scopeKey, ProbeMethodWebDAV)
	} else {
		p.markProbeStrategyFailure(scopeKey, ProbeMethodWebDAV)
	}
	return size
}

// findEncryptPath 查找匹配的加密路径配置
func (p *ProxyServer) findEncryptPath(filePath string) *EncryptPath {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	log.Debugf("[%s] Checking encryption path for: %q (len=%d)", internal.TagProxy, filePath, len(filePath))

	// 尝试 URL 解码，以防路径被编码
	decodedPath, err := url.PathUnescape(filePath)
	if err != nil {
		decodedPath = filePath
	}

	matchPrefix := func(candidate string) *EncryptPath {
		for _, rule := range p.prefixRules {
			if rule.ep == nil || !rule.ep.Enable {
				continue
			}
			if candidate == rule.prefix || strings.HasPrefix(candidate, rule.prefix+"/") {
				return p.applyFolderOverride(rule.ep, decodedPath)
			}
		}
		return nil
	}
	if ep := matchPrefix(filePath); ep != nil {
		return ep
	}
	if decodedPath != filePath {
		if ep := matchPrefix(decodedPath); ep != nil {
			return ep
		}
	}

	for _, ep := range p.config.EncryptPaths {
		if !ep.Enable {
			continue
		}
		if ep.regex != nil {
			log.Debugf("[%s] Testing rule %q (regex: %s) against %q", internal.TagProxy, ep.Path, ep.regex.String(), filePath)
			if ep.regex.MatchString(filePath) {
				p.debugf("path", "[%s] Matched rule: %s for %s (encType=%q, encName=%v)", internal.TagProxy, ep.Path, filePath, ep.EncType, ep.EncName)
				return p.applyFolderOverride(ep, decodedPath)
			}
			if filePath != decodedPath && ep.regex.MatchString(decodedPath) {
				p.debugf("path", "[%s] Matched rule (decoded): %s for %s (encType=%q, encName=%v)", internal.TagProxy, ep.Path, decodedPath, ep.EncType, ep.EncName)
				return p.applyFolderOverride(ep, decodedPath)
			}
		} else {
			log.Warnf("[%s] Rule %s has nil regex", internal.TagProxy, ep.Path)
		}
	}
	log.Debugf("[%s] No encryption path matched for: %q (decoded: %q)", internal.TagProxy, filePath, decodedPath)
	return nil
}

func (p *ProxyServer) isEncryptDirRoot(filePath string) bool {
	decodedPath, err := url.PathUnescape(filePath)
	if err != nil {
		decodedPath = filePath
	}
	normalized := strings.TrimRight(path.Clean(strings.TrimSpace(decodedPath)), "/")
	if normalized == "." || normalized == "" {
		return false
	}

	p.mutex.RLock()
	defer p.mutex.RUnlock()

	for _, ep := range p.config.EncryptPaths {
		if ep == nil || !ep.Enable {
			continue
		}
		prefix := strings.TrimRight(path.Clean(strings.TrimSpace(ep.prefix)), "/")
		if prefix == "." || prefix == "" {
			continue
		}
		if normalized == prefix {
			return true
		}
	}
	return false
}

func (p *ProxyServer) applyRoutingHints(req *http.Request, provider, driver string) {
	if req == nil {
		return
	}
	if v := strings.TrimSpace(provider); v != "" {
		req.Header.Set("X-Encrypt-Provider", v)
	}
	if v := strings.TrimSpace(driver); v != "" {
		req.Header.Set("X-Encrypt-Driver", v)
	}
}

func mapPathToMountPrefix(pathText string) string {
	p := strings.TrimSpace(pathText)
	if p == "" || p == "/" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		return ""
	}
	return "/" + parts[0]
}

func (p *ProxyServer) inferDriverFromPath(ctx context.Context, originalPath string, srcHeaders http.Header) string {
	mountPrefix := mapPathToMountPrefix(originalPath)
	if mountPrefix == "" {
		return ""
	}
	p.routingMu.RLock()
	driver := p.storageDriverMap[mountPrefix]
	p.routingMu.RUnlock()
	if driver != "" {
		p.noteDriverCandidate(driver)
		return driver
	}
	p.refreshStorageDriverMapIfNeeded(ctx, srcHeaders)
	p.routingMu.RLock()
	driver = p.storageDriverMap[mountPrefix]
	p.routingMu.RUnlock()
	if driver != "" {
		p.noteDriverCandidate(driver)
	}
	return driver
}

func stripEncAPIPath(baseURL string) string {
	b := normalizeDBExportBaseURL(baseURL)
	if b == "" {
		return ""
	}
	lower := strings.ToLower(b)
	if strings.HasSuffix(lower, "/enc-api") {
		return strings.TrimSuffix(b, b[len(b)-len("/enc-api"):])
	}
	return b
}

func (p *ProxyServer) tryFetchRemoteProviderRoutingCandidates(ctx context.Context) ([]string, map[string]string, bool) {
	if p == nil {
		return nil, nil, true
	}
	cfg := p.readDBExportSyncConfig()
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return nil, nil, false
	}
	rootBase := stripEncAPIPath(cfg.BaseURL)
	if rootBase == "" {
		return nil, nil, true
	}
	u, err := url.Parse(rootBase)
	if err == nil && p.config != nil {
		port := u.Port()
		if port == strconv.Itoa(p.config.ProxyPort) {
			host := strings.ToLower(strings.TrimSpace(u.Hostname()))
			if host == "" || host == "127.0.0.1" || host == "localhost" || host == "::1" {
				return nil, nil, false
			}
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(rootBase, "/")+"/api/encrypt/provider-routing-candidates", nil)
	if err != nil {
		return nil, nil, true
	}
	req.Header.Set("X-Encrypt-Routing-Candidates-Fallback", "1")
	if cfg.AuthEnabled {
		token, err := p.dbExportLogin(ctx, cfg)
		if err != nil {
			return nil, nil, true
		}
		if strings.TrimSpace(token) != "" {
			req.Header.Set("Authorizetoken", token)
		}
	}
	resp, err := dbExportSyncHTTPClient.Do(req)
	if err != nil {
		return nil, nil, true
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil, true
	}
	body, err := readLimitedBody(resp.Body, maxBufferedJSONBody)
	if err != nil {
		return nil, nil, true
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, nil, true
	}
	data, _ := payload["data"].(map[string]interface{})
	if data == nil {
		return nil, nil, true
	}
	rawProviders, _ := data["providers"].([]interface{})
	providers := make([]string, 0, len(rawProviders))
	seen := make(map[string]struct{}, len(rawProviders))
	for _, raw := range rawProviders {
		s, _ := raw.(string)
		s = normalizeProviderToken(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		providers = append(providers, s)
	}
	labels := make(map[string]string)
	rawLabels, _ := data["provider_labels"].(map[string]interface{})
	for key, raw := range rawLabels {
		k := normalizeProviderToken(key)
		v := strings.TrimSpace(fmt.Sprintf("%v", raw))
		if k == "" || v == "" {
			continue
		}
		labels[k] = v
	}
	return providers, labels, false
}
