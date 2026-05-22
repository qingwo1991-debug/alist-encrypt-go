package encrypt

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/OpenListTeam/OpenList/v4/openlistlib/internal"
	log "github.com/sirupsen/logrus"
)

const providerCatalogMetaLastRefresh = "provider_catalog_last_refresh_at"

func cloneRoutingHeaders(src http.Header) http.Header {
	if src == nil {
		return http.Header{}
	}
	dst := make(http.Header, len(src))
	for k, values := range src {
		for _, v := range values {
			dst.Add(k, v)
		}
	}
	return dst
}

func (p *ProxyServer) providerCatalogEnabled() bool {
	return p != nil && p.config != nil && p.config.ProviderCatalogEnabled
}

func (p *ProxyServer) providerCatalogTTL() time.Duration {
	if p == nil || p.config == nil || p.config.ProviderCatalogTTLMinutes <= 0 {
		return 12 * time.Hour
	}
	return time.Duration(p.config.ProviderCatalogTTLMinutes) * time.Minute
}

func (p *ProxyServer) initProviderCatalog() {
	if p == nil {
		return
	}
	now := time.Now()
	p.routingMu.Lock()
	if p.providerCatalog == nil {
		p.providerCatalog = make(map[string]string)
	}
	if p.providerSourceMask == nil {
		p.providerSourceMask = make(map[string]int)
	}
	for key, label := range builtinProviderCatalog {
		p.providerCatalog[key] = label
		p.providerSourceMask[key] |= providerSourceBuiltin
	}
	p.catalogNextRefresh = now
	p.routingMu.Unlock()

	if p.localStore != nil {
		if rows, err := p.localStore.ListProviderCatalog(); err == nil {
			p.mergeProviderCatalogRows(rows)
		}
		if value, _, err := p.localStore.GetMeta(providerCatalogMetaLastRefresh); err == nil && strings.TrimSpace(value) != "" {
			if ts, parseErr := time.Parse(time.RFC3339, value); parseErr == nil {
				p.routingMu.Lock()
				p.catalogLastRefresh = ts
				p.catalogNextRefresh = ts.Add(p.providerCatalogTTL())
				p.routingMu.Unlock()
			}
		}
	}

	if p.providerCatalogEnabled() && p.config.ProviderCatalogBootstrapOnStart {
		p.refreshProviderCatalogAsync(nil, true)
	}
}

func (p *ProxyServer) mergeProviderCatalogRows(rows []LocalProviderCatalogRecord) {
	if p == nil || len(rows) == 0 {
		return
	}
	p.routingMu.Lock()
	for _, row := range rows {
		key := normalizeProviderToken(row.ProviderKey)
		if key == "" {
			continue
		}
		if strings.TrimSpace(row.DisplayName) != "" {
			p.providerCatalog[key] = row.DisplayName
		}
		p.providerSourceMask[key] |= row.SourceMask
	}
	p.routingMu.Unlock()
}

func (p *ProxyServer) mergeProviderCatalog(provider string, label string, sourceMask int) {
	if p == nil {
		return
	}
	key := normalizeProviderToken(provider)
	if key == "" {
		return
	}
	label = strings.TrimSpace(label)
	if label == "" {
		label = buildProviderLabel(key)
	}
	p.routingMu.Lock()
	if p.providerCatalog == nil {
		p.providerCatalog = make(map[string]string)
	}
	if p.providerSourceMask == nil {
		p.providerSourceMask = make(map[string]int)
	}
	if label != "" {
		p.providerCatalog[key] = label
	} else if _, ok := p.providerCatalog[key]; !ok {
		p.providerCatalog[key] = ""
	}
	p.providerSourceMask[key] |= sourceMask
	p.routingMu.Unlock()
}

func (p *ProxyServer) refreshProviderCatalogAsync(srcHeaders http.Header, force bool) {
	if p == nil || !p.providerCatalogEnabled() {
		return
	}
	p.routingMu.Lock()
	if p.catalogRefreshing {
		p.routingMu.Unlock()
		return
	}
	if !force && !p.catalogNextRefresh.IsZero() && time.Now().Before(p.catalogNextRefresh) {
		p.routingMu.Unlock()
		return
	}
	p.catalogRefreshing = true
	p.routingMu.Unlock()
	headers := cloneRoutingHeaders(srcHeaders)
	go func() {
		defer recoverBackgroundTask("provider_catalog_refresh")
		defer func() {
			p.routingMu.Lock()
			p.catalogRefreshing = false
			p.routingMu.Unlock()
		}()
		p.refreshProviderCatalog(context.Background(), headers)
	}()
}

func (p *ProxyServer) maybeRefreshProviderCatalog(srcHeaders http.Header) {
	p.refreshProviderCatalogAsync(srcHeaders, false)
}

func (p *ProxyServer) refreshProviderCatalog(ctx context.Context, srcHeaders http.Header) {
	if p == nil {
		return
	}
	startedAt := time.Now()
	sourceEntries := make([]LocalProviderCatalogRecord, 0, 256)
	seen := make(map[string]struct{}, 256)
	appendEntry := func(provider string, label string, sourceMask int) {
		key := normalizeProviderToken(provider)
		if key == "" {
			return
		}
		label = strings.TrimSpace(label)
		if label == "" {
			label = buildProviderLabel(key)
		}
		if _, ok := seen[key]; ok {
			if label != "" {
				for i := range sourceEntries {
					if sourceEntries[i].ProviderKey == key && strings.TrimSpace(sourceEntries[i].DisplayName) == "" {
						sourceEntries[i].DisplayName = label
						break
					}
				}
			}
			return
		}
		seen[key] = struct{}{}
		sourceEntries = append(sourceEntries, LocalProviderCatalogRecord{
			ProviderKey: key,
			DisplayName: label,
			SourceMask:  sourceMask,
			FirstSeenAt: startedAt.Unix(),
			LastSeenAt:  startedAt.Unix(),
			UpdatedAt:   startedAt.Unix(),
		})
	}

	for provider, label := range builtinProviderCatalog {
		appendEntry(provider, label, providerSourceBuiltin)
	}

	p.routingMu.RLock()
	for provider := range p.seenProviders {
		appendEntry(provider, "", providerSourceSeen)
	}
	p.routingMu.RUnlock()

	driverNames, degradedDriverNames := p.fetchAdminDriverNames(ctx, srcHeaders)
	for _, driver := range driverNames {
		appendEntry(driver, "", providerSourceDriverNames)
	}

	p.refreshStorageDriverMapIfNeeded(ctx, srcHeaders)
	p.routingMu.RLock()
	for _, driver := range p.storageDriverMap {
		appendEntry(driver, "", providerSourceStorage)
	}
	p.routingMu.RUnlock()

	remoteProviders, remoteLabels, remoteDegraded := p.tryFetchRemoteProviderRoutingCandidates(ctx)
	for _, provider := range remoteProviders {
		appendEntry(provider, remoteLabels[provider], providerSourceRemote)
	}

	if len(sourceEntries) == 0 {
		p.routingMu.Lock()
		p.catalogLastError = "provider catalog refresh produced empty result"
		p.catalogNextRefresh = startedAt.Add(15 * time.Minute)
		p.routingMu.Unlock()
		return
	}

	if p.localStore != nil {
		if err := p.localStore.UpsertProviderCatalog(sourceEntries); err != nil {
			log.Warnf("[%s] provider catalog upsert failed: %v", internal.TagCache, err)
		}
		_ = p.localStore.SetMeta(providerCatalogMetaLastRefresh, startedAt.Format(time.RFC3339))
	}

	p.routingMu.Lock()
	if p.providerCatalog == nil {
		p.providerCatalog = make(map[string]string, len(sourceEntries))
	}
	if p.providerSourceMask == nil {
		p.providerSourceMask = make(map[string]int, len(sourceEntries))
	}
	for _, entry := range sourceEntries {
		if strings.TrimSpace(entry.DisplayName) != "" {
			p.providerCatalog[entry.ProviderKey] = entry.DisplayName
		} else if _, ok := p.providerCatalog[entry.ProviderKey]; !ok {
			p.providerCatalog[entry.ProviderKey] = ""
		}
		p.providerSourceMask[entry.ProviderKey] |= entry.SourceMask
	}
	p.catalogLastRefresh = startedAt
	p.catalogNextRefresh = startedAt.Add(p.providerCatalogTTL())
	if degradedDriverNames || remoteDegraded {
		p.catalogLastError = "partial refresh: some sources degraded"
	} else {
		p.catalogLastError = ""
	}
	p.routingMu.Unlock()
}

func (p *ProxyServer) providerCatalogSnapshot() ([]string, map[string]string, map[string]int, time.Time, time.Time, string) {
	if p == nil {
		return []string{}, map[string]string{}, map[string]int{}, time.Time{}, time.Time{}, ""
	}
	p.routingMu.RLock()
	defer p.routingMu.RUnlock()
	providers := make([]string, 0, len(p.providerCatalog))
	labels := make(map[string]string, len(p.providerCatalog))
	sources := make(map[string]int, len(p.providerSourceMask))
	for provider, label := range p.providerCatalog {
		providers = append(providers, provider)
		if strings.TrimSpace(label) != "" {
			labels[provider] = label
		}
	}
	for provider, mask := range p.providerSourceMask {
		sources[provider] = mask
	}
	sort.Strings(providers)
	return providers, labels, sources, p.catalogLastRefresh, p.catalogNextRefresh, p.catalogLastError
}
