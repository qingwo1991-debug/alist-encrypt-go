package encrypt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/OpenListTeam/OpenList/v4/openlistlib/internal"
	log "github.com/sirupsen/logrus"
)

const (
	dbExportCheckpointName          = "db_export_meta"
	dbExportStrategyCheckpointName  = "db_export_strategy"
	dbExportRangeCheckpointName     = "db_export_range_compat"
	dbExportSyncStatusName          = "db_export_meta"
	dbExportSyncModeFull            = "full"
	dbExportSyncModeSizeOnlyDegrade = "size_only_degraded"
	defaultDBExportSyncIntervalSecs = 300
	minDBExportSyncIntervalSecs     = 30
	defaultDBExportPageLimit        = 1000
	maxDBExportPageLimit            = 5000
	maxDBExportPagesPerCycle        = 200
	maxSyncCycleHistory             = 200
)

var (
	dbExportSyncHTTPClient         = &http.Client{Timeout: 20 * time.Second}
	errDBExportEndpointUnsupported = errors.New("db_export endpoint unsupported")
)

type dbExportSyncConfig struct {
	Enabled         bool
	BaseURL         string
	IntervalSeconds int
	AuthEnabled     bool
	Username        string
	Password        string
}

type dbExportLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type dbExportLoginResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		JWTToken string `json:"jwtToken"`
	} `json:"data"`
}

type dbExportFileMetaResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		Items []struct {
			KeyHash           string `json:"KeyHash"`
			ProviderHost      string `json:"ProviderHost"`
			OriginalPath      string `json:"OriginalPath"`
			EncryptedPath     string `json:"EncryptedPath"`
			Name              string `json:"Name"`
			Size              int64  `json:"Size"`
			CiphertextSize    int64  `json:"CiphertextSize"`
			ContentVersion    int    `json:"ContentVersion"`
			HeaderLen         int64  `json:"HeaderLen"`
			NonceField        []byte `json:"NonceField"`
			RawURL            string `json:"RawURL"`
			Sign              string `json:"Sign"`
			UpdatedAt         string `json:"UpdatedAt"`
			LastAccessed      string `json:"LastAccessed"`
			UpstreamFetchedAt string `json:"UpstreamFetchedAt"`
		} `json:"items"`
		HasMore    bool   `json:"has_more"`
		NextSince  int64  `json:"next_since"`
		NextCursor string `json:"next_cursor"`
	} `json:"data"`
}

type dbExportGenericResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		Items      []map[string]interface{} `json:"items"`
		HasMore    bool                     `json:"has_more"`
		NextSince  int64                    `json:"next_since"`
		NextCursor string                   `json:"next_cursor"`
	} `json:"data"`
}

func normalizeDBExportBaseURL(raw string) string {
	baseURL := strings.TrimSpace(raw)
	if baseURL == "" {
		return ""
	}
	baseURL = strings.TrimRight(baseURL, "/")
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "http://" + baseURL
	}
	return baseURL
}

func buildDBExportAPIURL(baseURL, endpoint string) string {
	b := strings.TrimRight(baseURL, "/")
	if strings.HasSuffix(b, "/enc-api") {
		return b + strings.TrimPrefix(endpoint, "/enc-api")
	}
	return b + endpoint
}

func parseRFC3339Unix(raw string, fallback int64) int64 {
	if strings.TrimSpace(raw) == "" {
		return fallback
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return fallback
	}
	return parsed.Unix()
}

func parseAnyTimeUnix(v interface{}, fallback int64) int64 {
	s := strings.TrimSpace(fmt.Sprintf("%v", v))
	if s == "" || s == "<nil>" {
		return fallback
	}
	if iv, err := strconv.ParseInt(s, 10, 64); err == nil {
		if iv <= 0 {
			return fallback
		}
		return iv
	}
	if ts, err := time.Parse(time.RFC3339, s); err == nil {
		return ts.Unix()
	}
	return fallback
}

func mapString(item map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if v, ok := item[key]; ok {
			s := strings.TrimSpace(fmt.Sprintf("%v", v))
			if s != "" && s != "<nil>" {
				return s
			}
		}
	}
	return ""
}

func mapInt64(item map[string]interface{}, keys ...string) int64 {
	for _, key := range keys {
		if v, ok := item[key]; ok {
			s := strings.TrimSpace(fmt.Sprintf("%v", v))
			if s == "" || s == "<nil>" {
				continue
			}
			if i, err := strconv.ParseInt(s, 10, 64); err == nil {
				return i
			}
		}
	}
	return 0
}

func (p *ProxyServer) readDBExportSyncConfig() dbExportSyncConfig {
	cfg := dbExportSyncConfig{Enabled: false}
	if p == nil {
		return cfg
	}
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	if p.config == nil {
		return cfg
	}
	cfg.Enabled = p.config.EnableDBExportSync
	cfg.BaseURL = normalizeDBExportBaseURL(p.config.DBExportBaseURL)
	cfg.IntervalSeconds = p.config.DBExportSyncIntervalSeconds
	cfg.AuthEnabled = p.config.DBExportAuthEnabled
	cfg.Username = strings.TrimSpace(p.config.DBExportUsername)
	cfg.Password = p.config.DBExportPassword
	return cfg
}

func (p *ProxyServer) dbExportSyncInterval() time.Duration {
	cfg := p.readDBExportSyncConfig()
	secs := cfg.IntervalSeconds
	if secs <= 0 {
		secs = defaultDBExportSyncIntervalSecs
	}
	if secs < minDBExportSyncIntervalSecs {
		secs = minDBExportSyncIntervalSecs
	}
	return time.Duration(secs) * time.Second
}

func (p *ProxyServer) startDBExportSyncLoop() {
	if p == nil || p.metaSyncDone == nil || p.localStore == nil {
		return
	}
	p.metaSyncWG.Add(1)
	go func() {
		defer p.metaSyncWG.Done()
		defer recoverBackgroundTask("db_export_sync_loop")
		timer := time.NewTimer(3 * time.Second)
		defer timer.Stop()
		for {
			select {
			case <-p.metaSyncDone:
				return
			case <-timer.C:
				p.syncDBExportMetaOnce(context.Background())
				timer.Reset(p.dbExportSyncInterval())
			}
		}
	}()
}

func (p *ProxyServer) stopDBExportSyncLoop() {
	if p == nil {
		return
	}
	if p.metaSyncDone != nil {
		close(p.metaSyncDone)
		p.metaSyncDone = nil
	}
	p.metaSyncWG.Wait()
}

func (p *ProxyServer) dbExportLogin(ctx context.Context, cfg dbExportSyncConfig) (string, error) {
	loginURL := buildDBExportAPIURL(cfg.BaseURL, "/enc-api/login")
	payload := dbExportLoginRequest{Username: cfg.Username, Password: cfg.Password}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := dbExportSyncHTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var loginResp dbExportLoginResponse
	if err := json.Unmarshal(respBody, &loginResp); err != nil {
		return "", err
	}

	if loginResp.Code != 0 && loginResp.Code != 200 {
		msg := strings.TrimSpace(loginResp.Msg)
		if msg == "" {
			msg = string(respBody)
		}
		return "", fmt.Errorf("login failed: code=%d msg=%s", loginResp.Code, msg)
	}
	token := strings.TrimSpace(loginResp.Data.JWTToken)
	if token == "" {
		return "", fmt.Errorf("login failed: empty token")
	}
	return token, nil
}

func (p *ProxyServer) fetchDBExportPage(
	ctx context.Context,
	cfg dbExportSyncConfig,
	token string,
	since int64,
	cursor string,
) (*dbExportFileMetaResponse, error) {
	exportURL := buildDBExportAPIURL(cfg.BaseURL, "/enc-api/exportFileMeta")
	parsedURL, err := url.Parse(exportURL)
	if err != nil {
		return nil, err
	}
	q := parsedURL.Query()
	limit := defaultDBExportPageLimit
	if limit > maxDBExportPageLimit {
		limit = maxDBExportPageLimit
	}
	q.Set("limit", strconv.Itoa(limit))
	q.Set("since", strconv.FormatInt(since, 10))
	if strings.TrimSpace(cursor) != "" {
		q.Set("cursor", cursor)
	}
	parsedURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorizetoken", token)
	}

	resp, err := dbExportSyncHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("exportFileMeta http status=%d", resp.StatusCode)
	}
	var apiResp dbExportFileMetaResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, err
	}
	if apiResp.Code != 0 && apiResp.Code != 200 {
		msg := strings.TrimSpace(apiResp.Msg)
		if msg == "" {
			msg = string(respBody)
		}
		return nil, fmt.Errorf("exportFileMeta failed: code=%d msg=%s", apiResp.Code, msg)
	}
	return &apiResp, nil
}

func (p *ProxyServer) fetchDBExportGenericPage(
	ctx context.Context,
	cfg dbExportSyncConfig,
	token string,
	endpoint string,
	since int64,
	cursor string,
) (*dbExportGenericResponse, error) {
	exportURL := buildDBExportAPIURL(cfg.BaseURL, endpoint)
	parsedURL, err := url.Parse(exportURL)
	if err != nil {
		return nil, err
	}
	q := parsedURL.Query()
	limit := defaultDBExportPageLimit
	if limit > maxDBExportPageLimit {
		limit = maxDBExportPageLimit
	}
	q.Set("limit", strconv.Itoa(limit))
	q.Set("since", strconv.FormatInt(since, 10))
	if strings.TrimSpace(cursor) != "" {
		q.Set("cursor", cursor)
	}
	parsedURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorizetoken", token)
	}

	resp, err := dbExportSyncHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusNotImplemented {
		return nil, fmt.Errorf("%w: %s http status=%d", errDBExportEndpointUnsupported, endpoint, resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s http status=%d", endpoint, resp.StatusCode)
	}

	var apiResp dbExportGenericResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, err
	}
	if apiResp.Code != 0 && apiResp.Code != 200 {
		msg := strings.TrimSpace(apiResp.Msg)
		if msg == "" {
			msg = string(respBody)
		}
		if apiResp.Code == 404 || apiResp.Code == 501 {
			return nil, fmt.Errorf("%w: %s code=%d", errDBExportEndpointUnsupported, endpoint, apiResp.Code)
		}
		return nil, fmt.Errorf("%s failed: code=%d msg=%s", endpoint, apiResp.Code, msg)
	}
	return &apiResp, nil
}

func sanitizeSyncError(err error) string {
	if err == nil {
		return ""
	}
	s := strings.TrimSpace(err.Error())
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	if len(s) > 240 {
		s = s[:240]
	}
	return s
}

func (p *ProxyServer) upsertSyncStatus(success bool, imported int, syncMode, errSummary string) {
	if p == nil || p.localStore == nil {
		return
	}
	if strings.TrimSpace(syncMode) == "" {
		syncMode = dbExportSyncModeSizeOnlyDegrade
	}
	if imported < 0 {
		imported = 0
	}
	current, _ := p.localStore.GetSyncStatus(dbExportSyncStatusName)
	totalImported := int64(imported)
	lastSuccessAt := int64(0)
	if current != nil {
		totalImported = current.TotalImported + int64(imported)
		lastSuccessAt = current.LastSuccessAt
	}
	if success {
		lastSuccessAt = time.Now().Unix()
	}
	status := LocalSyncStatusRecord{
		Name:              dbExportSyncStatusName,
		LastSuccessAt:     lastSuccessAt,
		LastCycleImported: imported,
		TotalImported:     totalImported,
		LastError:         strings.TrimSpace(errSummary),
		SyncMode:          syncMode,
		UpdatedAt:         time.Now().Unix(),
	}
	if err := p.localStore.UpsertSyncStatus(status); err != nil {
		log.Warnf("[%s] DB_EXPORT sync status save failed: %v", internal.TagCache, err)
	}
	cycle := LocalSyncCycleRecord{
		CycleAt:      time.Now().Unix(),
		Imported:     imported,
		OK:           success,
		ErrorSummary: strings.TrimSpace(errSummary),
	}
	if err := p.localStore.AppendSyncCycle(dbExportSyncStatusName, cycle, maxSyncCycleHistory); err != nil {
		log.Warnf("[%s] DB_EXPORT sync cycle append failed: %v", internal.TagCache, err)
	}
}

func (p *ProxyServer) syncDBExportMetaEntity(ctx context.Context, cfg dbExportSyncConfig, token string) (int, error) {
	since, cursor, err := p.localStore.GetSyncCheckpoint(dbExportCheckpointName)
	if err != nil {
		log.Warnf("[%s] DB_EXPORT meta checkpoint load failed: %v", internal.TagCache, err)
		since = 0
		cursor = ""
	}

	pageCount := 0
	importedCount := 0
	changedCheckpoint := false
	for pageCount < maxDBExportPagesPerCycle {
		pageCount++
		resp, err := p.fetchDBExportPage(ctx, cfg, token, since, cursor)
		if err != nil {
			return importedCount, err
		}

		payload := &LocalExport{Sizes: make([]LocalSizeRecord, 0, len(resp.Data.Items))}
		nowUnix := time.Now().Unix()
		for _, item := range resp.Data.Items {
			key := strings.TrimSpace(item.KeyHash)
			providerHost := strings.TrimSpace(item.ProviderHost)
			originalPath := strings.TrimSpace(item.OriginalPath)
			if key == "" && providerHost != "" && originalPath != "" {
				key = buildLocalKey(providerHost, originalPath)
			}
			if key == "" || providerHost == "" || originalPath == "" || item.Size <= 0 {
				continue
			}
			updatedAt := parseRFC3339Unix(item.UpdatedAt, nowUnix)
			lastAccessed := parseRFC3339Unix(item.LastAccessed, updatedAt)
			payload.Sizes = append(payload.Sizes, LocalSizeRecord{
				Key:               key,
				ProviderHost:      providerHost,
				OriginalPath:      originalPath,
				EncryptedPath:     strings.TrimSpace(item.EncryptedPath),
				Name:              strings.TrimSpace(item.Name),
				Size:              item.Size,
				CiphertextSize:    item.CiphertextSize,
				ContentVersion:    item.ContentVersion,
				HeaderLen:         item.HeaderLen,
				NonceField:        append([]byte(nil), item.NonceField...),
				RawURL:            strings.TrimSpace(item.RawURL),
				Sign:              strings.TrimSpace(item.Sign),
				UpstreamFetchedAt: parseRFC3339Unix(item.UpstreamFetchedAt, updatedAt),
				LastAccessed:      lastAccessed,
				UpdatedAt:         updatedAt,
			})
		}
		if len(payload.Sizes) > 0 {
			if err := p.localStore.Import(payload); err != nil {
				return importedCount, err
			}
			importedCount += len(payload.Sizes)
		}

		prevSince, prevCursor := since, cursor
		if resp.Data.NextSince > 0 {
			since = resp.Data.NextSince
		}
		cursor = strings.TrimSpace(resp.Data.NextCursor)
		if since != prevSince || cursor != prevCursor {
			changedCheckpoint = true
		}
		if !resp.Data.HasMore {
			break
		}
		if since == prevSince && cursor == prevCursor {
			log.Warnf("[%s] DB_EXPORT meta pagination made no forward progress, stop this cycle", internal.TagCache)
			break
		}
	}

	if changedCheckpoint {
		if err := p.localStore.SaveSyncCheckpoint(dbExportCheckpointName, since, cursor); err != nil {
			log.Warnf("[%s] DB_EXPORT meta checkpoint save failed: %v", internal.TagCache, err)
		}
	}
	return importedCount, nil
}

func (p *ProxyServer) syncDBExportStrategyEntity(ctx context.Context, cfg dbExportSyncConfig, token string) (int, error) {
	since, cursor, err := p.localStore.GetSyncCheckpoint(dbExportStrategyCheckpointName)
	if err != nil {
		since = 0
		cursor = ""
	}

	pageCount := 0
	importedCount := 0
	changedCheckpoint := false
	for pageCount < maxDBExportPagesPerCycle {
		pageCount++
		resp, err := p.fetchDBExportGenericPage(ctx, cfg, token, "/enc-api/exportStrategy", since, cursor)
		if err != nil {
			return importedCount, err
		}
		payload := &LocalExport{Strategies: make([]LocalStrategyRecord, 0, len(resp.Data.Items))}
		nowUnix := time.Now().Unix()
		for _, item := range resp.Data.Items {
			providerHost := mapString(item, "ProviderHost", "provider_host", "providerHost")
			originalPath := mapString(item, "OriginalPath", "original_path", "originalPath")
			networkType := strings.ToLower(mapString(item, "NetworkType", "network_type", "networkType"))
			strategy := strings.ToLower(mapString(item, "Strategy", "strategy"))
			key := mapString(item, "KeyHash", "key_hash", "key", "Key")
			if key == "" && providerHost != "" && originalPath != "" {
				key = buildLocalKey(providerHost, originalPath)
			}
			if key == "" || providerHost == "" || originalPath == "" || networkType == "" || strategy == "" {
				continue
			}
			updatedAt := parseAnyTimeUnix(item["UpdatedAt"], nowUnix)
			lastAccessed := parseAnyTimeUnix(item["LastAccessed"], updatedAt)
			payload.Strategies = append(payload.Strategies, LocalStrategyRecord{
				Key:          key,
				NetworkType:  networkType,
				Strategy:     strategy,
				ProviderHost: providerHost,
				OriginalPath: originalPath,
				LastAccessed: lastAccessed,
				UpdatedAt:    updatedAt,
			})
		}
		if len(payload.Strategies) > 0 {
			if err := p.localStore.Import(payload); err != nil {
				return importedCount, err
			}
			importedCount += len(payload.Strategies)
		}

		prevSince, prevCursor := since, cursor
		if resp.Data.NextSince > 0 {
			since = resp.Data.NextSince
		}
		cursor = strings.TrimSpace(resp.Data.NextCursor)
		if since != prevSince || cursor != prevCursor {
			changedCheckpoint = true
		}
		if !resp.Data.HasMore {
			break
		}
		if since == prevSince && cursor == prevCursor {
			break
		}
	}
	if changedCheckpoint {
		if err := p.localStore.SaveSyncCheckpoint(dbExportStrategyCheckpointName, since, cursor); err != nil {
			log.Warnf("[%s] DB_EXPORT strategy checkpoint save failed: %v", internal.TagCache, err)
		}
	}
	return importedCount, nil
}

func (p *ProxyServer) syncDBExportRangeCompatEntity(ctx context.Context, cfg dbExportSyncConfig, token string) (int, error) {
	since, cursor, err := p.localStore.GetSyncCheckpoint(dbExportRangeCheckpointName)
	if err != nil {
		since = 0
		cursor = ""
	}
	pageCount := 0
	importedCount := 0
	changedCheckpoint := false
	for pageCount < maxDBExportPagesPerCycle {
		pageCount++
		resp, err := p.fetchDBExportGenericPage(ctx, cfg, token, "/enc-api/exportRangeCompat", since, cursor)
		if err != nil {
			return importedCount, err
		}
		for _, item := range resp.Data.Items {
			key := mapString(item, "KeyHash", "key_hash", "key", "Key")
			if key == "" {
				providerHost := mapString(item, "ProviderHost", "provider_host", "providerHost")
				originalPath := mapString(item, "OriginalPath", "original_path", "originalPath")
				if providerHost != "" && originalPath != "" {
					key = buildLocalKey(providerHost, originalPath)
				}
			}
			if key == "" {
				continue
			}
			blockedUntilUnix := parseAnyTimeUnix(item["BlockedUntil"], 0)
			if blockedUntilUnix == 0 {
				blockedUntilUnix = parseAnyTimeUnix(item["blocked_until"], 0)
			}
			failures := int(mapInt64(item, "Failures", "failures", "FailCount", "fail_count"))
			if blockedUntilUnix > 0 {
				if err := p.localStore.UpsertRangeCompat(key, time.Unix(blockedUntilUnix, 0), 0); err != nil {
					return importedCount, err
				}
				importedCount++
				continue
			}
			if failures > 0 {
				if err := p.localStore.UpsertRangeCompat(key, time.Time{}, failures); err != nil {
					return importedCount, err
				}
				importedCount++
			}
		}
		prevSince, prevCursor := since, cursor
		if resp.Data.NextSince > 0 {
			since = resp.Data.NextSince
		}
		cursor = strings.TrimSpace(resp.Data.NextCursor)
		if since != prevSince || cursor != prevCursor {
			changedCheckpoint = true
		}
		if !resp.Data.HasMore {
			break
		}
		if since == prevSince && cursor == prevCursor {
			break
		}
	}
	if changedCheckpoint {
		if err := p.localStore.SaveSyncCheckpoint(dbExportRangeCheckpointName, since, cursor); err != nil {
			log.Warnf("[%s] DB_EXPORT range checkpoint save failed: %v", internal.TagCache, err)
		}
	}
	return importedCount, nil
}

func (p *ProxyServer) syncDBExportMetaOnce(ctx context.Context) {
	if p == nil || p.localStore == nil {
		return
	}
	if GetNetworkState() == NetworkStateOffline {
		return
	}
	cfg := p.readDBExportSyncConfig()
	if !cfg.Enabled {
		return
	}
	if cfg.BaseURL == "" {
		errSummary := "DB_EXPORT sync enabled but base URL is empty"
		log.Warnf("[%s] %s", internal.TagCache, errSummary)
		p.upsertSyncStatus(false, 0, dbExportSyncModeSizeOnlyDegrade, errSummary)
		return
	}
	if cfg.AuthEnabled && (cfg.Username == "" || cfg.Password == "") {
		errSummary := "DB_EXPORT sync auth enabled but username/password is empty"
		log.Warnf("[%s] %s", internal.TagCache, errSummary)
		p.upsertSyncStatus(false, 0, dbExportSyncModeSizeOnlyDegrade, errSummary)
		return
	}

	token := ""
	var err error
	if cfg.AuthEnabled {
		token, err = p.dbExportLogin(ctx, cfg)
		if err != nil {
			errSummary := sanitizeSyncError(fmt.Errorf("DB_EXPORT sync login failed: %w", err))
			log.Warnf("[%s] %s", internal.TagCache, errSummary)
			p.upsertSyncStatus(false, 0, dbExportSyncModeSizeOnlyDegrade, errSummary)
			return
		}
	}

	metaImported, err := p.syncDBExportMetaEntity(ctx, cfg, token)
	if err != nil {
		errSummary := sanitizeSyncError(fmt.Errorf("DB_EXPORT meta sync failed: %w", err))
		log.Warnf("[%s] %s", internal.TagCache, errSummary)
		p.upsertSyncStatus(false, 0, dbExportSyncModeSizeOnlyDegrade, errSummary)
		return
	}

	syncMode := dbExportSyncModeFull
	errorNotes := make([]string, 0, 2)
	strategyImported := 0
	rangeImported := 0

	strategyImported, err = p.syncDBExportStrategyEntity(ctx, cfg, token)
	if err != nil {
		syncMode = dbExportSyncModeSizeOnlyDegrade
		if errors.Is(err, errDBExportEndpointUnsupported) {
			errorNotes = append(errorNotes, "strategy endpoint unsupported")
		} else {
			errorNotes = append(errorNotes, "strategy sync failed: "+sanitizeSyncError(err))
		}
	}

	rangeImported, err = p.syncDBExportRangeCompatEntity(ctx, cfg, token)
	if err != nil {
		syncMode = dbExportSyncModeSizeOnlyDegrade
		if errors.Is(err, errDBExportEndpointUnsupported) {
			errorNotes = append(errorNotes, "range endpoint unsupported")
		} else {
			errorNotes = append(errorNotes, "range sync failed: "+sanitizeSyncError(err))
		}
	}

	cycleImported := metaImported + strategyImported + rangeImported
	lastError := strings.Join(errorNotes, "; ")
	p.upsertSyncStatus(true, cycleImported, syncMode, lastError)

	if cycleImported > 0 {
		log.Infof("[%s] DB_EXPORT sync imported total=%d (meta=%d strategy=%d range=%d)", internal.TagCache, cycleImported, metaImported, strategyImported, rangeImported)
	}
}
