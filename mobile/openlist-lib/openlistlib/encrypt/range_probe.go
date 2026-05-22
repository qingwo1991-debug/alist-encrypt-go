package encrypt

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/OpenListTeam/OpenList/v4/openlistlib/internal"
	log "github.com/sirupsen/logrus"
)

const (
	rangeProbeBatchInterval = 10 * time.Minute
	rangeProbeSuccessNext   = 6 * time.Hour
	rangeProbeFailureMax    = 30 * time.Minute
)

type rangeProbeTarget struct {
	Key         string
	URL         string
	SourcePath  string
	NextProbeAt time.Time
	Failures    int
}

func (p *ProxyServer) shouldBackgroundProbeURL(targetURL string) bool {
	parsed, err := url.Parse(strings.TrimSpace(targetURL))
	if err != nil || parsed == nil {
		return false
	}
	if !strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https") {
		return false
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if host == "" || isLocalOrPrivateHost(host) {
		return false
	}
	if p != nil && p.config != nil {
		alistHost := strings.ToLower(strings.TrimSpace(p.config.AlistHost))
		if alistHost != "" && host == alistHost {
			return false
		}
	}
	return true
}

func (p *ProxyServer) registerRangeProbeTarget(targetURL, sourcePath string, immediate bool) {
	if p == nil || p.config == nil || !p.config.EnableRangeCompatCache {
		return
	}
	if !p.shouldBackgroundProbeURL(targetURL) {
		return
	}
	key := p.rangeCompatKey(targetURL, sourcePath)
	if key == "" {
		return
	}
	now := time.Now()
	p.rangeProbeMu.Lock()
	if p.rangeProbeTargets == nil {
		p.rangeProbeTargets = make(map[string]rangeProbeTarget)
	}
	target := p.rangeProbeTargets[key]
	target.Key = key
	target.URL = targetURL
	target.SourcePath = sourcePath
	if immediate {
		target.NextProbeAt = now
	} else if target.NextProbeAt.IsZero() {
		target.NextProbeAt = now.Add(rangeProbeBatchInterval)
	}
	p.rangeProbeTargets[key] = target
	p.rangeProbeMu.Unlock()

	if p.localStore != nil {
		_ = p.localStore.UpsertRangeProbeTarget(target)
	}
	if immediate {
		p.enqueueRangeProbe(key)
	}
}

func (p *ProxyServer) enqueueRangeProbe(key string) {
	if p == nil || strings.TrimSpace(key) == "" {
		return
	}
	p.rangeProbeMu.Lock()
	queue := p.rangeProbeQueue
	done := p.rangeProbeDone
	p.rangeProbeMu.Unlock()
	if queue == nil || done == nil {
		return
	}
	select {
	case queue <- key:
	default:
	}
}

func (p *ProxyServer) startRangeProbeLoop() {
	if p == nil || p.config == nil || !p.config.EnableRangeCompatCache {
		return
	}
	p.rangeProbeMu.Lock()
	if p.rangeProbeDone != nil {
		p.rangeProbeMu.Unlock()
		return
	}
	p.rangeProbeDone = make(chan struct{})
	p.rangeProbeQueue = make(chan string, 128)
	if p.rangeProbeTargets == nil {
		p.rangeProbeTargets = make(map[string]rangeProbeTarget)
	}
	p.rangeProbeMu.Unlock()

	if p.localStore != nil {
		if persisted, err := p.localStore.LoadRangeProbeTargets(); err == nil {
			p.rangeProbeMu.Lock()
			for key, target := range persisted {
				p.rangeProbeTargets[key] = target
			}
			p.rangeProbeMu.Unlock()
		} else {
			log.Warnf("[%s] load range probe targets failed: %v", internal.TagCache, err)
		}
	}

	p.rangeProbeWG.Add(1)
	go p.rangeProbeLoop()

	p.rangeProbeMu.Lock()
	keys := make([]string, 0, len(p.rangeProbeTargets))
	for key, target := range p.rangeProbeTargets {
		if target.URL != "" {
			keys = append(keys, key)
		}
	}
	p.rangeProbeMu.Unlock()
	for _, key := range keys {
		p.enqueueRangeProbe(key)
	}
}

func (p *ProxyServer) stopRangeProbeLoop() {
	if p == nil {
		return
	}
	p.rangeProbeMu.Lock()
	done := p.rangeProbeDone
	if done != nil {
		close(done)
		p.rangeProbeDone = nil
	}
	p.rangeProbeQueue = nil
	p.rangeProbeMu.Unlock()
	p.rangeProbeWG.Wait()
}

func (p *ProxyServer) rangeProbeLoop() {
	defer p.rangeProbeWG.Done()
	defer recoverBackgroundTask("range_probe_loop")
	ticker := time.NewTicker(rangeProbeBatchInterval)
	defer ticker.Stop()
	for {
		p.rangeProbeMu.Lock()
		queue := p.rangeProbeQueue
		done := p.rangeProbeDone
		p.rangeProbeMu.Unlock()
		if queue == nil || done == nil {
			return
		}
		select {
		case <-done:
			return
		case key := <-queue:
			p.runRangeProbe(key, true)
		case <-ticker.C:
			p.runScheduledRangeProbes()
		}
	}
}

func (p *ProxyServer) runScheduledRangeProbes() {
	now := time.Now()
	p.rangeProbeMu.Lock()
	keys := make([]string, 0, len(p.rangeProbeTargets))
	for key, target := range p.rangeProbeTargets {
		if target.URL == "" {
			continue
		}
		if target.NextProbeAt.IsZero() || !target.NextProbeAt.After(now) {
			keys = append(keys, key)
		}
	}
	p.rangeProbeMu.Unlock()
	for _, key := range keys {
		p.runRangeProbe(key, false)
	}
}

func (p *ProxyServer) runRangeProbe(key string, fromQueue bool) {
	if p == nil || strings.TrimSpace(key) == "" {
		return
	}
	now := time.Now()
	p.rangeProbeMu.Lock()
	target, ok := p.rangeProbeTargets[key]
	if !ok || target.URL == "" {
		p.rangeProbeMu.Unlock()
		return
	}
	if !fromQueue && !target.NextProbeAt.IsZero() && target.NextProbeAt.After(now) {
		p.rangeProbeMu.Unlock()
		return
	}
	p.rangeProbeMu.Unlock()

	supportsRange, err := p.probeRangeCapability(target.URL)
	if err != nil {
		target.Failures++
		backoff := time.Duration(target.Failures*2) * time.Minute
		if backoff > rangeProbeFailureMax {
			backoff = rangeProbeFailureMax
		}
		target.NextProbeAt = time.Now().Add(backoff)
		p.rangeProbeMu.Lock()
		p.rangeProbeTargets[key] = target
		p.rangeProbeMu.Unlock()
		if p.localStore != nil {
			_ = p.localStore.UpsertRangeProbeTarget(target)
		}
		p.debugf("range", "range probe failed key=%s url=%s err=%v next=%s", key, target.URL, err, target.NextProbeAt.Format(time.RFC3339))
		return
	}

	target.Failures = 0
	if supportsRange {
		p.markRangeCompatible(target.URL, target.SourcePath)
		target.NextProbeAt = time.Now().Add(rangeProbeSuccessNext)
	} else {
		ttl := p.rangeCompatTTL()
		if ttl <= 0 {
			ttl = 30 * time.Minute
		}
		blockedUntil := time.Now().Add(ttl)
		p.rangeCompatMu.Lock()
		if p.rangeCompat == nil {
			p.rangeCompat = make(map[string]time.Time)
		}
		if p.rangeCompatFailures == nil {
			p.rangeCompatFailures = make(map[string]int)
		}
		p.rangeCompat[key] = blockedUntil
		p.rangeCompatFailures[key] = 0
		p.rangeCompatMu.Unlock()
		if p.localStore != nil {
			_ = p.localStore.UpsertRangeCompat(key, blockedUntil, 0)
		}
		target.NextProbeAt = time.Now().Add(rangeProbeBatchInterval)
	}
	p.rangeProbeMu.Lock()
	p.rangeProbeTargets[key] = target
	p.rangeProbeMu.Unlock()
	if p.localStore != nil {
		_ = p.localStore.UpsertRangeProbeTarget(target)
	}
	p.debugf("range", "range probe result key=%s supports=%v next=%s", key, supportsRange, target.NextProbeAt.Format(time.RFC3339))
}

func (p *ProxyServer) probeRangeCapability(targetURL string) (bool, error) {
	timeout := p.probeTimeout()
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Range", "bytes=0-1")
	req.Header.Set("User-Agent", "OpenList-Encrypt-RangeProbe/1.0")
	resp, err := p.probeClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	contentRange := strings.TrimSpace(resp.Header.Get("Content-Range"))
	if resp.StatusCode == http.StatusPartialContent && contentRange != "" {
		return true, nil
	}
	if resp.StatusCode == http.StatusRequestedRangeNotSatisfiable && contentRange != "" {
		return true, nil
	}
	if resp.StatusCode == http.StatusOK && contentRange == "" {
		return false, nil
	}
	if strings.Contains(strings.ToLower(resp.Header.Get("Accept-Ranges")), "bytes") && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return true, nil
	}
	return false, nil
}
