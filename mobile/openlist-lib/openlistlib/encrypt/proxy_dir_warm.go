package encrypt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/setting"
	"github.com/OpenListTeam/OpenList/v4/openlistlib/internal"
	log "github.com/sirupsen/logrus"
)

// dirWarmConcurrency bounds how many root-directory PROPFINDs are issued in
// parallel during the background warm pass. Keep it small: the whole point is
// to pre-group the OpenList storage drivers' cold enumeration (139/189/Google)
// so the first real WebDAV directory listing from the phone client returns
// quickly, NOT to hammer the upstream.
const (
	dirWarmConcurrency = 2
	dirWarmTimeout     = 8 * time.Second
	// alistReadyWaitTimeout bounds how long the preheat pass waits for the
	// OpenList backend (usually 127.0.0.1:5244, spawned alongside the encrypt
	// proxy at app launch) to accept connections. Without this wait the cold
	// PROPFINDs land on a not-yet-listening port and the whole pass fails.
	alistReadyWaitTimeout = 8 * time.Second
	// Upper bound on how much of the warm response we bother reading. We only
	// want the request to reach the backend and be answered; the body itself
	// is discarded.
	dirWarmMaxBody = 1 << 20
)

// dirWarmPropfindBody is the depth-1 allprops request sent to unpark cold
// storage drivers for a configured encrypt root directory.
const dirWarmPropfindBody = `<D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>`

// warmEncryptedRootDirsAsync issues a depth-1 PROPFIND against every enabled
// encrypt root prefix (e.g. /156联通云盘/encrypt) in the background, so the
// WebDAV backend has already loaded the storage driver lists by the time a
// real client asks. Failures are ignored: this is purely an optimization.
// Each attempt is recorded into the local warm_events store for the stats UI.
func warmEncryptedRootDirsAsync(p *ProxyServer, config *ProxyConfig) {
	if p == nil || config == nil {
		return
	}
	roots := make([]string, 0, len(config.EncryptPaths))
	seen := map[string]struct{}{}
	for _, ep := range config.EncryptPaths {
		if ep == nil || !ep.Enable {
			continue
		}
		root := strings.TrimRight(path.Clean(strings.TrimSpace(ep.prefix)), "/")
		if root == "" || root == "." {
			continue
		}
		if _, ok := seen[root]; ok {
			continue
		}
		seen[root] = struct{}{}
		roots = append(roots, root)
	}
	if len(roots) == 0 {
		return
	}

	go func() {
		alistURL := p.getAlistURL()
		ready := waitForAlistReady(p, alistURL)
		if !ready {
			log.Warnf("[%s] Skipping preheat pass: Alist not ready within %v (%s)", internal.TagServer, alistReadyWaitTimeout, alistURL)
		}
		sem := make(chan struct{}, dirWarmConcurrency)
		var wg sync.WaitGroup
		for _, root := range roots {
			wg.Add(1)
			sem <- struct{}{}
			go func(root string) {
				defer wg.Done()
				defer func() { <-sem }()
				if ready {
					warmOneRootDir(p, alistURL, root)
				} else {
					recordWarmSkipped(p, root)
				}
			}(root)
		}
		wg.Wait()
	}()
}

func warmOneRootDir(p *ProxyServer, alistURL, root string) {
	startedAt := time.Now()
	rec := WarmEventRecord{
		TargetPath: root,
		StartedAt:  startedAt.Unix(),
		Status:     WarmEventOK,
	}
	defer func() {
		rec.FinishedAt = time.Now().Unix()
		rec.DurationMs = time.Since(startedAt).Milliseconds()
		if p != nil && p.localStore != nil {
			_ = p.localStore.AddWarmEvent(rec)
		}
	}()

	davPath := "/dav/" + strings.TrimPrefix(root, "/")
	if !strings.HasSuffix(davPath, "/") {
		davPath += "/"
	}
	target := alistURL + davPath
	ctx, cancel := context.WithTimeout(context.Background(), dirWarmTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "PROPFIND", target, bytes.NewReader([]byte(dirWarmPropfindBody)))
	if err != nil {
		rec.Status = WarmEventFail
		rec.Detail = err.Error()
		return
	}
	req.Header.Set("Depth", "1")
	req.Header.Set("Content-Type", "application/xml")

	// OpenList 的 /dav 端点在 WebDAVAuth 中要求认证：Bearer 令牌（对应
	// 设置项 conf.Token）或 Basic 用户。预热请求无法携带登录态，这里直接
	// 读同进程内 OpenList 的 WebDAV token 作为 Bearer，避免 PROPFIND 被
	// 401 拒绝。token 为空（如 OpenList 尚未初始化）时仍尝试裸请求，
	// 交由后端按其 guest 策略处理。
	if token := strings.TrimSpace(setting.GetStr(conf.Token)); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := doMetadataRequest(http.DefaultClient, req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			rec.Status = WarmEventTimeout
			rec.Detail = "timeout"
		} else {
			rec.Status = WarmEventFail
			rec.Detail = err.Error()
		}
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		rec.Status = WarmEventFail
		rec.Detail = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	// Drain a bounded amount to let the backend fully stream the listing once;
	// the bytes themselves are irrelevant.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, dirWarmMaxBody))
}

// waitForAlistReady polls the OpenList backend until it answers, so the
// preheat PROPFINDs don't fire against a port that isn't listening yet
// (OpenList and the encrypt proxy boot in parallel at app launch).
func waitForAlistReady(p *ProxyServer, alistURL string) bool {
	if p == nil || alistURL == "" {
		return false
	}
	client := &http.Client{Timeout: 800 * time.Millisecond}
	deadline := time.Now().Add(alistReadyWaitTimeout)
	for {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, alistURL+"/ping", nil)
		if err != nil {
			return false
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode < 500 {
				return true
			}
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// recordWarmSkipped writes a warm event marking the root as not attempted
// because the backend never became ready (keeps the stats page honest).
func recordWarmSkipped(p *ProxyServer, root string) {
	if p == nil || root == "" {
		return
	}
	now := time.Now().Unix()
	rec := WarmEventRecord{
		ID:         fmt.Sprintf("%d-%s", now, root),
		TargetPath: root,
		StartedAt:  now,
		FinishedAt: now,
		DurationMs: 0,
		Status:     WarmEventFail,
		Detail:     "backend not ready",
	}
	if p.localStore != nil {
		_ = p.localStore.AddWarmEvent(rec)
	}
}
