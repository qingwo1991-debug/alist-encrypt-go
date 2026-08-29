package encrypt

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"
)

// dirWarmConcurrency bounds how many root-directory PROPFINDs are issued in
// parallel during the background warm pass. Keep it small: the whole point is
// to pre-group the OpenList storage drivers' cold enumeration (139/189/Google)
// so the first real WebDAV directory listing from the phone client returns
// quickly, NOT to hammer the upstream.
const (
	dirWarmConcurrency = 2
	dirWarmTimeout     = 8 * time.Second
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
		sem := make(chan struct{}, dirWarmConcurrency)
		var wg sync.WaitGroup
		for _, root := range roots {
			wg.Add(1)
			sem <- struct{}{}
			go func(root string) {
				defer wg.Done()
				defer func() { <-sem }()
				warmOneRootDir(alistURL, root)
			}(root)
		}
		wg.Wait()
	}()
}

func warmOneRootDir(alistURL, root string) {
	davPath := "/dav/" + strings.TrimPrefix(root, "/")
	if !strings.HasSuffix(davPath, "/") {
		davPath += "/"
	}
	target := alistURL + davPath
	ctx, cancel := context.WithTimeout(context.Background(), dirWarmTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "PROPFIND", target, bytes.NewReader([]byte(dirWarmPropfindBody)))
	if err != nil {
		return
	}
	req.Header.Set("Depth", "1")
	req.Header.Set("Content-Type", "application/xml")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	// Drain a bounded amount to let the backend fully stream the listing once;
	// the bytes themselves are irrelevant.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, dirWarmMaxBody))
}
