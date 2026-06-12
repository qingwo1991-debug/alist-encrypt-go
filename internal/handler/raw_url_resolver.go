package handler

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/httputil"
	"github.com/alist-encrypt-go/internal/proxy"
)

const finalRawURLResolveTimeout = 3 * time.Second

func resolveFinalRawURL(ctx context.Context, cfg *config.Config, alistURL, displayPath, realPath string, authHeaders http.Header, fileDAO *dao.FileDAO) rawURLFetchResult {
	if cfg == nil || strings.TrimSpace(alistURL) == "" || strings.TrimSpace(realPath) == "" {
		return rawURLFetchResult{}
	}
	clients := []struct {
		source string
		url    string
	}{
		{source: "redirect_d", url: httputil.BuildTargetURLStripped(alistURL, "/d"+realPath)},
		{source: "redirect_dav", url: httputil.BuildTargetURLStripped(alistURL, "/dav"+realPath)},
	}
	for _, candidate := range clients {
		if strings.TrimSpace(candidate.url) == "" {
			continue
		}
		result := followToFinalRawURL(ctx, cfg, candidate.url, authHeaders)
		if strings.TrimSpace(result.RawURL) == "" {
			continue
		}
		result.Source = candidate.source
		cacheResolvedRawURL(fileDAO, displayPath, realPath, result.RawURL, result.Size)
		return result
	}
	return rawURLFetchResult{FailureReason: "raw_url_empty"}
}

func followToFinalRawURL(ctx context.Context, cfg *config.Config, initialURL string, authHeaders http.Header) rawURLFetchResult {
	ctx, cancel := context.WithTimeout(ctx, finalRawURLResolveTimeout)
	defer cancel()

	client := proxy.NewHTTPClient(cfg, finalRawURLResolveTimeout)
	origHost := hostOfURL(initialURL)
	maxHops := 2
	if cfg != nil && cfg.AlistServer.RedirectMaxHops > 0 {
		maxHops = cfg.AlistServer.RedirectMaxHops
	}

	methods := []string{http.MethodHead, http.MethodGet}
	for _, method := range methods {
		currentURL := initialURL
		redirected := false
		for redirect := 0; redirect <= maxHops; redirect++ {
			req, err := http.NewRequestWithContext(ctx, method, currentURL, nil)
			if err != nil {
				return rawURLFetchResult{FailureReason: "raw_url_redirect_request"}
			}
			copyAuthHeadersConditional(req, authHeaders, origHost, hostOfURL(currentURL))
			if method == http.MethodGet {
				req.Header.Set("Range", "bytes=0-0")
			}

			resp, err := client.Do(req)
			if err != nil {
				return rawURLFetchResult{FailureReason: "raw_url_redirect:" + err.Error()}
			}

			if isRedirectStatusCode(resp.StatusCode) {
				location := strings.TrimSpace(resp.Header.Get("Location"))
				resp.Body.Close()
				if location == "" {
					return rawURLFetchResult{StatusCode: resp.StatusCode, FailureReason: "raw_url_redirect_location"}
				}
				nextURL := resolveRedirectURL(currentURL, location)
				if nextURL == "" {
					return rawURLFetchResult{StatusCode: resp.StatusCode, FailureReason: "raw_url_redirect_invalid"}
				}
				currentURL = nextURL
				redirected = true
				continue
			}

			size := responseSize(resp)
			if method == http.MethodGet {
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1))
			}
			resp.Body.Close()

			if resp.StatusCode >= 200 && resp.StatusCode < 300 && redirected &&
				!strings.EqualFold(hostOfURL(currentURL), origHost) {
				return rawURLFetchResult{
					RawURL:     currentURL,
					Size:       size,
					StatusCode: resp.StatusCode,
				}
			}
			break
		}
	}
	return rawURLFetchResult{FailureReason: "raw_url_empty"}
}

func cacheResolvedRawURL(fileDAO *dao.FileDAO, displayPath, realPath, rawURL string, size int64) {
	if fileDAO == nil || strings.TrimSpace(displayPath) == "" || strings.TrimSpace(rawURL) == "" {
		return
	}
	info := &dao.FileInfo{
		Path:              displayPath,
		EncryptedPath:     realPath,
		RawURL:            rawURL,
		UpstreamFetchedAt: time.Now(),
	}
	if size > 0 {
		info.Size = size
	}
	_ = fileDAO.Set(info)
}

func responseSize(resp *http.Response) int64 {
	if resp == nil {
		return 0
	}
	if contentRange := strings.TrimSpace(resp.Header.Get("Content-Range")); contentRange != "" {
		if slash := strings.LastIndex(contentRange, "/"); slash >= 0 && slash < len(contentRange)-1 {
			if size, err := strconv.ParseInt(contentRange[slash+1:], 10, 64); err == nil && size > 0 {
				return size
			}
		}
	}
	if contentLen := strings.TrimSpace(resp.Header.Get("Content-Length")); contentLen != "" {
		if size, err := strconv.ParseInt(contentLen, 10, 64); err == nil && size > 0 {
			return size
		}
	}
	return 0
}
