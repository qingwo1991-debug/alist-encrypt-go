package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/alist-encrypt-go/internal/dao"
)

const rawURLExpirySafetyMargin = time.Minute

func rawURLAuthScope(headers http.Header) string {
	if headers == nil {
		return "anon"
	}
	authorization := strings.TrimSpace(headers.Get("Authorization"))
	cookie := strings.TrimSpace(headers.Get("Cookie"))
	if authorization == "" && cookie == "" {
		return "anon"
	}
	sum := sha256.Sum256([]byte(authorization + "\x00" + cookie))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func cachedRawURLFresh(info *dao.FileInfo, fallback time.Duration, authScope string) bool {
	if info == nil || strings.TrimSpace(info.RawURL) == "" {
		return false
	}
	if strings.TrimSpace(authScope) == "" {
		authScope = "anon"
	}
	// Legacy entries without a scope are deliberately cold. Reusing one could
	// expose a signed URL fetched with broader credentials before scope tracking.
	if info.RawURLAuthScope == "" || info.RawURLAuthScope != authScope {
		return false
	}
	if fallback > 0 && info.UpstreamStaleness() >= fallback {
		return false
	}
	if expiresAt, ok := rawURLExpiresAt(info.RawURL); ok {
		return time.Now().Before(expiresAt.Add(-rawURLExpirySafetyMargin))
	}
	return true
}

func rawURLExpiresAt(raw string) (time.Time, bool) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return time.Time{}, false
	}
	query := parsed.Query()

	if dateText := strings.TrimSpace(query.Get("X-Amz-Date")); dateText != "" {
		if ttlText := strings.TrimSpace(query.Get("X-Amz-Expires")); ttlText != "" {
			signedAt, err := time.Parse("20060102T150405Z", dateText)
			if err == nil {
				if ttlSeconds, err := strconv.ParseInt(ttlText, 10, 64); err == nil && ttlSeconds > 0 {
					return signedAt.Add(time.Duration(ttlSeconds) * time.Second), true
				}
			}
		}
	}

	if expiresText := strings.TrimSpace(query.Get("Expires")); expiresText != "" {
		if unixSeconds, err := strconv.ParseInt(expiresText, 10, 64); err == nil && unixSeconds > 0 {
			return time.Unix(unixSeconds, 0), true
		}
	}

	return time.Time{}, false
}
