package encrypt

import (
	"net/url"
	"strings"
)

// safeURLForLog preserves only the origin of an absolute URL. Signed download
// URLs routinely carry reusable credentials in their path, query, fragment,
// or user-info and must never be written to application logs.
func safeURLForLog(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "<empty-url>"
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "<relative-or-invalid-url>"
	}
	return strings.ToLower(u.Scheme) + "://" + u.Host
}
