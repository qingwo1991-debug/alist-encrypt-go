package config

import "strings"

// NormalizeUserEncPaths normalizes user-provided encPath rules.
// It removes legacy-expanded prefixes, trims whitespace, ensures leading slash, and de-duplicates.
func NormalizeUserEncPaths(paths []string) []string {
	seen := make(map[string]struct{}, len(paths))
	result := make([]string, 0, len(paths))

	for _, raw := range paths {
		for _, token := range splitPathTokens(raw) {
			normalized := normalizeSingleEncPath(token)
			if normalized == "" {
				continue
			}
			if _, ok := seen[normalized]; ok {
				continue
			}
			seen[normalized] = struct{}{}
			result = append(result, normalized)
		}
	}

	return result
}

// normalizePasswdListEncPaths normalizes encPath for every password rule.
// It returns true when any item has changed.
func normalizePasswdListEncPaths(passwds []PasswdInfo) bool {
	changed := false
	for i := range passwds {
		before := passwds[i].EncPath
		after := NormalizeUserEncPaths(before)
		if !stringSlicesEqual(before, after) {
			passwds[i].EncPath = after
			changed = true
		}
	}
	return changed
}

func splitPathTokens(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		part = strings.Trim(part, ",")
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}

func normalizeSingleEncPath(path string) string {
	path = strings.TrimSpace(path)
	path = strings.Trim(path, ",")
	if path == "" {
		return ""
	}

	// Keep regex-like rules as-is (legacy compatibility) except trimming.
	if looksLikeRegex(path) {
		return path
	}

	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	path = stripLegacyExpandedPrefixes(path)
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	return path
}

func looksLikeRegex(path string) bool {
	return strings.ContainsAny(path, "^$()[]{}|\\")
}

func stripLegacyExpandedPrefixes(path string) string {
	curr := path
	for {
		next, changed := stripOneLegacyPrefix(curr)
		if !changed {
			return curr
		}
		curr = next
	}
}

func stripOneLegacyPrefix(path string) (string, bool) {
	// Normal expanded forms: /d/<base>, /p/<base>, /dav/<base>
	switch {
	case strings.HasPrefix(path, "/d/"):
		return path[2:], true
	case strings.HasPrefix(path, "/p/"):
		return path[2:], true
	case strings.HasPrefix(path, "/dav/"):
		return path[4:], true
	}

	// Legacy malformed expansion when base path missed leading slash:
	// "/d移动..." "/p移动..." "/dav移动..."
	if strings.HasPrefix(path, "/d") && shouldStripCompactPrefix(path, 2) {
		return "/" + path[2:], true
	}
	if strings.HasPrefix(path, "/p") && shouldStripCompactPrefix(path, 2) {
		return "/" + path[2:], true
	}
	if strings.HasPrefix(path, "/dav") && shouldStripCompactPrefix(path, 4) {
		return "/" + path[4:], true
	}

	return path, false
}

func shouldStripCompactPrefix(path string, prefixLen int) bool {
	if len(path) <= prefixLen {
		return false
	}
	r := rune(path[prefixLen])
	// Avoid stripping valid English path prefixes like /data, /private, /davinci.
	if isASCIIAlphaNumeric(r) || r == '_' || r == '-' {
		return false
	}
	return true
}

func isASCIIAlphaNumeric(r rune) bool {
	return (r >= 'a' && r <= 'z') ||
		(r >= 'A' && r <= 'Z') ||
		(r >= '0' && r <= '9')
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
