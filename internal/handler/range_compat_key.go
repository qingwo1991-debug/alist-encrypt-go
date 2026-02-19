package handler

import (
	"strings"

	"github.com/alist-encrypt-go/internal/config"
)

func buildRangeCompatStorageKey(passwdInfo *config.PasswdInfo, displayPath string) string {
	if passwdInfo == nil {
		return "/"
	}

	normalizedPath := normalizePath(displayPath)
	bestMatch := ""
	bestAny := ""

	for _, pattern := range passwdInfo.EncPath {
		prefix := extractPatternLiteralPrefix(pattern)
		if prefix == "" {
			continue
		}
		prefix = normalizePath(prefix)
		if len(prefix) > len(bestAny) {
			bestAny = prefix
		}
		if normalizedPath != "" && strings.HasPrefix(normalizedPath, prefix) && len(prefix) > len(bestMatch) {
			bestMatch = prefix
		}
	}

	if bestMatch != "" {
		return bestMatch
	}
	if bestAny != "" {
		return bestAny
	}
	return "/"
}

func extractPatternLiteralPrefix(pattern string) string {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range pattern {
		switch r {
		case '*', '+', '?', '[', ']', '(', ')', '{', '}', '|', '^', '$', '.', '\\':
			return strings.TrimRight(b.String(), "/")
		default:
			b.WriteRune(r)
		}
	}
	return strings.TrimRight(b.String(), "/")
}

func normalizePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	path = strings.TrimRight(path, "/")
	if path == "" {
		return "/"
	}
	return path
}
