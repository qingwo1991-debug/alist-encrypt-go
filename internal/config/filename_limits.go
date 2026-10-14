package config

import (
	"fmt"
	"path"
	"strings"
)

func cloneFilenameWriteLimits(limits map[string]int) map[string]int {
	if limits == nil {
		return nil
	}
	out := make(map[string]int, len(limits))
	for prefix, limit := range limits {
		out[prefix] = limit
	}
	return out
}

func validateFilenameWriteLimits(limits map[string]int) error {
	for prefix, limit := range limits {
		if prefix == "/" || !strings.HasPrefix(prefix, "/") || path.Clean(prefix) != prefix || strings.ContainsAny(prefix, "\\\x00*?") {
			return fmt.Errorf("filenameWriteLimits requires an explicit canonical mount prefix")
		}
		if limit < 32 || limit > 255 {
			return fmt.Errorf("filenameWriteLimits must be between 32 and 255 characters")
		}
	}
	return nil
}
