package handler

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

var uploadSizeHeaders = []string{
	"X-File-Size",
	"File-Size",
	"X-Upload-Content-Length",
	"X-Expected-Entity-Length",
}

func resolveUploadFileSize(r *http.Request) (int64, error) {
	if r == nil {
		return 0, fmt.Errorf("request is nil")
	}

	if v := strings.TrimSpace(r.Header.Get("Content-Length")); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n, nil
		}
	}

	if total := parseContentRangeTotal(r.Header.Get("Content-Range")); total > 0 {
		return total, nil
	}

	for _, header := range uploadSizeHeaders {
		if v := strings.TrimSpace(r.Header.Get(header)); v != "" {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
				return n, nil
			}
		}
	}

	return 0, fmt.Errorf("cannot determine upload file size")
}

// parseContentRangeTotal extracts total size from "bytes start-end/total" style header.
func parseContentRangeTotal(contentRange string) int64 {
	contentRange = strings.TrimSpace(contentRange)
	if contentRange == "" {
		return 0
	}
	idx := strings.LastIndex(contentRange, "/")
	if idx < 0 || idx+1 >= len(contentRange) {
		return 0
	}
	totalStr := strings.TrimSpace(contentRange[idx+1:])
	if totalStr == "" || totalStr == "*" {
		return 0
	}
	total, err := strconv.ParseInt(totalStr, 10, 64)
	if err != nil || total <= 0 {
		return 0
	}
	return total
}
