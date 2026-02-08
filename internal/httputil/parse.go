package httputil

import (
	"strconv"
)

// ParseInt64 safely parses a string to int64
func ParseInt64(s string) (int64, error) {
	return strconv.ParseInt(s, 10, 64)
}
