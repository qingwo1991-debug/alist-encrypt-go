package httputil

import (
	"fmt"
	"strconv"
	"strings"
)

// Range represents a single byte range
type Range struct {
	Start int64
	End   int64
}

// RangeRequest represents a parsed Range header
type RangeRequest struct {
	Ranges []Range
}

// ParseRange parses an HTTP Range header (RFC 7233)
// Returns nil if no valid range is present
func ParseRange(rangeHeader string, fileSize int64) (*RangeRequest, error) {
	if rangeHeader == "" {
		return nil, nil
	}

	// Must start with "bytes="
	if !strings.HasPrefix(rangeHeader, "bytes=") {
		return nil, fmt.Errorf("invalid range header format")
	}

	rangeSpec := strings.TrimPrefix(rangeHeader, "bytes=")
	rangeSpecs := strings.Split(rangeSpec, ",")

	var ranges []Range
	for _, spec := range rangeSpecs {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}

		// Parse range: "start-end", "start-", or "-suffix"
		parts := strings.Split(spec, "-")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid range spec: %s", spec)
		}

		var r Range
		if parts[0] == "" {
			// Suffix range: "-500" means last 500 bytes
			suffix, err := strconv.ParseInt(parts[1], 10, 64)
			if err != nil || suffix <= 0 {
				return nil, fmt.Errorf("invalid suffix range: %s", spec)
			}
			if suffix > fileSize {
				suffix = fileSize
			}
			r.Start = fileSize - suffix
			r.End = fileSize - 1
		} else if parts[1] == "" {
			// Open-ended range: "100-" means from 100 to EOF
			start, err := strconv.ParseInt(parts[0], 10, 64)
			if err != nil || start < 0 {
				return nil, fmt.Errorf("invalid start position: %s", spec)
			}
			r.Start = start
			r.End = fileSize - 1
		} else {
			// Bounded range: "100-200"
			start, err1 := strconv.ParseInt(parts[0], 10, 64)
			end, err2 := strconv.ParseInt(parts[1], 10, 64)
			if err1 != nil || err2 != nil || start < 0 || end < start {
				return nil, fmt.Errorf("invalid range: %s", spec)
			}
			r.Start = start
			r.End = end
		}

		// Validate range is satisfiable
		if r.Start >= fileSize {
			return nil, &RequestedRangeNotSatisfiable{fileSize}
		}

		// Clamp end to file size
		if r.End >= fileSize {
			r.End = fileSize - 1
		}

		ranges = append(ranges, r)
	}

	if len(ranges) == 0 {
		return nil, nil
	}

	return &RangeRequest{Ranges: ranges}, nil
}

// ContentLength returns the length of the range in bytes
func (r *Range) ContentLength() int64 {
	if r.End < r.Start {
		return 0
	}
	length := r.End - r.Start + 1
	// Overflow detection: if addition caused overflow, length would be negative
	if length < 0 {
		return 0
	}
	return length
}

// ContentRangeHeader generates the Content-Range header value
// Format: "bytes start-end/total"
func (r *Range) ContentRangeHeader(totalSize int64) string {
	return fmt.Sprintf("bytes %d-%d/%d", r.Start, r.End, totalSize)
}

// RequestedRangeNotSatisfiable is returned when a range cannot be satisfied
type RequestedRangeNotSatisfiable struct {
	FileSize int64
}

func (e *RequestedRangeNotSatisfiable) Error() string {
	return fmt.Sprintf("requested range not satisfiable, file size: %d", e.FileSize)
}
