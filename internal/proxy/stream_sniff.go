package proxy

import (
	"bytes"
	"io"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"
)

// sniffDecrypted reads the first N bytes of decrypted output and checks
// if it looks like valid plaintext (not random encrypted garbage).
// Returns a reader that prepends the consumed bytes on success.
func sniffDecrypted(r io.Reader) (io.Reader, bool) {
	const sniffLen = 512
	buf := make([]byte, sniffLen)
	n, err := io.ReadFull(r, buf)
	if err != nil && n == 0 {
		// Empty response, let it through
		return io.MultiReader(bytes.NewReader(buf[:n]), r), true
	}
	sample := buf[:n]

	// Count unique byte values and zero bytes.
	// Encrypted data: ~200+ unique bytes in 512 samples, few zeros.
	// Valid plaintext: 30-120 unique bytes, many zero bytes (headers, structures).
	// Use fixed array instead of map for zero-GC stack allocation.
	var seen [256]bool
	zeros := 0
	unique := 0
	for _, b := range sample {
		if !seen[b] {
			seen[b] = true
			unique++
		}
		if b == 0 {
			zeros++
		}
	}

	// Heuristic: encrypted data has high entropy (high unique ratio, few zeros).
	// Valid decrypted data has lower entropy (fewer unique bytes, more zeros).
	uniqueRatio := 0.0
	if n > 0 {
		uniqueRatio = float64(unique) / float64(n)
	}
	if (n >= 128 && uniqueRatio >= 0.72 && zeros < 10) || (unique > 200 && zeros < 10) {
		log.Warn().Int("unique_bytes", unique).Int("zeros", zeros).
			Int("sample_len", n).
			Float64("unique_ratio", uniqueRatio).
			Msg("Decrypted data looks encrypted — wrong password or file size?")
		return nil, false
	}

	// Prepend the consumed bytes
	return io.MultiReader(bytes.NewReader(sample), r), true
}

func shouldSniffDecryptedContent(method, contentType string, startOffset int64) bool {
	if method != http.MethodGet {
		return false
	}
	if startOffset > 0 {
		return false
	}
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	if strings.HasPrefix(mediaType, "video/") || strings.HasPrefix(mediaType, "audio/") {
		return false
	}
	return true
}
