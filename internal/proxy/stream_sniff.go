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

	if looksLikeKnownPlaintext(sample) {
		return io.MultiReader(bytes.NewReader(sample), r), true
	}

	// Count unique byte values and zero bytes.
	// Encrypted data: ~200+ unique bytes in 512 samples, few zeros.
	// Valid plaintext usually has lower entropy, but media payloads can be high-entropy.
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
			Msg("Decrypted data looks encrypted; wrong password or file size?")
		return nil, false
	}

	// Prepend the consumed bytes
	return io.MultiReader(bytes.NewReader(sample), r), true
}

func looksLikeKnownPlaintext(sample []byte) bool {
	if len(sample) >= 12 && bytes.Equal(sample[4:8], []byte("ftyp")) {
		return true
	}
	if len(sample) >= 4 {
		switch {
		case bytes.Equal(sample[:4], []byte{0x1a, 0x45, 0xdf, 0xa3}): // Matroska/WebM EBML
			return true
		case bytes.Equal(sample[:4], []byte("OggS")):
			return true
		case bytes.Equal(sample[:4], []byte("fLaC")):
			return true
		case bytes.Equal(sample[:4], []byte("%PDF")):
			return true
		case bytes.Equal(sample[:4], []byte("PK\x03\x04")):
			return true
		}
	}
	if len(sample) >= 12 && bytes.Equal(sample[:4], []byte("RIFF")) {
		kind := sample[8:12]
		if bytes.Equal(kind, []byte("AVI ")) || bytes.Equal(kind, []byte("WAVE")) || bytes.Equal(kind, []byte("WEBP")) {
			return true
		}
	}
	if len(sample) >= 3 {
		if bytes.Equal(sample[:3], []byte("ID3")) || bytes.Equal(sample[:3], []byte{0xff, 0xd8, 0xff}) {
			return true
		}
	}
	if len(sample) >= 8 && bytes.Equal(sample[:8], []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}) {
		return true
	}
	if len(sample) >= 6 && (bytes.Equal(sample[:6], []byte("GIF87a")) || bytes.Equal(sample[:6], []byte("GIF89a"))) {
		return true
	}
	return false
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
