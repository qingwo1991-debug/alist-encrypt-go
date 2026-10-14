package encryption

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"
)

const boundedFilenameHashChars = 16

// BoundEncryptedFilename prepares a NEW file's encrypted filename for an explicit
// upstream character limit. It encrypts the entire display name (including its
// original extension), appends a complete CRC, then adds the normalized suffix.
// Existing filename lookup and decoding must continue to use the legacy helpers.
//
// Shortening is lossy: the hash is a discriminator, not a recovery mechanism or
// collision guarantee. Callers MUST persist the complete original name separately
// and coordinate that mapping with a non-overwriting upstream write. This helper
// performs neither persistence nor collision checks. A storage-specific limit
// must be supplied; it must not be inferred as a global cloud-provider limit.
func BoundEncryptedFilename(password, encType, plainName, encryptedSuffix string, maxNameChars int) (encodedFilename, shortDisplayName string, err error) {
	if !validBoundedDisplayName(plainName) {
		return "", "", errors.New("invalid plaintext filename")
	}
	// Validate the raw suffix before normalization so controls cannot silently
	// disappear through TrimSpace. Output is ASCII, so bytes equal characters.
	for _, r := range encryptedSuffix {
		if r > unicode.MaxASCII || unicode.IsControl(r) || r == '/' || r == '\\' {
			return "", "", errors.New("invalid encrypted suffix")
		}
	}
	suffix := NormalizeEncSuffix(encryptedSuffix)
	if maxNameChars <= len(suffix) {
		return "", "", errors.New("encrypted filename limit is too small")
	}
	// MixBase64 emits 4*ceil(N/3) ASCII characters plus one CRC character.
	// Division is performed before multiplication to avoid overflow for large
	// caller-supplied limits. For suffix .bin and limit 100 the budget is 69.
	budget := ((maxNameChars - len(suffix) - 1) / 4) * 3
	if budget < 1 {
		return "", "", errors.New("encrypted filename limit is too small")
	}
	shortDisplayName = plainName
	if len(plainName) > budget {
		ext := path.Ext(plainName)
		markerSize := 1 + boundedFilenameHashChars
		if len(ext) > budget-markerSize {
			return "", "", errors.New("filename extension cannot fit encrypted filename limit")
		}
		digest := sha256.Sum256([]byte(plainName))
		marker := "~" + hex.EncodeToString(digest[:boundedFilenameHashChars/2])
		stem := strings.TrimSuffix(plainName, ext)
		prefixBudget := budget - len(marker) - len(ext)
		end := 0
		for i, r := range stem {
			next := i + utf8.RuneLen(r)
			if next > prefixBudget {
				break
			}
			end = next
		}
		shortDisplayName = stem[:end] + marker + ext
	}
	encodedFilename = EncodeName(password, encType, shortDisplayName) + suffix
	if len(encodedFilename) > maxNameChars {
		return "", "", errors.New("encrypted filename exceeds requested limit")
	}
	return encodedFilename, shortDisplayName, nil
}

func validBoundedDisplayName(name string) bool {
	if name == "" || name == "." || name == ".." || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if r == '/' || r == '\\' || unicode.IsControl(r) {
			return false
		}
	}
	return true
}
