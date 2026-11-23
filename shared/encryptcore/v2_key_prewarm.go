package encryption

import "strings"

// v2KeyParams maps a configured encType to the PBKDF2 salt label and key
// length used by its V2 cipher constructor (see *_v2.go). Keep in sync.
func v2KeyParams(encType string) (string, int, bool) {
	switch EncType(strings.ToLower(strings.TrimSpace(encType))) {
	case EncTypeAESCTR:
		return "AES-CTR-v2", 16, true
	case EncTypeChaCha20:
		return "ChaCha20-v2", 32, true
	case EncTypeRC4MD5:
		return "RC4-v2", 16, true
	default:
		return "", 0, false
	}
}

// PrewarmV2Key derives and caches the V2 PBKDF2 base key (600k iterations)
// for one password/encType pair, so the first V2 playback after a restart or
// config change does not pay the derivation on its request path. It is a
// no-op for unknown encTypes or empty passwords; cached keys return at once.
func PrewarmV2Key(password, encType string) bool {
	if len(password) == 0 {
		return false
	}
	label, keyLen, ok := v2KeyParams(encType)
	if !ok {
		return false
	}
	_ = cachedV2Key(password, label, keyLen)
	return true
}
