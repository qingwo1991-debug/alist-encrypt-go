package encryption

import (
	"net/http"
	"strings"
)

// SingleStrongETag accepts one RFC 9110 entity-tag, not a list, weak tag or
// quoted-string with escapes. etagc allows !, # through ~, and obs-text;
// backslash is an ordinary opaque byte. Only surrounding HTTP OWS is trimmed.
func SingleStrongETag(h http.Header) (string, bool) {
	values := h.Values("ETag")
	if len(values) != 1 {
		return "", false
	}
	value := strings.Trim(values[0], " \t")
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
		return "", false
	}
	for i := 1; i < len(value)-1; i++ {
		b := value[i]
		if b != 0x21 && !(b >= 0x23 && b <= 0x7e) && b < 0x80 {
			return "", false
		}
	}
	return value, true
}
