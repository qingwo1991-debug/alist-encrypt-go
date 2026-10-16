package encryption

import (
	"net/http"
	"testing"
)

func TestSingleStrongETag(t *testing.T) {
	for _, tc := range []struct {
		name   string
		values []string
		want   string
		ok     bool
	}{
		{"quoted", []string{`"revision"`}, `"revision"`, true},
		{"empty-opaque", []string{`""`}, `""`, true},
		{"ows", []string{" \t\"revision\"\t "}, `"revision"`, true},
		{"opaque-backslash", []string{`"a\b"`}, `"a\b"`, true},
		{"obs-text", []string{"\"\x80\xff\""}, "\"\x80\xff\"", true},
		{"missing", nil, "", false},
		{"whitespace", []string{" \t "}, "", false},
		{"unquoted", []string{"revision"}, "", false},
		{"weak", []string{`W/"revision"`}, "", false},
		{"combined-list", []string{`"one", "two"`}, "", false},
		{"multiple-lines", []string{`"one"`, `"two"`}, "", false},
		{"duplicate-lines", []string{`"one"`, `"one"`}, "", false},
		{"opaque-space", []string{`"a b"`}, "", false},
		{"opaque-tab", []string{"\"a\tb\""}, "", false},
		{"control", []string{"\"a\x01b\""}, "", false},
		{"delete", []string{"\"a\x7fb\""}, "", false},
		{"escaped-quote-not-escape", []string{`"a\"b"`}, "", false},
		{"outer-newline", []string{"\n\"revision\""}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := SingleStrongETag(http.Header{"Etag": tc.values})
			if got != tc.want || ok != tc.ok {
				t.Fatalf("got=%q valid=%v want=%q valid=%v", got, ok, tc.want, tc.ok)
			}
		})
	}
}
