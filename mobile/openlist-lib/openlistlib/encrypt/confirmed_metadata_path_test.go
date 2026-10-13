package encrypt

import "testing"

func TestConfirmedMetadataCanonicalPathPreservesDecodedPercent(t *testing.T) {
	for input, want := range map[string]string{
		"/dav/library/a%2fb.mkv": "/dav/library/a%2fb.mkv",
		"/d/library/a%252fb.mkv": "/dav/library/a%252fb.mkv",
		"/p/library/中文.mkv":      "/dav/library/中文.mkv",
		"/dav2/library/a.mkv":    "/dav/library/a.mkv",
		"/library/a.mkv":         "/dav/library/a.mkv",
		"":                       "",
	} {
		if got := canonicalMetadataDAVPath(input); got != want {
			t.Errorf("path %q: got %q want %q", input, got, want)
		}
	}
}
