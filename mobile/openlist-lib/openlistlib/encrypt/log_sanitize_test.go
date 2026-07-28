package encrypt

import "testing"

func TestSafeURLForLogStripsCredentialsAndSignedMaterial(t *testing.T) {
	got := safeURLForLog("https://user:pass@CDN.Example.com/private/file?token=secret#fragment")
	if got != "https://CDN.Example.com" {
		t.Fatalf("safeURLForLog() = %q", got)
	}
	if got := safeURLForLog("/relative/path?token=secret"); got != "<relative-or-invalid-url>" {
		t.Fatalf("relative URL was not redacted: %q", got)
	}
}
