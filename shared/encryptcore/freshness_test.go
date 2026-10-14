package encryption

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFreshnessEvidenceDoesNotInventProviderProof(t *testing.T) {
	for _, strict := range []bool{false, true} {
		ev := MetadataFreshnessEvidence(strict)
		if ev.AtomicSnapshot || ev.Level == EvidenceProviderValidator || ev.Level == EvidenceAEADAuthenticatedRecord {
			t.Fatalf("invented freshness proof: %+v", ev)
		}
		raw, err := json.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"raw_url", "sign", "nonce", "password", "scope"} {
			if strings.Contains(string(raw), secret) {
				t.Fatalf("evidence exposes %s: %s", secret, raw)
			}
		}
	}
}
