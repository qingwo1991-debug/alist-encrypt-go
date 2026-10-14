package encryption

// EvidenceLevel describes distinct evidence, not an ordered trust score. In
// particular record authentication does not authenticate container metadata.
type EvidenceLevel string

const (
	EvidenceLocalHint               EvidenceLevel = "local_hint"
	EvidenceConfirmedMetadata       EvidenceLevel = "confirmed_metadata"
	EvidenceUpstreamTTLRecent       EvidenceLevel = "upstream_ttl_recent"
	EvidenceProviderValidator       EvidenceLevel = "provider_validator"
	EvidenceAEADAuthenticatedRecord EvidenceLevel = "aead_authenticated_record"
)

type FreshnessPolicy string

const (
	PolicyBoundedCache    FreshnessPolicy = "bounded-cache"
	PolicyStrictFreshness FreshnessPolicy = "strict-freshness"
)

// FreshnessEvidence is safe to expose in API responses. Never add transport
// URLs, signatures, credentials, nonce/key material or private scope digests.
// Confirmed metadata means geometry observed under the current authorization
// and rule epoch, NOT cryptographic header authenticity or an atomic snapshot.
// ProviderValidator requires an explicitly reliable provider revision capability
// and matching object/representation namespace; an arbitrary ETag is not proof.
type FreshnessEvidence struct {
	Level                  EvidenceLevel   `json:"level"`
	Policy                 FreshnessPolicy `json:"policy"`
	StableObjectAssumption bool            `json:"stable_object_assumption"`
	AtomicSnapshot         bool            `json:"atomic_snapshot"`
}

// MetadataFreshnessEvidence deliberately makes no atomic-snapshot claim even
// after a fresh prefix/trailer query: the provider can change between requests.
func MetadataFreshnessEvidence(strict bool) FreshnessEvidence {
	if strict {
		return FreshnessEvidence{Level: EvidenceConfirmedMetadata, Policy: PolicyStrictFreshness, StableObjectAssumption: true}
	}
	return FreshnessEvidence{Level: EvidenceLocalHint, Policy: PolicyBoundedCache, StableObjectAssumption: true}
}
