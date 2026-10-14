package encrypt

import (
	"context"
	"net/http"
	"time"

	core "github.com/alist-encrypt-go/shared/encryptcore"
)

// No current mobile provider adapter proves an immutable revision. Strict mode
// therefore deliberately re-reads rather than promoting an arbitrary ETag into
// a provider version, and never shares hot plaintext/authenticated records.
func (p *ProxyServer) strictFreshnessEnabled() bool {
	if p == nil {
		return false
	}
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.config != nil && p.config.StrictFreshness
}

// resolveStrictConfirmedMetadata does not join an older request's flight or
// read restored/TTL geometry. The caller's fresh canonical fs/get is mandatory:
// a still-readable signed URL does not establish current authorization.
func (p *ProxyServer) resolveStrictConfirmedMetadata(ctx context.Context, holder *confirmedMetadataRequest, enc *EncryptPath, size int64) (ContentMeta, bool) {
	failed := LegacyContentMeta(enc.EncType, size)
	if holder == nil || holder.identity.CryptoFingerprint != confirmedMetadataCryptoFingerprint(enc) || ctx.Err() != nil {
		return failed, false
	}
	state := &p.confirmedMetadata
	state.mu.Lock()
	entry := state.ensureEntry(holder.identity, time.Now())
	if entry == nil {
		state.mu.Unlock()
		return failed, false
	}
	generation := entry.generation
	state.mu.Unlock()

	// Preserve current caller credentials, never the cached redirect's headers.
	auth := holder.callerHeaders.Clone()
	target, currentSize := p.resolveEncryptedRawURLViaFsGet(ctx, auth, holder.davPath)
	if target == "" || ctx.Err() != nil {
		return failed, false
	}
	collector := &confirmedMetadataCollector{}
	inspectCtx := context.WithValue(ctx, confirmedMetadataCollectorKey{}, collector)
	meta, recognized := p.inspectEncryptedContentConfirmed(inspectCtx, target, auth, enc, currentSize)
	collector.mu.Lock()
	proof := collector.proof
	collector.mu.Unlock()
	if recognized && meta.IsV3() && ValidateV3ContentMeta(meta) != nil {
		return meta, true // Recognized V3 must remain a terminal format failure.
	}
	if !recognized || !proof.captured || !proof.reusable || proof.total != meta.CiphertextSize {
		return failed, false
	}
	now := time.Now().Unix()
	rec := confirmedMetadataRecord{Identity: holder.identity, Meta: meta, Provenance: confirmedMetadataProvenanceInspection, ConfirmedAt: now, ValidatedAt: now, ETag: proof.etag, LastModified: proof.lastModified, ValidatorScope: proof.scope, Generation: generation}
	if !validConfirmedMetadataRecord(rec) {
		// Recognized malformed V3 stays terminal, never downgrade to legacy.
		return meta, recognized
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if ctx.Err() != nil || state.entries[holder.identity] != entry || entry.generation != generation {
		return failed, false
	}
	state.coldStarts.Add(1)
	// Request-local only. No persistent write, no promotion into TTL evidence.
	holder.attach(rec)
	holder.mu.Lock()
	holder.strictTarget = target
	holder.mu.Unlock()
	return meta, true
}

func strictConfirmedMetadataTarget(ctx context.Context, fallback string) string {
	if holder := confirmedMetadataRequestFromContext(ctx); holder != nil {
		holder.mu.Lock()
		defer holder.mu.Unlock()
		if holder.strictTarget != "" {
			return holder.strictTarget
		}
	}
	return fallback
}

// Evidence is explicit about the bounded-cache assumption and lack of a
// cross-request atomic snapshot. Neither geometry nor this header proves AEAD
// authentication (only the record reader can do that).
func (p *ProxyServer) setMetadataFreshnessHeaders(w http.ResponseWriter) {
	evidence := core.MetadataFreshnessEvidence(p.strictFreshnessEnabled())
	w.Header().Set("X-Encrypt-Freshness-Policy", string(evidence.Policy))
	w.Header().Set("X-Encrypt-Freshness-Evidence", string(evidence.Level))
	w.Header().Set("X-Encrypt-Atomic-Snapshot", "false")
	if p.strictFreshnessEnabled() {
		w.Header().Set("X-Encrypt-Stable-Object-Assumption", "between-requests-no-atomic-snapshot")
	} else if evidence.StableObjectAssumption {
		w.Header().Set("X-Encrypt-Stable-Object-Assumption", "bounded-24h")
	} else {
		w.Header().Set("X-Encrypt-Stable-Object-Assumption", "none")
	}
}
