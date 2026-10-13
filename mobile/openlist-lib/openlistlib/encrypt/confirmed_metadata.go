package encrypt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const confirmedMetadataLimit = 2048
const confirmedMetadataMaxAge = 24 * time.Hour

// confirmedMetadataState is owned by one ProxyServer. Its lock also fences
// synchronous store operations, so invalidation cannot race a delayed upsert.
// Never acquire p.mutex while holding this lock.
type confirmedMetadataState struct {
	mu             sync.Mutex
	entries        map[confirmedMetadataIdentity]*confirmedMetadataEntry
	nextGeneration uint64
	hits           atomic.Uint64
	coldStarts     atomic.Uint64
	persistentHits atomic.Uint64
	invalidations  atomic.Uint64
	sharedWaits    atomic.Uint64
}

func (p *ProxyServer) confirmedMetadataStats() map[string]uint64 {
	if p == nil {
		return map[string]uint64{}
	}
	s := &p.confirmedMetadata
	return map[string]uint64{"hits": s.hits.Load(), "cold_starts": s.coldStarts.Load(), "persistent_hits": s.persistentHits.Load(), "invalidations": s.invalidations.Load(), "shared_waits": s.sharedWaits.Load()}
}

type confirmedMetadataEntry struct {
	record     confirmedMetadataRecord
	flight     *confirmedMetadataFlight
	generation uint64
	loaded     bool
	used       time.Time
}
type confirmedMetadataFlight struct {
	done      chan struct{}
	meta      ContentMeta
	confirmed bool
	record    confirmedMetadataRecord
}
type confirmedMetadataRequestKey struct{}
type confirmedMetadataCollectorKey struct{}
type confirmedMetadataWarmBudgetKey struct{}
type confirmedMetadataObservedSizeKey struct{}
type confirmedMetadataFallbackKey struct{}

// withConfirmedMetadataFallback opts playback into authenticated canonical DAV
// fallback only after a target fails inspection. Ordinary DAV/warm resolution
// remains a single inspector call unless its own route explicitly opts in.
func withConfirmedMetadataFallback(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, confirmedMetadataFallbackKey{}, true)
}

// withConfirmedMetadataObservedSize carries an authoritative ciphertext size
// for this canonical object, not a plaintext size or an untrusted listing hint.
func withConfirmedMetadataObservedSize(ctx context.Context, size int64) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, confirmedMetadataObservedSizeKey{}, size)
}

func (p *ProxyServer) confirmedMetadataObjectID(encryptedDAVPath string) string {
	if p == nil || !strings.HasPrefix(encryptedDAVPath, "/") {
		return ""
	}
	origin := confirmedMetadataOrigin(p.getAlistURL())
	if origin == "" {
		return ""
	}
	return confirmedMetadataDigest(origin, encryptedDAVPath)
}

// withConfirmedMetadataWarmBudget caps the owned cold inspection itself, not
// just the warm caller's wait. Normal foreground callers retain a 15s budget.
func withConfirmedMetadataWarmBudget(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return withConfirmedMetadataProbeBudget(ctx, 5*time.Second)
}

// withConfirmedMetadataProbeBudget explicitly bounds owned inspections for
// latency-sensitive metadata routes, independently of waiter cancellation.
func withConfirmedMetadataProbeBudget(ctx context.Context, budget time.Duration) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if budget <= 0 || budget > 15*time.Second {
		budget = 15 * time.Second
	}
	return context.WithValue(ctx, confirmedMetadataWarmBudgetKey{}, budget)
}

type confirmedMetadataRequest struct {
	identity confirmedMetadataIdentity
	davPath  string // Canonical decoded encrypted DAV object path; never a CDN URL.
	mu       sync.Mutex
	record   confirmedMetadataRecord
	attached bool
}
type confirmedMetadataProof struct {
	captured                  bool
	reusable                  bool
	etag, lastModified, scope string
	total                     int64
}
type confirmedMetadataCollector struct {
	mu    sync.Mutex
	proof confirmedMetadataProof
}

func confirmedMetadataDigest(values ...string) string {
	// Length-delimited serialization avoids delimiter collisions and stores no
	// raw credentials, password, URL tokens, or crypto configuration in the DB.
	b, _ := json.Marshal(values)
	digest := sha256.Sum256(b)
	return hex.EncodeToString(digest[:])
}
func confirmedMetadataCryptoFingerprint(enc *EncryptPath) string {
	if enc == nil {
		return ""
	}
	return confirmedMetadataDigest(strconv.FormatBool(enc.Enable), string(normalizeContentEncType(enc.EncType)), enc.Password, enc.EncSuffix, strconv.FormatBool(enc.EncName), enc.Path)
}
func confirmedMetadataOrigin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	port := u.Port()
	if port != "" && !(scheme == "http" && port == "80") && !(scheme == "https" && port == "443") {
		host += ":" + port
	}
	return scheme + "://" + host
}
func confirmedMetadataValidatorScope(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	origin := confirmedMetadataOrigin(raw)
	if origin == "" {
		return ""
	}
	// Queries often contain rotated signatures. Different origins or paths are
	// different validator namespaces; their ETags must never be compared.
	return origin + u.EscapedPath()
}

// withConfirmedMetadataIdentity must be called with the canonical encrypted DAV
// object path, before resolving a redirect. It never derives identity from CDN
// URLs. Paths are not cleaned or unescaped here: that could collapse distinct
// upstream objects; the caller owns conversion to the canonical DAV path.
func (p *ProxyServer) withConfirmedMetadataIdentity(r *http.Request, encryptedPath string, enc *EncryptPath) *http.Request {
	if p == nil || r == nil || enc == nil || !enc.Enable || !strings.HasPrefix(encryptedPath, "/") {
		return r
	}
	objectID := p.confirmedMetadataObjectID(encryptedPath)
	if objectID == "" {
		return r
	}
	id := confirmedMetadataIdentity{
		ObjectID:          objectID,
		CryptoFingerprint: confirmedMetadataCryptoFingerprint(enc),
	}
	// Hash all values rather than Header.Get: duplicate credential headers must
	// not accidentally share an identity with a differently authenticated request.
	id.CredentialScope = confirmedMetadataDigest(strings.Join(r.Header.Values("Authorization"), "\x00"), strings.Join(r.Header.Values("Cookie"), "\x00"), strings.Join(r.Header.Values("Proxy-Authorization"), "\x00"))
	holder := &confirmedMetadataRequest{identity: id, davPath: encryptedPath}
	return r.WithContext(context.WithValue(r.Context(), confirmedMetadataRequestKey{}, holder))
}
func confirmedMetadataRequestFromContext(ctx context.Context) *confirmedMetadataRequest {
	if ctx == nil {
		return nil
	}
	holder, _ := ctx.Value(confirmedMetadataRequestKey{}).(*confirmedMetadataRequest)
	return holder
}

// confirmedMetadataForObject is a memory-only listing lookup. The context
// supplies the request credential and crypto scope, while the canonical child
// path supplies ObjectID. No legacy tuples, SQLite reads, probes, invalidations,
// or stale/unknown-size records are used by this cheap directory rewrite path.
func (p *ProxyServer) confirmedMetadataForObject(ctx context.Context, encryptedDAVPath string, size int64) (ContentMeta, bool) {
	holder := confirmedMetadataRequestFromContext(ctx)
	if p == nil || holder == nil || size <= 0 || ctx.Err() != nil {
		return ContentMeta{}, false
	}
	objectID := p.confirmedMetadataObjectID(encryptedDAVPath)
	if objectID == "" {
		return ContentMeta{}, false
	}
	id := holder.identity
	id.ObjectID = objectID
	state := &p.confirmedMetadata
	state.mu.Lock()
	defer state.mu.Unlock()
	entry := state.entries[id]
	if entry == nil || !confirmedMetadataFresh(entry.record, time.Now()) || entry.record.Meta.CiphertextSize != size {
		return ContentMeta{}, false
	}
	entry.used = time.Now()
	state.hits.Add(1)
	rec := cloneConfirmedMetadataRecord(entry.record)
	return rec.Meta, true
}

func cloneConfirmedMetadataRecord(rec confirmedMetadataRecord) confirmedMetadataRecord {
	rec.Meta.NonceField = cloneNonceField(rec.Meta.NonceField)
	return rec
}
func (h *confirmedMetadataRequest) attach(rec confirmedMetadataRecord) {
	h.mu.Lock()
	h.record = cloneConfirmedMetadataRecord(rec)
	h.attached = true
	h.mu.Unlock()
}

// captureConfirmedMetadataProof is an inspector hook, called only immediately
// before a successful validated-inspection return, with the actual final
// response. It does not perform I/O. Unknown/variant Vary values disable reuse.
func captureConfirmedMetadataProof(ctx context.Context, resp *http.Response, finalURL string) {
	if ctx == nil || resp == nil {
		return
	}
	collector, _ := ctx.Value(confirmedMetadataCollectorKey{}).(*confirmedMetadataCollector)
	if collector == nil {
		return
	}
	proof := confirmedMetadataProof{captured: true, reusable: true, etag: strings.TrimSpace(resp.Header.Get("ETag")), lastModified: strings.TrimSpace(resp.Header.Get("Last-Modified")), scope: confirmedMetadataValidatorScope(finalURL)}
	for _, value := range resp.Header.Values("Vary") {
		for _, field := range strings.Split(value, ",") {
			field = strings.TrimSpace(field)
			if field != "" && !strings.EqualFold(field, "Accept-Encoding") {
				proof.reusable = false
			}
		}
	}
	if interval, ok := parseContentRange(resp.Header.Get("Content-Range")); ok && interval.TotalKnown {
		proof.total = interval.Total
	} else if resp.StatusCode == http.StatusOK {
		proof.total = resp.ContentLength
	}
	collector.mu.Lock()
	collector.proof = proof
	collector.mu.Unlock()
}

func confirmedMetadataFresh(rec confirmedMetadataRecord, now time.Time) bool {
	// Store validates the full geometry; reject malformed provenance and times
	// here too, and never promote imported listing or legacy size rows.
	age := now.Unix() - rec.ConfirmedAt
	return validConfirmedMetadataRecord(rec) && rec.ConfirmedAt > 0 && rec.ValidatedAt >= rec.ConfirmedAt && age >= 0 && age < int64(confirmedMetadataMaxAge/time.Second)
}
func (s *confirmedMetadataState) ensureEntry(id confirmedMetadataIdentity, now time.Time) *confirmedMetadataEntry {
	if s.entries == nil {
		s.entries = make(map[confirmedMetadataIdentity]*confirmedMetadataEntry)
	}
	if entry := s.entries[id]; entry != nil {
		entry.used = now
		return entry
	}
	if len(s.entries) >= confirmedMetadataLimit {
		var oldestID confirmedMetadataIdentity
		var oldest *confirmedMetadataEntry
		for key, entry := range s.entries {
			if entry.flight == nil && (oldest == nil || entry.used.Before(oldest.used)) {
				oldestID, oldest = key, entry
			}
		}
		if oldest == nil {
			return nil
		}
		delete(s.entries, oldestID)
	}
	s.nextGeneration++
	entry := &confirmedMetadataEntry{generation: s.nextGeneration, used: now}
	s.entries[id] = entry
	return entry
}

// resolveConfirmedMetadata returns the inspector's recognition bit unchanged.
// Only stable identities may reuse metadata. Expired entries revalidate on
// demand (one shared foreground wait), never on timers or each playback.
func (p *ProxyServer) resolveConfirmedMetadata(ctx context.Context, target string, headers http.Header, enc *EncryptPath, size int64) (ContentMeta, bool) {
	if ctx == nil {
		ctx = context.Background()
	}
	holder := confirmedMetadataRequestFromContext(ctx)
	if p == nil || holder == nil || enc == nil || holder.identity.CryptoFingerprint != confirmedMetadataCryptoFingerprint(enc) {
		return p.inspectEncryptedContentConfirmed(ctx, target, headers, enc, size)
	}
	if ctx.Err() != nil {
		return LegacyContentMeta(enc.EncType, size), false
	}
	// Snapshot the store outside the cache lock (global server lock order).
	p.mutex.RLock()
	store := p.localStore
	p.mutex.RUnlock()
	state := &p.confirmedMetadata
	state.mu.Lock()
	entry := state.ensureEntry(holder.identity, time.Now())
	if entry == nil {
		state.mu.Unlock()
		return p.inspectEncryptedContentConfirmed(ctx, target, headers, enc, size)
	}
	if !entry.loaded {
		entry.loaded = true
		if store != nil {
			if rec, ok := store.GetConfirmedMetadata(holder.identity); ok && rec.Identity == holder.identity {
				entry.record = cloneConfirmedMetadataRecord(rec)
				if state.nextGeneration <= rec.Generation {
					state.nextGeneration = rec.Generation + 1
				}
				entry.generation = state.nextGeneration
				entry.record.Generation = entry.generation
				if confirmedMetadataFresh(entry.record, time.Now()) {
					state.persistentHits.Add(1)
				}
			}
		}
	}
	if observed, _ := ctx.Value(confirmedMetadataObservedSizeKey{}).(int64); observed > 0 && entry.record.Provenance != "" && entry.record.Meta.CiphertextSize != observed {
		state.invalidateObjectLocked(holder.identity.ObjectID, store)
		entry = state.ensureEntry(holder.identity, time.Now())
		entry.loaded = true // The object-wide store delete was synchronous.
		holder.mu.Lock()
		holder.attached = false
		holder.mu.Unlock()
	}
	if confirmedMetadataFresh(entry.record, time.Now()) {
		state.hits.Add(1)
		rec := cloneConfirmedMetadataRecord(entry.record)
		state.mu.Unlock()
		holder.attach(rec)
		return rec.Meta, true
	}
	flight := entry.flight
	if flight != nil {
		state.sharedWaits.Add(1)
	}
	if flight == nil {
		flight = &confirmedMetadataFlight{done: make(chan struct{})}
		entry.flight = flight
		generation := entry.generation
		// Clone caller-owned mutable inputs before the detached goroutine starts.
		auth := headers.Clone()
		encCopy := *enc
		budget := 15 * time.Second
		if explicit, ok := ctx.Value(confirmedMetadataWarmBudgetKey{}).(time.Duration); ok && explicit > 0 && explicit < budget {
			budget = explicit
		}
		fallback, _ := ctx.Value(confirmedMetadataFallbackKey{}).(bool)
		started := p.goBackground(func(lifetime context.Context) {
			completed := false
			// RoundTrippers and test hooks may terminate their goroutine with
			// runtime.Goexit; cancellation alone cannot close this flight then.
			// Do not recover panics, but always release waiters and admission.
			defer func() {
				state.mu.Lock()
				defer state.mu.Unlock()
				if !completed {
					flight.meta = LegacyContentMeta(encCopy.EncType, size)
					flight.confirmed = false
					flight.record = confirmedMetadataRecord{}
				}
				if current := state.entries[holder.identity]; current == entry && entry.generation == generation && entry.flight == flight {
					entry.flight = nil
					if !completed {
						entry.record = confirmedMetadataRecord{}
					}
				}
				close(flight.done)
			}()
			inspectCtx, cancel := context.WithTimeout(lifetime, budget)
			defer cancel()
			collector := &confirmedMetadataCollector{}
			inspectCtx = context.WithValue(inspectCtx, confirmedMetadataCollectorKey{}, collector)
			var meta ContentMeta
			var confirmed bool
			if fallback {
				// Normalize both object paths and already-prefixed DAV routes,
				// then escape decoded paths once, including literal %, #, ?.
				route := (&url.URL{Path: canonicalMetadataDAVPath(holder.davPath)}).EscapedPath()
				meta, confirmed = p.inspectEncryptedContentWithFallbackConfirmed(inspectCtx, target, auth, &encCopy, size, route)
			} else {
				meta, confirmed = p.inspectEncryptedContentConfirmed(inspectCtx, target, auth, &encCopy, size)
			}
			collector.mu.Lock()
			proof := collector.proof
			collector.mu.Unlock()
			now := time.Now().Unix()
			rec := confirmedMetadataRecord{Identity: holder.identity, Meta: meta, Provenance: confirmedMetadataProvenanceInspection, ConfirmedAt: now, ValidatedAt: now, ETag: proof.etag, LastModified: proof.lastModified, ValidatorScope: proof.scope, Generation: generation}
			state.mu.Lock()
			defer state.mu.Unlock()
			current := state.entries[holder.identity]
			validGeneration := current == entry && entry.generation == generation && entry.flight == flight
			if validGeneration {
				flight.meta, flight.confirmed = meta, confirmed
				// A recognized invalid V3 is not a confirmed complete record. The store's
				// validation rejects it too, but avoid publishing it to memory first.
				if confirmed && proof.captured && proof.reusable && proof.total == meta.CiphertextSize && validConfirmedMetadataRecord(rec) {
					entry.record = cloneConfirmedMetadataRecord(rec)
					flight.record = cloneConfirmedMetadataRecord(rec)
					if store != nil {
						_ = store.PutConfirmedMetadata(rec)
					}
				}
			}
			completed = true
		})
		if started {
			state.coldStarts.Add(1)
		}
		if !started {
			entry.flight = nil
			close(flight.done)
		}
	}
	state.mu.Unlock()
	select {
	case <-ctx.Done():
		return LegacyContentMeta(enc.EncType, size), false
	case <-flight.done:
		if flight.record.Provenance != "" {
			holder.attach(flight.record)
		}
		meta := flight.meta
		meta.NonceField = cloneNonceField(meta.NonceField)
		return meta, flight.confirmed
	}
}

// invalidateConfirmedMetadata fences already-running inspections as well as
// deleting persisted results. Their waiters receive unconfirmed, never stale
// metadata; a subsequent request is allowed to start a fresh generation.
func (p *ProxyServer) invalidateConfirmedMetadata(ctx context.Context) {
	holder := confirmedMetadataRequestFromContext(ctx)
	if p == nil || holder == nil {
		return
	}
	p.mutex.RLock()
	store := p.localStore
	p.mutex.RUnlock()
	state := &p.confirmedMetadata
	state.mu.Lock()
	state.invalidations.Add(1)
	delete(state.entries, holder.identity)
	if store != nil {
		_ = store.DeleteConfirmedMetadata(holder.identity)
	}
	state.mu.Unlock()
	holder.mu.Lock()
	holder.attached = false
	holder.mu.Unlock()
}

// invalidateConfirmedMetadataObject invalidates every credential/rule variant
// of a canonical encrypted DAV object, including in-flight warm inspections.
func (p *ProxyServer) invalidateConfirmedMetadataObject(encryptedDAVPath string) {
	objectID := p.confirmedMetadataObjectID(encryptedDAVPath)
	if objectID == "" {
		return
	}
	p.mutex.RLock()
	store := p.localStore
	p.mutex.RUnlock()
	state := &p.confirmedMetadata
	state.mu.Lock()
	state.invalidateObjectLocked(objectID, store)
	state.mu.Unlock()
}

// invalidateAllConfirmedMetadata is the conservative subtree mutation fence.
// ObjectIDs are hashed and cannot support path-prefix matching. Rare directory
// mutations deliberately clear all confirmed rows rather than risk descendants
// surviving a server-side MOVE/DELETE/COPY. Inspection admission is serialized
// with the synchronous store delete under the same mutex.
func (p *ProxyServer) invalidateAllConfirmedMetadata() {
	if p == nil {
		return
	}
	p.mutex.RLock()
	store := p.localStore
	p.mutex.RUnlock()
	state := &p.confirmedMetadata
	state.mu.Lock()
	state.invalidations.Add(1)
	state.nextGeneration++
	state.entries = nil
	if store != nil {
		_ = store.DeleteAllConfirmedMetadata()
	}
	state.mu.Unlock()
}

// Caller holds s.mu; never snapshot ProxyServer configuration under this lock.
func (s *confirmedMetadataState) invalidateObjectLocked(objectID string, store *localStore) {
	s.invalidations.Add(1)
	s.nextGeneration++
	for id := range s.entries {
		if id.ObjectID == objectID {
			delete(s.entries, id)
		}
	}
	if store != nil {
		_ = store.DeleteConfirmedMetadataObject(objectID)
	}
}

func confirmedMetadataStrongETag(value string) bool {
	return len(value) >= 2 && strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"")
}

// validateConfirmedMetadataResponse piggybacks on the real stream response,
// before client headers are written. false requires parent abort/re-resolve;
// no proof/no comparable validator uses the bounded stable-object assumption.
func (p *ProxyServer) validateConfirmedMetadataResponse(ctx context.Context, resp *http.Response) bool {
	holder := confirmedMetadataRequestFromContext(ctx)
	if holder == nil || resp == nil {
		return true
	}
	holder.mu.Lock()
	rec, attached := cloneConfirmedMetadataRecord(holder.record), holder.attached
	holder.mu.Unlock()
	if !attached {
		return true
	}
	conflict := false
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusPartialContent {
		if interval, ok := parseContentRange(resp.Header.Get("Content-Range")); ok && interval.TotalKnown {
			conflict = interval.Total != rec.Meta.CiphertextSize
		} else if resp.StatusCode == http.StatusOK && resp.ContentLength >= 0 {
			conflict = resp.ContentLength != rec.Meta.CiphertextSize
		}
		encoding := strings.TrimSpace(resp.Header.Get("Content-Encoding"))
		conflict = conflict || resp.Uncompressed || (encoding != "" && !strings.EqualFold(encoding, "identity"))
		if resp.Request != nil && resp.Request.URL != nil && rec.ValidatorScope != "" && confirmedMetadataValidatorScope(resp.Request.URL.String()) == rec.ValidatorScope {
			etag := strings.TrimSpace(resp.Header.Get("ETag"))
			if confirmedMetadataStrongETag(rec.ETag) && confirmedMetadataStrongETag(etag) {
				conflict = conflict || etag != rec.ETag
			} else if rec.LastModified != "" && resp.Header.Get("Last-Modified") != "" {
				conflict = conflict || rec.LastModified != strings.TrimSpace(resp.Header.Get("Last-Modified"))
			}
		}
		for _, value := range resp.Header.Values("Vary") {
			for _, field := range strings.Split(value, ",") {
				field = strings.TrimSpace(field)
				if field != "" && !strings.EqualFold(field, "Accept-Encoding") {
					conflict = true
				}
			}
		}
	}
	if conflict {
		p.invalidateConfirmedMetadata(ctx)
		return false
	}
	return true
}
