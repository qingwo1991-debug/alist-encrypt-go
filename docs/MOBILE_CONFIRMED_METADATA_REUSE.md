# Mobile confirmed metadata reuse

## Contract

The Android Go proxy maintains a separate confirmed-metadata cache and SQLite table. Admission requires a successful, bounded, validated inspection and complete V1/V2/V3 geometry. A recognized but invalid V3 header, truncated/compressed prefix, directory size, legacy import, or old FileInfo tuple does not become confirmed metadata.

Identity is a digest of the configured origin, canonical encrypted DAV object path, caller authorization/cookie scope, and encryption rule fingerprint. Signed CDN URLs and their expiry are transport concerns, not stable content identity. Secret credentials and encryption passwords are hashed, never stored in this table. Multiple cold waiters share one lifecycle-owned inspection; cancellation of one waiter does not kill another. Confirmed records are synchronously persisted, and survive process restart. The memory cache is bounded to 2048 identities.

A fresh complete record avoids additional metadata-prefix/HEAD/PROPFIND/fs-get calls made solely to reconfirm geometry. Actual media requests, real authorization of local HEAD/empty V3 responses, and necessary signed-URL resolution are **not** eliminated. Geometry expires after 24 hours and is rechecked on demand, not by periodic polling. The ordinary owned inspection budget is 15 seconds; explicit Depth:0 budgets and speculative warm probes use smaller caps. SQLite busy time is separate from the network budget.

The fs/get route now publishes its required fresh inspection into the same confirmed store, so the subsequent token playback does not repeat that proof. Its existing signed-URL-change path still requires a fresh inspection; this is a remaining endpoint-specific cost, not a promise that every transport refresh is probe-free.

Actual media responses are checked before forwarding successful headers/body: ciphertext total, full-response length, and same-origin/path strong ETag (or observed Last-Modified) conflicts invalidate confirmation. Unsupported Vary dimensions disable cache admission. A detected conflict fails closed for that response; the next request reconfirms rather than silently decrypting with stale geometry.

## Change detection and limitations

PUT/POST invalidate the object across credential/crypto variants. DELETE/MOVE/COPY conservatively clear the confirmed cache/table because these may mutate an unknown subtree; the mapped Destination is also invalidated. Authoritative Depth:0 ciphertext-size conflicts trigger fresh confirmation. Old listing/import caches cannot repromote an invalidated tuple.

For explicit refresh, send `X-Encrypt-Metadata-Refresh: 1` on a WebDAV request. This invalidates that object's confirmed variants before normal authorized handling. It does not grant permission or promote imported metadata.

**Same-path, same-size replacement without a comparable strong validator/immutable object version cannot always be detected on a seek-only request.** V1/V2 are not authenticated formats. Cached size, nonce, a local fingerprint, and age are not proofs that the remote object is unchanged. URL refresh to another validator namespace also cannot make unrelated ETags comparable. This implementation uses a bounded 24-hour stable-object assumption where upstream validators are unavailable; manually refresh after replacements. It does not claim cryptographic authenticity for V1/V2 or permanent zero-probe freshness. V3 authenticated record verification remains in the playback path.

## Optional low-cost neighbor warming

`metadataNextWarmEnabled` is independently configurable and defaults to **false**. No battery-level, power-save, or metered-network telemetry is currently wired into this proxy; default-off avoids silently adding speculative radio work.

When enabled, complete successful Depth:1 XML listings supply real same-directory object candidates without extra listing requests or per-entry probes. Candidate memory is bounded to 32 directories and 128 video entries per directory. Only an unambiguous same-series, same-extension numeric episode +1 is selected; multi-number names such as season-and-episode pairs and ambiguous/truncated listings are skipped. This is an advisory neighbor, **not knowledge of MX's playlist**.

The first successful downstream body write of an encrypted GET can enqueue one neighbor. There is one server-wide worker and at most two pending tasks; admission never waits on foreground playback. Tasks use current caller credentials (never startup admin credentials), a five-second owned inspection budget, current origin/rule checks, offline/backoff skips, 24-hour successful and five-minute failed cooldowns. They read only necessary format headers/trailers, not video segments, and perform no decryption/KDF. Joining an already-running foreground inspection does not extend or cancel its lifetime. Speculation can still compete for transport/radio resources after the first write; device measurements are required to quantify battery and first-frame effects.

## Observability and validation

Probe stats include `metadata_hits`, `metadata_cold_starts`, `metadata_persistent_hits`, `metadata_invalidations`, `metadata_shared_waits`, and `next_warm_*` counters. Startup rootwarm still means upstream directory warming, not confirmed file metadata readiness.

Tests cover strict admission, scope isolation, persistent restart, cancellation/shutdown, in-flight invalidation, memory bounds, validator conflicts, authorization revocation, and real HTTP direct/redirect V1/V2/V3 repeated GET/HEAD/seeks. The GitHub mobile race regression selection includes `TestConfirmedMetadata` and `TestMetadataWarm`. Local validation is limited to formatting/diff checks; compilation and full tests run through a Draft PR.

Acceptance on a real device remains separate: compare the same file, phone, MX configuration and network; measure first decrypted byte/first displayed frame, tail seek, replay and next episode, plus probe counts and battery/radio impact. This document does not assert measured device improvements.
