# P5 conservative freshness: implemented subset

This change is not full completion of REMAINING_ENGINEERING_PLAN §10. No format, encrypted file, deployment or production configuration is changed. `strictFreshness` is opt-in; absent/false retains existing compatibility behavior.

## Evidence contract

`shared/encryptcore.FreshnessEvidence` contains only `level`, `policy`, `stable_object_assumption`, `atomic_snapshot`. Evidence kinds are **not a trust ordering**:

| level | Meaning / boundary |
|---|---|
| `local_hint` | Imported/listed/legacy persisted metadata; not current authorization or nonce proof. Root compatibility playback conservatively reports this. |
| `confirmed_metadata` | Fresh format/geometry observed for current caller/rules; not authenticated global header/trailer, remote immutable version, or whole-transfer atomicity. |
| `upstream_ttl_recent` | Scoped bounded reuse under a stable-object assumption; not strict freshness. |
| `provider_validator` | Reserved for explicitly reliable revision capability in the same object/representation namespace. Unknown/weak ETag, Last-Modified, signed URL and mathematical KDF key are NOT this evidence. No new code promotes arbitrary ETags to this level. |
| `aead_authenticated_record` | Authentication of one record/index/nonce/key, not object identity or complete container metadata. |

Playback headers `X-Encrypt-Freshness-Policy` and `X-Encrypt-Freshness-Evidence` expose only safe labels. Never expose RawURL/signatures, credentials, nonce/KDF key material or private scope hashes in evidence. All current descriptors explicitly decline atomic-snapshot guarantees.

## Actual root path

`executeDecryptPlayback` strict branch calls `strictPlaybackMetadata`: **first** canonical `/api/fs/get` with current caller Authorization/Cookie and `refresh:true` (no admin/service fallback), requires HTTP/API code 200 and returned RawURL, then reads fresh geometry from that exact route without cached supplied size. No fallback race can select a different signed URL/object. Cross-host geometry probes do not forward caller credentials. Failure/cancellation/config revision change is terminal before decryption.

The result remains request-local; it is not published to old unscoped geometry caches. Both actual StreamProxy decrypt entrypoints and response-consumption boundary require the exact target and current Config.RuntimeRevision marker. A retry to a changed URL cannot silently inherit it. Direct legacy routes not using the checked orchestration fail closed in strict mode rather than bypassing it. Strict requests disable legacy plaintext and V3 authenticated-record hot reuse (read AND publication) without clearing process-global caches or KDF caches used by compatible instances.

`freshness_test.go` root fixture asserts two sequential inspections make `authorizedquery_count=2`, `geometry_count=2`; after permission revocation `authorizedquery_count=3`, `geometry_count=2` despite signed URL remaining readable. Proxy test covers unchecked actual stream, old epoch marker and changed URL rejection, and disabled plaintext cache key.

## Mobile

Mobile `freshness.go` reuses confirmed-metadata identity/entry generations but strict inspection is request-local: mandatory fresh canonical caller-only fs/get, returned route prefix/trailer, current generation and exact-target response validation. No restored TTL, older shared flight, or arbitrary ETag supplies strict proof. Advanced config, V2 HTTP config and gomobile server config carry the opt-in. Plaintext and V3 hot read/write reuse is disabled in strict without global KDF resets. UpdateConfig invalidates confirmed generations synchronously. Tests authored for repeated GET/HEAD/seek authorization counts, same-size nonce replacement, revocation, attached response invalidation and config/evidence/cache identity.

**Mobile remaining boundary:** this base lacks complete P0 request-admission config revision capture. Already-admitted inspections/attached generation fences are implemented, not the complete managed-update admission contract. Legacy V1/V2 routes which cannot safely rebind the later target fail closed when fresh target differs. These constraints must remain explicit; do not call the entire mobile config-update matrix complete.

## Deferred / not claimed

* Reliable provider revision capability adapters, namespace/representation-aware conditional 304/412 optimization, immutable revisions, validator piggyback proof, coordinated multi-request atomic snapshots.
* Complete root migration of historical geometry/alias caches into epoch+credential-scoped confirmed records and full mutation invalidation event bus. Compatibility remains legacy and is deliberately labeled hint rather than freshly authorized evidence.
* Strict seamless support for every direct legacy route: unchecked paths fail closed. Missing canonical encrypted path or missing fresh RawURL fails explicitly rather than using historical aliases.
* Full root/mobile hot-hit/HEAD/empty/tail-seek/two-hop TTL/token/credential/config-update cancellation matrix. Added tests are focused regression fixtures, not a claim that all section10 acceptance cases pass.
* Global exported manifest/API review and public V3 metadata redaction outside the new evidence structure.

## Validation

Local validation is formatting and `git diff --check` only, per the delegated no-heavy-local-Go instruction. Focused tests and compilation must run in the parent's Draft PR cloud matrix; no local test success is claimed. No commit/push performed by this worker.
