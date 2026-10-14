# P8 / 13.1 conservative first batch

## Implemented (not full 13.1 acceptance)

The authoritative filename occupancy/name audit remains the existing local Bolt store, including when ordinary metadata uses MySQL. This batch does not implement CAS, distributed coordination, HA, retry uploads, mutation, cleanup, or occupancy release.

Management endpoints:

- `GET /enc-api/filenameAudit`
- `GET /enc-api/exportFilenameAudit` (same bounded JSON page contract, not an unbounded DB dump)
- `POST /enc-api/filenameReconcileDryRun` (local checks plus append-only check evidence)

All require header `Authorization: Bearer <management JWT>`, an extant persistent management user checked on **each request**, explicit `version=1&sensitive=true`, and these mandatory bounds:

- `path_prefix`: canonical absolute raw/physical path prefix, component-boundary matching; `/` explicitly selects the entire origin within time/scan bounds.
- `from`, `until`: RFC3339 timestamps selecting reservation creation times, `[from,until)`, at most 31 days.
- `limit`: 1–100 records.
- Optional `include_names=true`: opt in to original path/display name. Defaults omit those JSON fields, not merely empty values. Tokens, auth/rule digests, passwords and nonce fields never appear in DTO JSON.
- Optional `cursor`: opaque AEAD-encrypted continuation valid 15 minutes. Binds management username/current stored password hash, current configured root upstream origin, version, all query fields/bounds/name selection, and query versus dry-run mode. Server secret rotation invalidates it. Re-submit the identical query plus cursor. Limit is also bound. Unknown/duplicate fields are rejected.

This model has **no Role field**: extant management users share management access; no new or fictitious admin-role authorization is claimed. `sensitive=true` is explicit acknowledgement, not a separate RBAC grant or proof of upstream permission. Deleting/renaming a user makes its old JWT ineligible for these endpoints. Existing JWTs do not carry password revision and password changes alone do not revoke an initial-page JWT; password change does invalidate its previously issued audit cursors.

Each page is one consistent Bolt view, not a persistent cross-page snapshot. Both output and work are bounded (100 records, 1000 inspected physical records per page); filtered pages may be empty with a continuation. Exports must follow `next_cursor` until empty. Changes during export can cause live-pagination misses: do not call this a backup or snapshot. Responses are `no-store`.

Selected records check primary key identity and original-name reverse mapping in the same Bolt transaction; duplicate historical original entries sharing one reverse mapping yield a violation rather than getting silently deduplicated. This is **not** exhaustive reverse-orphan/alias validation or remote evidence. No default stats route has been changed or given original names/tokens.

Dry-run returns a new random `op_id` for each request (including repeated identical requests), counts checked local invariants and appends a separate `filename_management_checks_v1` entry. Reusing an existing check ID is rejected atomically. Check IDs are never reservation tokens or permission for upload/nonce retry. Only this append-only checks bucket is written; existing reservations, indexes, aliases, upload statuses, remote files and metadata are unchanged. Check storage failure refuses a success response. No automatic TTL or deletion is introduced.

## Explicitly deferred / runtime blocked

`remote=unknown`, `actual_remote_check=false`, and an explicit `runtime_blocked` reason are always returned by this first dry-run batch. There is **no actual remote check**. Management JWT is not an upstream credential. We have not established an authorized current-caller root-upstream/known-route resolver and a verified safe backup capability for this operation. We deliberately do not improvise scan credentials, accept arbitrary URLs, follow caller URLs, or send a management JWT upstream. No 404 (including final-consistency/list delay) can release occupancy; no remote absence inference is made at all.

Pending/failed/complete history and v1 reservation bytes/schema are preserved. Check evidence uses a new additive bucket only; no reservation status migration was needed for read-only management. Unknown is a check result, **not** a destructive rewrite of old upload status. Reconciliation/tombstone state transitions, repair confirmation, backup/restore procedure, remote result verification and authenticated remote querying remain later work. Old binaries ignore this additional bucket but cannot expose check evidence; retain the full database when rolling back and never use rollback as occupancy cleanup.

13.3 rename/move/copy (including directories, cross-rule/backend) guards remain unchanged and refusing unproven capabilities. No provider CAS, remote conditional create, no-overwrite, Wopan interoperability or HA completion is claimed. Do not report full 13.1 / P8 completion.

## Validation and delivery

Focused tests cover sensitive JWT absence, deleted persistent user, required bounds, JSON original-name opt-in/token exclusion, cursor authentication/scope/secret conservation, duplicate Bolt reverse-index invariants, append-only check ID rejection, and dry-run reservation/occupancy preservation. Full compilation and CI still required on parent Draft PR. No commit or push performed by this batch.

Local formatting uses `/usr/local/go/bin/gofmt`; `git diff --check` is a cheap gate. The one focused Go attempt was blocked by read-only host module/build caches (dependencies unavailable to this session); no download/build retries or sandbox workaround were performed. The parent should run focused tests plus complete CI with its authorized environment, rather than treating the test sources as passing evidence.
