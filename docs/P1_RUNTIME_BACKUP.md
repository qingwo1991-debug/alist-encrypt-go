# P1 root runtime backup owner (component only)

This phase adds an instance-owned, controlled disk worker around the existing
root Bolt snapshot library. It is **not a full-site backup**, scheduler, restore
endpoint, reconciliation fence, or authorization/RBAC migration.

## Exact scope

Every job status explicitly reports:

- `components: ["rootBolt"]`
- `excluded: ["external-runtime-config", "mysql", "sqlite"]`
- `scope: "component_only"`
- `full_restore_ready: false`

The read transaction captures committed Bolt transactions and all its buckets,
including its `config` bucket. That bucket is **not the external runtime
`conf.json`/`cfg.configJSON`**. Application buffers are not flushed by a new global
barrier. There is no cross-store or external configuration publication barrier.
MySQL may be active and authoritative for some runtime state; it remains excluded.
See [component consistency](BACKUP_COMPONENT_CONSISTENCY.md) for exact snapshot,
validation, publication, sensitivity and offline-only restore boundaries.

## API and management authorization scope

- `POST /enc-api/admin/backups`: empty body or `{}` uses defaults; optional
  `max_bytes` is an integer in `1..1073741824`, `timeout_seconds` in `1..30`.
  Unknown keys, client filenames/paths and trailing JSON are rejected; body is
  limited to 1024 bytes. Accepted returns 202. One worker and zero queued jobs;
  busy returns 409, sealed owner returns 503.
- `GET /enc-api/admin/backups/:id`: status of a known server-generated random ID;
  unknown/evicted IDs return 404 without filesystem access.
- `POST /enc-api/admin/backups/:id/cancel`: signals an active job; terminal jobs
  remain terminal. Returns the current status, not a promise that I/O has stopped.

These routes reuse the application's **real management JWT authentication** and
add a fresh persisted username existence check. Deleted/nonexistent accounts and
invalid JWTs fail generically before any job lookup. JWT credentials are not
provider credentials. The existing JWT schema has only username and the existing
user schema has no role: **all existing management accounts have this bounded
backup capability; separate administrator/nonadministrator role isolation is
unsupported in this phase**, despite the `/admin` route namespace. No fake token
or username spelling confers authorization; no new role field, implicit legacy
migration, or claim that a verified JWT proves an administrator role is introduced.
An explicit reviewed RBAC schema/provisioning/migration is required before claiming
role-scoped admin-only authorization. This limitation was chosen by parent scope
review; do not expose management credentials to untrusted users.

Status includes generic state/error, cancellation request, timestamps, component
scope and, on success, the non-secret component manifest. It does not expose
absolute paths, original names, signed URLs, reusable tokens, or download links.
`version` uses `config.Version` (currently the repository's `1.0.0` constant).
`source_commit` and manifest commit are populated only from valid 40/64-hex
`runtime/debug` build `vcs.revision` metadata; unknown provenance stays empty, not
an invented worktree HEAD. This is build metadata, not an attestation.

## Ownership and lifecycle

The owner is constructed by `Server.New`, not HTTP `Start`; it owns its context,
cancel, admission mutex, single active slot and wait group. Construction requires
`DataDir/backups` to be a real 0700 directory, creating it privately if absent;
an existing symlink or nonprivate directory fails closed and stores are closed.
The DataDir ancestry/filesystem must remain trusted and must not be replaced by a
hostile local process; this is not protection against a same-privilege filesystem
attacker. Workers call `Store.CreateSnapshot` directly with a random 128-bit ID
and a server-derived `.tar` basename. No ResponseWriter or request context is held
by a transaction. Existing storage verification publishes a sensitive, unencrypted
0600 bundle without overwriting older artifacts. Private modes are not encryption
or a full Windows ACL policy.

Cancellation and the 30-second deadline are **cooperative**, not hard real-time:
disk I/O, fsync, Bolt acquisition/check and cleanup may block until OS return.
Cancellation sets a signal/flag; only actual worker return records terminal state
and frees admission. A successful snapshot already published before a late cancel
is still successful. Failure messages are generic and never copy raw disk errors.

Shutdown first seals admission and signals cancellation, then shuts down HTTP,
then joins the actual backup worker before closing Bolt. Joining is mandatory even
if the HTTP shutdown context expires; shutdown can therefore exceed that deadline.
Shutdown works without Start and is idempotent through `sync.Once`. A lifecycle
mutex seals Start/preparation/request admission atomically with wait-group adds.
Listener preparation is joined outside that mutex; a late prepared listener is
closed rather than published after shutdown. All HTTP/HTTPS/Unix listeners are
prepared before Serve, and startup/Serve failure closes siblings and drains them.
Repeat Start (including Start after Stop) is rejected. Request handlers are owned
and joined before DAO/store shutdown even when HTTP Shutdown times out: Close
cancels ordinary connection I/O, while an instance cancellation context also
signals request contexts (including h2c hijacked sessions). A handler ignoring
cancellation must actually return before the store closes. Idle hijacked h2c
transport sessions are not counted as active application handlers; after sealing,
new requests receive 503 without accessing closed stores.

Latest 64 job statuses are retained in memory (including the active job); terminal
entries are evicted on admission, with no unbounded status map. Status does not
survive restart. **Artifact retention/deletion is not implemented**: operators
must manage private disk capacity offline; per-job payload is bounded but repeated
successful jobs can consume disk cumulatively. Errors never delete earlier good
backups; a publication/directory sync error may leave a valid new artifact, per
the storage component contract. No runtime restore or unfencing is offered.

## Validation evidence

`backup_owner_test.go` uses real Bolt fixtures plus a controllable blocked runner:
real private validated artifact, previous-good preservation, strict bounds,
symlink rejection, latest-64 status cap, actual management JWT/unknown-user checks,
create/busy/status/cancel, slot retention until return, no-Start shutdown drain and
repeat shutdown. Shutdown fixture accesses Bolt after cancellation while blocked,
proving the store remains open until worker return. `lifecycle_test.go` adds real
listener gates before preparation and before publication, Start/Stop races,
repeat/never-started lifecycle, sibling failure cleanup, real network requests
blocked through canceled Shutdown with actual context signaling and store access
before handler return, and `New`/production routes/JWT/HTTP-to-validated-disk-bundle
integration. The cancellation disk fixture cancels before CreateSnapshot enters;
it does not simulate a blocked filesystem syscall. Formatting and diff checks
are local gates; root heavy compilation/test/race execution is delegated to parent
cloud validation, not claimed from formatting. ENOSPC/crash/fault injection and
platform-specific ACL/FS capability tests remain unverified.
