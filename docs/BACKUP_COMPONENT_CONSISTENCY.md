# Root Bolt component snapshot — current P1 scope

This document describes only `internal/storage` root Bolt support. It does not
claim SQLite/MySQL/mobile backup, a cross-store point-in-time snapshot, restore
integration, a running backup scheduler, retention, or completed P1 acceptance.

Root runtime configuration (`cfg.configJSON`) is an independently atomically
published JSON file, **not** the Bolt `BucketConfig` bucket. This component copies
that bucket only as database content; it does not capture the external runtime
configuration JSON or promise a full-configuration/whole-site backup. A future
owner/API integration must explicitly include that external configuration and
coordinate its publication boundary with the relevant database snapshots before
claiming a coordinated backup. Owner/API integration is outside this library-only
phase and must not be inferred from the presence of a bucket named `config`.

## APIs and exact consistency promise

- `(*Store).Snapshot(ctx, io.Writer, SnapshotOptions) (SnapshotManifest, error)`:
  one `db.View`, with the complete `tx.WriteTo` and watermark `tx.ID()` in that
  same transaction. Semantics are **committed transactions**, not flushed
  application buffers, attempted writes, or the process-local `WriteTxnCount`.
  Concurrent later commits do not enter this snapshot. Rollbacks do not advance
  its watermark. All buckets, including unknown/nested buckets, are copied.
- `(*Store).CreateSnapshot(ctx, directory, name, options)`: controlled local-file
  wrapper. Directory must already exist and be trusted (no hostile symlink/path
  replacement); name is one basename. Positive `MaxBytes` bounds the database
  payload; tar headers/manifest/padding add a small bounded overhead. Multiple
  temporary DB copies plus the bundle require additional disk space.
- `ValidateSnapshot(ctx, dbPath, manifest)`: verifies an immutable offline DB.
- `ValidateSnapshotBundle(ctx, bundlePath, maxBytes)`: verifies a bundle via
  private temporary extraction; does not restore it or mutate production data.

The manifest has versioned format/schema identifiers, root-Bolt component,
optional 40/64-hex source commit, creation time, payload bytes/SHA-256, transaction
ID and the literal `committed transactions` semantics. Commit is caller-supplied;
this code does not discover or attest build provenance. No original filename,
record value, credentials, source path, or signed URL is placed in the manifest.
SHA-256 detects accidental modification; it is not a signature/authenticity proof.

## Publication and sensitivity

A unique 0700 staging directory is created inside the destination filesystem.
Database is written as 0600, synced and closed, then hash/engine/audit validated.
A tar bundle containing exactly `manifest.json` and `database.bolt` (0600 member
modes) is created as 0600, synced/closed, then the actual packaged DB is extracted
and validated again. A same-filesystem hard link publishes the finished bundle
without overwriting an existing destination; no live naked DB copy or overwriting
rename is used. Output directory is synced after publication. Filesystems without
hard-link support fail closed. Directory-sync failure can return an error after
a valid bundle has become visible; callers must inspect that name before retrying.
There is no retention deletion and no failure path deletes an older good bundle.
Staging cleanup errors are joined into the returned error. Bundle format is strict
standalone USTAR: physical headers are checked before the logical tar reader;
PAX/GNU extensions, unexpected metadata/link names, missing two-block terminators,
nonzero trailing bytes and concatenated archives are rejected. Additional complete
all-zero padding blocks are allowed; total archive parsing has bounded overhead.

The database payload is **sensitive and unencrypted**: complete original names,
reservation tokens, settings and potentially stored credentials are present.
0600 is not encryption or a full Windows ACL policy. Keep destination directories
private, do not upload these bundles publicly, and apply separately managed
at-rest encryption/access controls if required. A manifest without secrets does
not make its DB payload safe to share.

## Validation is read-only, not repair

Validator first verifies payload byte count/hash, then uses `bolt.Open` with
`ReadOnly: true` and bounded lock timeout, never `NewStore` (which creates
buckets). It drains all `tx.Check()` results before leaving the transaction,
including on cancellation/error. It checks the manifest transaction ID and the
root schema's initialized base buckets. The four audit buckets are validated as
strict bidirectional pairs:

1. `filename_reservations_v1` ↔ `filename_original_index_v1`;
2. `verified_media_aliases_v1` ↔ `verified_media_reverse_v1`.

Absent pairs are allowed for legacy/lazy initialization; a half-present pair is
an error. Records must have structurally valid fields, statuses/token/geometry
and derived primary keys. Every primary needs its exact derived reverse key and
every reverse must point back to a matching primary (no orphan, extra wrong key,
or nested audit bucket). Errors do not echo original names or raw record values.
Expired but structurally valid media aliases remain valid backup records: no TTL
lookup is used and no verification timestamp is renewed. Unknown buckets are
preserved, not interpreted, removed or repaired.

## Cancellation, budgets and ownership boundaries

Positive byte budgets are mandatory. Snapshot preflights transaction size and
checks context before/after writes in chunks no larger than 64 KiB; short writes
are errors. Deadline is the caller's context deadline. No background copy worker
is abandoned: the transaction, temporary files, tar writers, readers and DB are
closed/joined before return. Caller retains ownership of the low-level writer.

**Not hard-real-time cancellation:** arbitrary `Writer.Write`, disk writes,
`fsync`, Bolt transaction acquisition/mmap/open/`tx.Check`, directory operations
and cleanup may block in the OS. Context cannot interrupt those calls; it is
checked at cooperative boundaries. In particular a gate writer must unblock
before `Snapshot` can return and release its transaction. Read transactions can
pin old pages and delay remapping while writes continue: schedule/rate-limit
backups externally; this phase adds no worker admission/Stop protocol. Byte
budget does not bound validator CPU or `tx.Check` memory for a very large DB.

## Offline exercise, not production restore or fencing

Tests write snapshots only into `t.TempDir()` and reopen them read-only to check
records and unknown buckets. There is no production writable restore API, no
hot overwrite, no restored Store returned to callers, and no claim of a durable
reconciliation fence. Before a future restore may serve writes it needs an
independent, persistent fail-closed read-only/reconciliation fence that survives
restart, invalidation of transport/session state, and operator reconciliation of
remote objects created after the old audit snapshot. A manifest field or a
read-only validation open is **not** that executed fence. Do not reset alias
verification timestamps or treat restored old auth/rule evidence as fresh.

## Test coverage and remaining acceptance

`backup_test.go` covers real Reserve/Complete/Failed with Chinese originals,
expired aliases, unknown nested buckets, concurrent transaction/gate writer
watermarks, canceled/deadline contexts, byte budget, short writes, blocked-writer
join, bad hash, missing/orphan/wrong reverse indexes, no source repair, private
verified bundle, destination collision, prior-good preservation and altered
bundle payload. This change intentionally does not rerun the root heavy Go
dependency tests on this machine (previous root dependency test exceeded 60s).
Formatting/diff gates are local evidence only; parent review/CI must supply actual
compilation/race/test results. Real ENOSPC, fsync failure, process crash at each
publication boundary and platform/filesystem capability acceptance remain future
integration/fault-injection work; those scenarios are not claimed as tested.
