# P1 mobile SQLite snapshot — startup scope

## Contract

`local_media.db` construction now waits for a complete verified SQLite backup **before** opening the normal writer or running `initLocalSchema`. A missing database skips backup. An existing empty, corrupt, unreadable database, a busy/no-progress backup, cancellation, or a durability error fails construction; it is not represented as a successful backup.

The proxy's existing upper-level `initLocalStore` fallback remains: it logs **Local persistence disabled** and continues with no local store when construction fails. This is degraded/ephemeral cache behavior, not a persisted-storage success and not an application-wide startup failure. No existing database is migrated after snapshot failure. The `schema_version=7` marker is now written only after `migrateLocalSchema` and `initConfirmedMetadataSchema` both succeed. The existing migration sequence is still not one atomic transaction: a migration error can leave partial DDL, but it cannot advance the version marker; transactional migration refactoring remains follow-up work.

The pinned `github.com/mattn/go-sqlite3 v1.14.22` provides destination `SQLiteConn.Backup`, `Step`, `Remaining`, `PageCount`, `Finish`. `Step(false,nil)` can mean BUSY/LOCKED and is not progress. The loop has a cooperative 30-second overall context budget and a 2-second no-page-progress budget, copying 128 pages per step and calling `Finish` exactly once. These are cancellation checks, not a hard wall-clock guarantee: a blocking filesystem sync or native call cannot be forcibly interrupted. Cancellation is checked again after parent-directory sync; a complete snapshot already published is retained and its path returned alongside the cancellation error. Source and destination have independent connections. The source uses `mode=ro`, **not immutable**, and an actual read inside a source transaction pins the WAL read snapshot before nested source/destination Raw callbacks; no pool SQL is called inside Raw.

Semantics: **committed database transactions only**. The snapshot includes actual database tables/indexes/triggers/views, not a selected export of sizes and strategies. It does not flush application buffers, promise a Flush barrier, invent a commit watermark, or coordinate other databases. TTL, confirmation, checkpoint and audit timestamps remain unchanged.

## Files and durability

Each snapshot is a unique `local_media.db.bak-<random>/` directory with:

- `database.sqlite` — sensitive, unencrypted data, mode 0600;
- `manifest.json` — format/component, creation time, SQLite version, full schema fingerprint/table inventory, content SHA-256/size, sensitivity and transaction semantics, mode 0600.

A private staging directory is copied, checked with read-only `PRAGMA integrity_check`, fingerprinted, hashed, manifest-verified, and fsynced. A private destination candidate is exclusively reserved. The verified database is hard-linked into it without overwriting, then the verified manifest is hard-linked last as the commit marker. Candidate and parent directories are synced. This is a manifest-last publication protocol, **not** an atomic whole-directory rename. Both links reference already verified/fsynced same-filesystem staging files; removing staging links does not remove the published files. Failure before the manifest link cleans only this call's owned candidate; after that link the complete package is retained even if sync or cancellation reports an error. **The `.bak-*` namespace contains candidates, not exclusively complete published snapshots.** A crash before the manifest link may leave an empty/database-only candidate; a crash before directory sync may persist only a subset of names. A snapshot is eligible for selection only after `verifyLocalStoreSnapshot` accepts its manifest, integrity, schema, hash and size; glob/name matching alone must never imply publication/completeness. Empty/incomplete reservations are unpublished and rejected by verification. There is no discovery/restore API in this batch that selects candidates automatically. A parent-sync failure is reported even though the complete published snapshot is retained. No previously good snapshot is overwritten or removed. There is deliberately **no automatic pruning** in this first safe implementation: historical `.bak-*` files, unknown directories, and even older owned snapshots are retained. Storage growth is an explicit follow-up risk; pruning must first establish a verified owned-format inventory.

Verification accepts only owned-format standalone rollback-journal packages: it rejects WAL-mode database headers and any WAL/SHM/journal sidecar before opening SQLite. It is not an arbitrary live SQLite database verifier. Verification does not initialize or upgrade a schema. Schema fingerprints include SQLite schema entries in deterministic order; manifests do not include source credentials, signed URLs, or fabricated build/commit identities. The database body may of course contain sensitive cached URLs and metadata and requires private storage.

## Deliberate non-goals

- No public runtime backup API/worker in this PR. The internal context-aware function uses independent connections and can be integrated in a later owner-admitted, cancel-and-join runtime worker. `Close` has no backup goroutine to cancel or join in this synchronous startup scope.
- No live restore. Tests rehearse copying to a disposable directory and verifying/querying it. Any future real restore needs service exclusion, backup of current state, and a reconciliation/write fence before old audit state may authorize writes. That fence is **not implemented here**.
- No OpenList `data.db`, Bolt, MySQL, or cross-component consistency claim.
- No cloud validation was launched from this worktree; the parent PR owns compilation and focused/full mobile tests. No local dependency downloads/builds were attempted.

## Review / cloud gates

Run the encrypt package tests in the existing mobile Go CI environment, including the rewritten `newbackup_test.go` startup-order/ownership tests and `local_store_backup_test.go` fixtures/faults. Existing store reopen tests now do synchronous filesystem I/O and create backup directories, not naked files. Same-filesystem hard links and candidate/parent-directory fsync need device/filesystem acceptance (Android/Linux intended); unsupported publication/durability fails closed rather than claiming success. Process-kill/crash, real ENOSPC and device tests remain acceptance work beyond deterministic injected sync errors.
