# P1: OpenList ForceDBSync checkpoint semantics

## Verified implementation facts

- Scope is `mobile/openlist-lib/openlistlib/server.go` → `internal/db.GetDb()` → the actual GORM `Dialector.Name()`. This is the OpenList database (`data.db` for the SQLite deployment), **not** the encrypt proxy's `local_media.db`.
- `internal/bootstrap/db.go` supports SQLite, MySQL and PostgreSQL. Default/mobile SQLite uses `github.com/glebarez/sqlite v1.11.0` (existing `github.com/glebarez/go-sqlite v1.21.2` dependency). `sqlite_cgo_compat` and specified legacy architecture build tags select `gorm.io/driver/sqlite v1.5.6`. Both SQLite dialectors report `sqlite`; configuration calls it `sqlite3`. We branch on the actual dialector, not configuration or a filename.
- `ForceDBSync() error` remains unchanged for gomobile. Detailed `checkpoint.Result` is internal Go-only, avoiding new generated bridge signatures. It records driver/mode, supported/attempted, busy/log/checkpointed and complete; the bridge logs these fields and returns errors.
- The SQLite call uses `QueryContext` and `Rows.Scan` to read `PRAGMA wal_checkpoint(mode)`'s three values. Query, scan, iteration, close and context errors are not success. Rows are closed. The existing default is PASSIVE, timeout 2000 ms, configurable via `OPENLIST_WAL_CHECKPOINT_MODE` and `OPENLIST_WAL_CHECKPOINT_TIMEOUT_MS`; mode is allowlisted to PASSIVE/FULL/RESTART/TRUNCATE (invalid values fall back to PASSIVE). Cancellation uses the SQL driver's context implementation; a timeout is not a stronger guarantee than that driver's cancellation behavior.

## Outcome contract

| Actual result | Detailed outcome | Existing error-only bridge |
| --- | --- | --- |
| SQLite busy=0, log=checkpointed, both nonnegative | complete for this invocation | nil |
| SQLite busy != 0, or unequal/invalid counters | incomplete, retain counters | error containing mode and counters |
| SQLite busy=0, log=checkpointed=-1 | no active WAL, not a checkpoint | error (`ErrNoWAL`) |
| Query/read/scan/close/cancellation failure | incomplete | wrapped error |
| MySQL/PostgreSQL/other dialect | unsupported, not attempted | error (`ErrUnsupported`) |
| Uninitialized DB or inaccessible SQL handle | not performed | error |

PASSIVE can return **busy=0 and checkpointed < log** while a reader pins WAL pages. Executing the statement without a SQL error is therefore insufficient. FULL/RESTART/TRUNCATE can also report busy and must not be logged as complete. TRUNCATE can legitimately return 0/0/0; PASSIVE/FULL completion does not imply WAL deletion. A real no-WAL (-1/-1) result must not masquerade as complete merely because the counters are equal.

MySQL and PostgreSQL intentionally perform a legal **no-op for this API** with an explicit unsupported-checkpoint error: there is no SQLite WAL operation to perform. Their transaction commit/durability policies remain owned by the engines. We do not issue SQLite PRAGMA, global MySQL FLUSH operations, engine checkpoints, or claim an application flush barrier. Existing transaction commits are not pending writes owned by ForceDBSync.

The old post-checkpoint `PRAGMA synchronous=FULL` was removed: changing a connection-local policy after the operation cannot retroactively strengthen previous commits, can affect an unrelated pooled connection, and was not a truthful durability/backup barrier.

## Flutter / Android consumer contract

Flutter lifecycle events currently reach Android `OpenListService` / `MainActivity`, then `model/openlist/OpenList.kt`, then the Go binding. There is no detailed Flutter checkpoint result API. The existing Kotlin `forceDatabaseSync(): Unit` wrapper catches and logs Go errors; callers must not interpret its return as either checkpoint success or a backup signal. Its documentation and success log now say **completion is flush/checkpoint only, not backup**, and restrict completion to the reported invocation. Go `Shutdown` also retains its existing error-handling behavior (it ignores the ForceDBSync error); shutdown completion is not checkpoint or backup verification.

Even a complete SQLite checkpoint is not a stable snapshot: concurrent/subsequent writes can immediately append more WAL. This API does not flush uncommitted application state, establish a write watermark, coordinate stores, fsync an exported artifact, or promise all data is merged forever. Never copy the main file alone on the strength of this result; do not independently copy DB and WAL and call that a consistent backup.

## Tests and validation

- `openlistlib/internal/checkpoint/checkpoint_test.go`: dependency-free database/sql connector/rows adapter covers busy, PASSIVE partial with busy=0, full/empty WAL, no-WAL, query error, row iteration error (including after a result), canceled/pre-canceled contexts, invalid scans/empty rows, mode allowlisting and unsupported engines without SQL.
- `openlistlib/internal/checkpoint/sqlite_test.go`: existing glebarez/GORM dependency creates a real file-backed WAL DB; pins a reader, observes deterministic PASSIVE partial counters, releases the reader and observes FULL completion, then checks DELETE-journal no-WAL behavior. No new module dependency.
- Local scope requested: gofmt and git diff whitespace checks only; no dependency downloads, backend/mobile builds, binding generation, commit or push. Go execution and the real SQLite fixture belong to cloud validation (`cd mobile/openlist-lib && go test ./openlistlib/internal/checkpoint`, then the existing mobile Go compilation/tests). The added tests are not claimed as executed locally.

## Explicit exclusions

No snapshot/online-backup/VACUUM INTO implementation, pre-migration backup, restore, retention, backup manifest, application write barrier, cross-store coordination, encrypt-cache changes, server DB policy tuning, generated binding changes, or new heavy dependency. The existing `mobile/openlist-lib/src` mirror is not imported by the active `openlistlib` implementation and is not changed. SQLite compatibility-driver coverage still needs the cloud build-tag matrix; the real fixture intentionally exercises the existing default mobile SQLite dependency.
