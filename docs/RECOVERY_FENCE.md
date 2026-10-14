# P1 startup recovery fence (partial infrastructure)

This change is **not a restore tool** and does not install a live fence, acquire
service lifetime ownership, or authorize reconciliation/unfencing. Do not copy an
old database over a live service or manually delete a recovery marker to resume
writes. The offline restore/locking/journal protocol remains a separate delivery.

At startup root loads `<data_dir>/recovery-state.json` before constructing handlers.
The marker is independent of `alist-encrypt.db` so an old DB cannot overwrite it.
An absent marker permits legacy installations. Any present malformed, unreadable,
non-regular, unknown-version or unknown-stage marker fails closed for remote
mutations while reads and authenticated status remain available. This is an
immutable startup snapshot: changing the file after startup has no effect.

Version 1 accepts the following marker shape (only an illustrative fixture, not
instructions to install a live fence):

```json
{"version":1,"stage":"reconciliation-required","operation_id":"restore-1","generation":1,"bundle_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
```

Accepted stages `prepared`, `restoring`, `reconciliation-required` all fence writes.
There is no `reconciled`, `clear`, or force override. `generation` currently validates
marker structure only; it is not yet matched against a sticky database generation.
Future restore tooling must add that binding so deletion of a required sidecar
cannot be confused with a legacy store. The operator-owned data directory is a
trust boundary, not an adversarial filesystem sandbox.

Config holds a private non-JSON runtime state that ordinary managed updates cannot
clear. The Bolt Store independently holds the same startup state and checks it
inside the filename reservation transaction. Audit schemas and existing records
are unchanged. Cache/stat/config writes are not blanket-blocked.

Fenced API PUT/remove/rename/move/copy and DAV mutations return HTTP 503 with
`recovery_reconciliation_required` before DAO/probe/upstream I/O. This does not
depend on filename length, current encryption rule or configured write limits.
DAV GET/HEAD/PROPFIND/OPTIONS are unchanged. Catch-all proxy requests permit only
exact known filesystem read endpoint/method pairs; unknown endpoints are refused
even on GET because they can trigger upstream side effects. Dedicated local
management routes remain available; their JWT configuration is unchanged.

`GET /enc-api/admin/reconciliation-status` uses the existing management JWT
middleware. It exposes only required/stage/reason, never paths, original names,
reservation tokens or credentials. This is status, not a reconciliation report.

The fence does not stop external writers, independent OpenList administrative
jobs, direct provider writes or another store. P8 must implement audited unknown/
tombstone/reconcile transitions and prove range completeness, including remote
objects created after the restored snapshot. Missing local records, a cached 404,
a listing gap or matching size cannot silently release reservations or this fence.
No remote CAS/strict HA or cross-store atomicity is claimed.
