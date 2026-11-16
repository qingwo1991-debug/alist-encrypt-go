# Custom safety integration

## Status

Selected filename retry and structured-upload-error changes are integrated on top
of the existing PR102, PR104 and PR105 changes. Cloud/local-claim release through
`POST /enc-api/retryFilename` is **disabled**, including when
`ALIST_FILENAME_RETRY_MAINTENANCE_ENABLE=1`. No automatic retry is authorized.

- The management-JWT-protected endpoint and separate explicit DAV Basic
  credentials are retained. `dry_run` only reads the local audit digest/status.
- Without the exact opt-in value `1`, a release request returns HTTP 503 with
  `maintenance_release_disabled` and `retryable:false`.
- With opt-in, otherwise eligible requests may perform caller-scoped read probes,
  but still return HTTP 503 with `physical_parent_proof_unavailable` and
  `retryable:false` after successful probes. Earlier invalid, conflicting or
  unavailable probes retain their explicit errors. The handler never invokes
  local reservation release and never uploads or deletes a cloud object.
- Failed reservations remain claimed. Storage-level compare-and-swap release and
  immutable audit transactions remain separately unit-tested, not exposed as an
  enabled cloud retry capability.

## Security boundary

A valid Basic login does not prove that API or DAV paths address the reserved
physical namespace: account `base_path` can rewrite both. A successful `fs/list`
response with matching total/content lengths is also not authoritative physical
inventory: filtering, deduplication and virtual navigation after driver failure
can conceal objects. Even a full-looking empty parent and two child DAV 404s
cannot authorize release. Task lists do not prove cross-instance quiescence.

An authoritative bridge proving the exact physical parent, complete fresh driver
inventory, target absence and writer safety is required before reconsidering
release. There is no test-only production bypass or administrator-list shortcut.
Normal-upload API inventory parsing is additionally hardened against invalid or
duplicate basenames while retaining successful `content:null,total:0` handling;
this validation does not turn the API listing into physical release proof.

## Selected paths

- `internal/handler/filename_retry.go` and `_test.go`
- `internal/storage/filename_retry.go` and `_test.go`
- `internal/server/filename_retry_auth_test.go`
- Selected release wrapper in `internal/dao/filename_records.go`
- Structured errors and inventory validation in
  `internal/handler/filename_write.go` and focused `_test.go` cases
- Upload error handling in `internal/handler/alist.go` and `webdav.go`
- Protected POST registration in `internal/server/server.go`

Offline/lost-complete/maintenance-command changes are not imported. Local
validation is limited to formatting and diff checks; the parent owns commits,
push and the full cloud test matrix. No real cloud probes, service restarts or
remote deletion are part of this integration.
