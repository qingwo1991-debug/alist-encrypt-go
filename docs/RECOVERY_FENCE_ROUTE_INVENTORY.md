# Root recovery-fence route inventory

This inventory follows `internal/server/server.go:registerRoutes`, not schema-only
checks. `internal/server/recovery_routes_test.go` invokes the actual registration
with real handler instances and a recording HTTP upstream.

| Registered entry | Fence location | Fixture |
| --- | --- | --- |
| PUT `/api/fs/put` | start of HandleFsPut, before passwd lookup and unencrypted direct proxy | raw short path, no encryption DAO; limits configured and removed |
| POST `/api/fs/remove` | start of HandleFsRemove | refused before body/DAO/upstream |
| POST `/api/fs/rename` | start of HandleFsRename | refused before body/DAO/upstream |
| POST `/api/fs/move`, `/copy` | start of shared handleCopyOrMove | both refused |
| Any `/dav`, `/dav/*path` plus explicit DAV methods | start of WebDAVHandler.Handle | PUT, DELETE, MKCOL, MOVE, COPY, PROPPATCH, LOCK, UNLOCK refused |
| NoRoute `/api/fs/form`, `/batch_rename`, `/other` | first guard in HandleProxy | multipart/batch/unknown shapes refused without parsing body |
| NoRoute upstream admin/task/unknown | first guard in HandleProxy | POST admin/storage/update, GET offline_download/add, PATCH/GET unknown refused |
| NoRoute known fs read `/api/fs/dirs` POST | precise read allowlist | upstream 204 preserved |
| GET `/enc-api/admin/reconciliation-status` | existing management JWT group | unauthenticated 401, authenticated 200 with required flag and no path |

All mutation fixtures assert 503/recovery_reconciliation_required and zero
recorded upstream requests. Missing DAO dependencies also ensure an accidental
pre-guard lookup cannot silently pass. Separate tests cover managed config update
removing write limits/rules and the Store's transaction-level reservation denial.

## Explicit read routes do not pass through the catch-all guard

GET/HEAD `/d/*path` and `/p/*path` register directly to HandleDownload. Its no-rule
branch calls StreamProxy.ProxyRequest, **not** HandleProxy. GET/HEAD DAV dispatches
handleGet; PROPFIND dispatches handlePropfind. Registered POST fs/get, fs/link,
fs/list and fs/search dispatch their own read handlers. These paths do not call
guardProtectedProxyMutation. Playback stream/range implementation is unchanged.
Thus rejecting unknown GET endpoints in NoRoute does not reject the registered
`/d` or `/p` media routes. Existing playback and DAV byte tests remain necessary
CI regression coverage; this batch does not claim to have re-run them locally.

The catch-all does deliberately reject unreviewed static/front-end GET paths
while fenced, rather than treating all GET as side-effect free. Dedicated local
management routes retain their existing authentication and behavior. This is a
remote object-write fence, not an OS filesystem write sandbox: explicitly
JWT-authorized local encrypt/config/stat management remains separate.

## Recovery-component boundaries

A malformed sidecar still fences Store reservations independently of managed
configuration. This change does not verify a restore package or configuration
component. Root `alist-encrypt.db` contains the Bolt config bucket, but runtime
`conf/config.json` (or configPath) is separate and cannot be silently omitted from
a later recovery package. Future offline tooling must bind a sticky DB generation
to the sidecar, require exclusive service ownership, validate included/external
configuration, and keep unknown remote objects fenced. None of those are supplied
by this startup-only PR.
