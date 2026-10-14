# P2 instance-owner first safety batch

Status: implemented prerequisite safety batch, **not complete P2/P3 acceptance**. No production configuration, network defaults, all-driver transport migration, or deployment changes.

## Implemented

- `openlistlib.Init` acquires a pointer-capability process lease **before** bootstrap configuration/logging/DB/hooks. A second Init cannot overwrite the current generation. Invalid-callback Init fails before bootstrap and releases only its own lease.
- `StartEmbedded() error` gives synchronous `embedded_instance_overlap`/not-initialized errors. Legacy mobile `Start()` ABI logs that rejection; it does not start another server. The fixed OpenList globals do not support simultaneous embedded servers.
- Manager Initialize/StartProxy no longer overwrite an unrelated global factory. Only the held embedded capability publishes cloned configuration snapshots. `DriverConfigurationPendingEpoch()` reports the newest snapshot for **new** clients; existing sessions need explicit storage reinitialization, not hot update.
- Trusted storage bootstrap supplies driver, storage database ID, embedded server generation and configuration epoch through typed context. Provider is optional/not inferred when bootstrap lacks an authoritative provider. No header, URL or mount guessing. MEGA consumes that bootstrap identity.
- Session parent is the generation context, not Init's three-second deadline. MEGA SDK owns its independent session context; generation cancellation closes its admission/I/O, explicit Drop joins SDK poller/operations before releasing client ownership.
- Owned factory clients stop admission on retirement. In-flight round trips and actual response bodies retain resources until failure/EOF/Close. Release while a body is active returns `embedded_instance_pending` and retains the lease; a second server cannot steal the factory.
- Shutdown cancels the generation, drains endpoints, joins actual storage-load calls, calls existing driver Drop methods, checkpoints DB, then attempts owner-only release. Endpoint-generation registry registers ownership before launching Serve, synchronously prepares non-HTTP sockets/readiness, seals start admission, and joins captured local Serve calls. HTTP drain timeout retains endpoints and owner for retry. Hooks capture generation subscribers and run outside counted Serve work to avoid callback self-join.
- Explicit `bootstrap.InitOwned/StartOwned/ShutdownOwned/ReleaseOwned` require capability; legacy bootstrap/CLI entrypoints reject ownerless calls while embedded lease is held, before config/DB/server effects. cmd server returns on rejection instead of waiting for signals. Bootstrap lifecycle serialization covers its entire startup body, not only endpoint Serve.
- After all endpoints/loaders/Drop/managed clients have joined, capability-fenced cleanup clears storage/readiness/balance maps and storage directory/details caches before global lease release. Generation B cannot route to generation A's old WORK mount. This does **not** prove arbitrary legacy driver Drop joins internal work.
- Storage-load admission now seals under its own mutex before join, so newly admitted loads cannot race WaitGroup Wait. Startup reopens admission only for a new owner generation after prior cleanup.
- Actual/src source overlays are synchronized using explicit `scripts/sync_source_overlay.py --apply`, after full-batch preflight. New upstream paths use null pristine fingerprints; bootstrap/run.go fingerprint was retrieved from the exact pinned v4.2.2 commit, not from patched src.

## Tests / validation boundary

Added `internal/net/instance_owner_test.go`: real loopback HTTP body, overlap rejection, outsider cleanup/overwrite rejection, body-delayed release, restart generation, independent Init/session cancellation, trusted storage/server/epoch and snapshots. Added `openlistlib/instance_owner_test.go`: invalid Init cleanup cannot release another owner; Start requires Init. Existing factory snapshot/header spoof tests remain applicable. Python overlay tests (8) and manual-sync tests (10) pass; mirror gate passes after synchronization.

The standard-library-only endpoint-generation suite passed local `-race -count=20` (actual HTTP loopback drain timeout/retry, immediate stop-before-Serve, admission seal, failed bind, blocked-stop retry ownership, gated non-HTTP readiness, and reentrant hooks). Full package/driver tests are supplied for cloud `test-mobile-go`; this batch does not claim those ran successfully locally or that a complete real embedded two-server bootstrap fixture passed. New bootstrap/cmd entry-fence, storage-load seal, and old-mount reset tests are also included for cloud compilation/execution. Local SDK test was blocked by the environment's read-only default Go cache, before compilation. A separate standalone ownership smoke attempt was blocked before compilation by the pinned Go 1.26.5 toolchain download cache being read-only (installed toolchain is 1.26.0); its temporary stub was removed. Neither denial was escalated or bypassed. No heavy local mobile build, no commit/push/dispatch. Parent must run compilation and focused new/old lifecycle tests in authorized cloud CI.

## Explicit deferred / unsupported

- Simultaneous embedded instances: rejected, not implemented.
- Full legacy Init/Drop/task/token-refresh/body/SDK join coverage, asynchronous storage mutation fencing and all-driver cancellation: P3. Non-cooperative Init/Drop can still block real joins; no abandoned goroutine or false bounded Stop guarantee.
- FTP/SFTP dependencies do not expose accepted-session join hooks. When those optional protocols are enabled, shutdown explicitly returns unsupported-drain and retains the generation/lease; Stop/restart is not supported for that case in this batch. No change to their default enablement. Their preparation/readiness lock itself is not deadline-cancellable.
- Full embedded server loopback Start/Stop, failed real driver Init, configuration reinit and per-operation driver fixture acceptance remains cloud/unverified. Endpoint listeners remain upstream asynchronous; StartEmbedded success means bootstrap submitted, not listener readiness.
- The existing immutable route pool retains native topology/request policy and defaults. This batch adds ownership/identity rather than redesigning all purpose budgets, immutable DNS/proxy decisions or aggregate storage task/pool budgets; those P2/P3 contracts remain outstanding.
- Endpoint drain failure is fail-closed: retry Shutdown, do not start another generation. Per-driver Drop errors and managed clients with live bodies likewise retain ownership until their actual cleanup completes.

## Process-global crypto budget

`shared/encryptcore/newv3_kdf_service.go` is **process-global**, at most min(GOMAXPROCS, 2) running derivations, 32 queued flights, 128 waiters. Canceling one waiting instance does not release a still-running PBKDF2 CPU slot or close the shared service. Neither embedded Shutdown nor proxy Stop closes this global KDF; doing so would break other root/mobile consumers. Process service teardown, if introduced, needs an independent whole-process owner.

Mathematical password/nonce/iteration key reuse is not storage authorization or object-version proof. Authentication-record/metadata namespaces retain existing conservative identity; this lease does not make them revision-safe or turn them into instance-local budgets. Instance cache namespace cleanup/aggregate record-memory acceptance is still a separate scoped follow-up, not claimed by the factory lease.
