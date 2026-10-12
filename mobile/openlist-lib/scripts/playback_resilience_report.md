# Mobile storage playback resilience

## Implemented

- Startup registers pending mounts before asynchronous initialization. Storage readiness is tracked separately per mount. Ready storage and virtual ancestors do not wait for unrelated startup work.
- Removed the repeated global 1.5-second HTTP middleware gate. Pending/failed mounts return `StorageNotInit`; filesystem listing does not turn readiness/cancellation errors into virtual-only successful lists. Virtual root remains browsable.
- Initialization checks its context before and after calling the driver, records panic as failure, and sets final status before publishing. A driver returning success after deadline cannot publish `WORK`.
- `singleflight.DoContext` makes duplicate waiters cancellation-aware without starting extra wrapper goroutines, forgetting active keys, or cancelling the leader. List, Link and storage-detail calls use it. Shared work is leader-owned; leader cancellation can still terminate all shared results by design.
- Management detail aggregation uses one absolute 3-second deadline derived from `Request.Context()`, passed through to detail retrieval. Reload Drop uses the same initialization budget.
- Google Drive and OneDrive refresh/list requests propagate contexts through actual HTTP requests, pagination, reference/shortcut requests and bounded auth recovery. Removed sticky Google initialization context from the non-source copy.
- `init_openlist.sh` preserves a narrow manifest of reviewed backend files and offline tests, restores them to newly cloned `src` before copying packages, retaining source/build equality on reinitialization. Existing mobile CreateStorage diagnostics are retained in both trees.

## Honest limits

MEGA's go-mega dependency source/cache and configurable transport cancellation hooks were unavailable. Login remains synchronous with pre/post cancellation checks and a local candidate not assigned after cancellation. This prevents late driver publication but does **not** prove in-flight HTTP cancellation or cleanup of dependency-owned login/event activity; a non-cooperative Init can exceed 3 seconds. No goroutine-plus-select fake timeout was introduced. Requests no longer depend on global initialization completing.

## Validation

Added offline httptest cancellation coverage for Google/OneDrive (refresh, list, shortcuts/pagination/reference/auth recovery), pre-cancelled MEGA tests, fake late-success Init/readiness tests, and singleflight cancelled duplicate/shared-work tests.

Formatting, scoped `git diff --check`, source/build equality checks and `bash -n scripts/init_openlist.sh` are the local gates. Focused Go tests were attempted with `GOPROXY=off GOTOOLCHAIN=local -mod=readonly`; setup was blocked by the sandbox's read-only `/root/.cache/go-build`. No cache relocation, escalation, build retries, heavy build, commit, push or branch switch occurred. Compilation/execution must be confirmed by CI; tests are not claimed to pass locally.

The sync manifest is a whole-file compatibility overlay, intentionally scoped but requiring review on future upstream upgrades. Re-cloning upstream is not itself a test of compatibility.
