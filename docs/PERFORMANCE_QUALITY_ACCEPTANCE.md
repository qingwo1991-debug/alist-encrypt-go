# Performance and quality acceptance

This work targets correctness, bounded resource use, regression protection and
maintainability. A subjective score is not an acceptance test, and successful CI
is not proof of production throughput or an absence of defects.

## Compatibility constraints

- Preserve V1/V2 reads and the existing V3 container format and default chunk size.
- Persist V3 chunk size and KDF iteration count throughout path caches, BoltDB,
  MySQL metadata and playback. Incomplete legacy V3 cache entries must be probed
  again rather than interpreted with current defaults.
- Once HTTP response headers are committed, do not retry into the same response
  or append an error document. Record the failed/incomplete transfer separately.
- Keep the original worktree improvements in a separate baseline commit.

## Resource-use acceptance

- V3 sequential readers reuse a per-reader record buffer; avoid fresh whole-chunk
  plaintext and ciphertext allocations for every record.
- V3 writer buffer reuse must preserve zero padding, error semantics and byte
  counts. Random-access reuse must remain safe for concurrent ReaderAt calls.
- Decrypted cache hits assemble immutable block snapshots outside the global
  cache lock, without exposing caller-mutable stored data.
- Playback hints and scheduler active state must have explicit capacity/expiry
  limits. Lifetime operation counters remain cumulative; active unique-file
  counts describe only the retained state, not an all-time distinct-file count.
- Statistics must not hold scheduler record locks during DAO reads or sorting.
- Frontend polling and configuration saving must respect disposal and avoid
  overlapping operations. Warm-detail tables must bound rendered row counts.

## Cloud-first validation

Use an `agent/*` branch and a Draft PR against `main`. Do not invoke the release
workflow manually merely for validation. The PR matrix runs Go, shared-core,
mobile Go, both Web UIs, Flutter analysis/tests and the container build.

The concurrency/performance job additionally runs the selected Go data-path
packages with the race detector and publishes network-free benchmark output
with Go version and CPU information as the `performance-baselines` artifact.
Benchmark throughput on shared GitHub runners is observational, not a stable
pass/fail threshold. Compare allocations and repeated samples; validate latency,
RSS, throughput and concurrency on a fixed deployment device before making
capacity claims.

AAR/APK production packaging is not executed by the existing PR workflow; a
passing PR must not be described as having verified those native release builds.

## Suggested fixed-device workload matrix

Measure cold and hot key setup separately. Test V3 sequential playback, small
within-chunk reads, crossing chunk boundaries and repeated seeks, with 1, 4, 16
and 32 concurrent readers where the device supports them. Include upstream
truncation after response headers, slow upstream responses, client cancellation,
expired direct URLs, cache replacement and non-default V3 parameters.

For long-running scale tests, rotate signed URLs and repeatedly discover large
directories. Track active-state size, heap/RSS, GC CPU, statistics response size,
DAO work, p50/p95 time-to-first-byte and completed/failed playback counters.
Check hidden-page polling, slow-response navigation and repeated save clicks.

## Remaining architectural work

Platform network binding and lifecycle logic should stay platform-specific.
Shared pure encryption, metadata and cache contracts can be extracted in small
steps with cross-implementation compatibility tests; do not replace entire
mobile proxy implementations in a single unmeasured rewrite.
