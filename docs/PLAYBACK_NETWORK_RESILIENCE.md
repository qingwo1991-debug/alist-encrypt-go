# Playback and mobile network resilience acceptance

This follow-up targets playback correctness and bounded waiting, not security.
A passing CI suite is not a measured Android first-frame or VPN compatibility result.

## Changes and required automated evidence

- Non-Range V3 fallback preserves exact GET, seek and suffix plaintext.
- Metadata redirects/header/trailer reads share a total probe budget; header-only
  success cannot leave prefix inspection blocked indefinitely.
- Retry-backoff cancellation does not count as a provider failure; exhausted
  upstream status errors preserve their status and classification.
- Signed-URL proactive refresh is nonblocking, deduplicated, capacity bounded,
  and cancelled on handler shutdown.
- Next-episode preparation begins after the first successful body write, before
  EOF. Background scheduler provider isolation must prevent one offline provider
  from occupying every worker.
- FirstByteLatencyMs is request entry to successful body write. HeaderLatencyMs
  remains a stream-preparation metric, not player-rendered first-frame latency.
- V3 record buffers have a process-local 256 MiB aggregate playback budget.
  Capacity exhaustion is a terminal 503, never a retry into another strategy.
- Root/mobile stream body idle protection applies only during blocked upstream
  reads (30 seconds), not player pauses, slow downstream writes or total duration.
- Mobile initialization does not impose a global repeated 1.5-second wait on ready
  domestic mounts. Individual pending/failed mounts return an explicit error.
- Google Drive/OneDrive requests consume their context; shared-listing waiters
  can cancel without forgetting or duplicating the leader.
- Mobile initial construction and config updates preserve the same 7-second
  stream response-header cap and rebuild the dialer.
- Mobile network changes invalidate idle connections and stale routing hints;
  unsupported raw socket binding falls back to the system-selected route.
- Flutter downloading performs each offset seek/write atomically, bounds active
  tasks and cancels sibling ranges after the first failure. Header/body stalls
  may move to another source without cancelling the user's entire task.
- Upstream src overlays survive init_openlist.sh re-cloning and are tested in
  both the embedded module and source copy.

## Explicit compatibility and residual limits

- Existing V1/V2 behavior and root V3 container layout/default 16 MiB chunk are
  preserved. An uncached V3 block must still be fully downloaded/authenticated
  before plaintext is available. Future smaller-block profiles require separate
  measured design; this work does not promise low weak-network V3 latency.
- Mobile's independent encryption engine supports V1/V2. V3 is explicitly
  identified and rejected with HTTP 415 instead of returning legacy-decoded
  garbage. Native mobile V3 support remains separate work.
- Android opaque network handles are not treated as raw SO_MARK values. Reliable
  explicit network selection requires a supported Network.bindSocket bridge and
  real-device testing; current default is honest system routing.
- HTTP proxy bypass is NOT a TUN/VPN bypass. A broken system VPN can still affect
  domestic providers. Embedded backend provider APIs may use a global proxy.
- MEGA's dependency does not expose a confirmed request-context cancellation
  contract. Pending initialization no longer delays other mounts, and cancelled
  work must not publish success; underlying login may finish later.
- Stable-identity cache assumptions remain: replacing content in place requires
  invalidation. Do not remove URL identity safeguards to fake higher cache hit rates.
- CI does not measure decoding/rendering, battery, network-switch recovery or
  empirical first-frame/seek percentiles. These require the matrix below.

## Real-device matrix before near-100 playback claims

Test V1/V2 and root V3 separately, cold/hot cache, Range accepted/refused, and
front/tail seeks. Record request first-byte and player first-rendered-frame separately.
Use normal network plus 1/2/5 MiB/s, 100/300 ms RTT, loss, header blackhole and
body blackhole; test ten rapid episode switches and user cancellation. Mix one
reachable domestic mount with an unreachable overseas mount. Repeat before/after
saving config and Wi-Fi/cellular switch, with VPN off, healthy VPN and broken TUN.
Report p50/p95, wrong-byte/truncation count, pending request count after cancel,
peak RSS, downloaded amplification, and whether healthy domestic requests remain
independent. No latency threshold can override plaintext correctness.
