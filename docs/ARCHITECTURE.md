# Architecture

Encrypted Alist/OpenList compatibility proxy. Clients see plaintext
filenames; upstream stores ciphertext (`.bin` names, `orig_` fallback for
undecodable names). Go backend, gin HTTP server, Bolt/MySQL metadata.

This document captures the design decisions that are not obvious from the
code. Point-in-time reports and acceptance records live in `docs/archive/`.

## Request topology

```
client ──► proxy :5344 ──► OpenList :5244
              │
              ├─ /api/fs/*    Alist-compatible JSON API (alist_*.go)
              ├─ /dav/*       WebDAV (webdav*.go)
              ├─ /enc-api/*   management API (JWT)
              ├─ /redirect/*  signed-URL 302 playback
              ├─ /debug/*     troubleshooting (debug.enabled gate)
              └─ /metrics     Prometheus text (same gate + optional token)
```

## Name resolution — the single most important invariant

Display names and upstream names differ. Every mutating entry point
(`fs/remove`, `fs/move`, `fs/copy`, `fs/rename`, WebDAV `DELETE`/`MOVE`/`COPY`)
resolves display→upstream through **one** chain in
`internal/handler/name_resolver.go`:

1. `GetEncPath` cache mapping → cached `FileInfo` (dir keeps spelling,
   file uses `EncryptedPath`)
2. already-encrypted name (decrypts) → passthrough
3. `orig_` prefix → strip, literal (never `path.Join`-cleaned: `.`/`..`
   must reach mutation-name validation)
4. upstream existence probe (`fs/get` on the **display** spelling) →
   plaintext files/dirs keep their spelling; only absent names are
   filename-encrypted via `ToRealName`

Directory display names are **never** filename-encrypted. Read paths
(GET/PROPFIND) intentionally do **not** probe — they use
`resolveEncryptedRealPath` (cache + deterministic derive) to stay fast;
mutations probe because correctness beats latency there.

Batch mutations (`fs/remove`/`move`/`copy` with N names) substitute one
upstream directory `fs/list` for N `fs/get` probes and warm the
display↔upstream mapping cache from the same payload
(`fetchDirObjectSet`/`warmDirNameCache`).

## Caching and auth scoping

- `fileDAO` path cache maps displayPath ↔ upstream path + FileInfo.
  Mutations invalidate the **subtree** (`InvalidateDisplaySubtree`), not
  just the exact key — a deleted/moved directory takes descendants with it.
- `fs/list` snapshots (`dirsync`) are keyed by `path + authScopeHash +
  provider host`. A snapshot is only served to the same credential scope;
  cross-session reuse requires `request_fill` source mode (background
  `scan` snapshots may carry a privileged scan account and are never
  served publicly).
- Raw playback URLs are auth-scope keyed; legacy empty-scope entries are
  cold under the `standard` profile.

## Playback profiles

- `standard` (default): per-request upstream authorization, conservative
  cache identity checks.
- `trusted_local`: trusted-local optimization — confirmed-playback
  geometry required for length reuse; explicit opt-in only.

## dirsync (directory snapshots)

- `request_fill` snapshots: TTL tiered (elevated for hot/recent dirs),
  refreshed async off the response path.
- Background `scan`: longer TTL.
- Failure handling: scan failures back off exponentially (30m→12h cap)
  per path — permanently broken mounts (`/local_stroge` etc.) stop
  consuming upstream calls every cycle; success clears the backoff.
- Recent-directory LRU (64 entries, fed by both `fs/list` and WebDAV
  PROPFIND) prewarms snapshots before expiry; request-refresh failures
  get their own backoff. All background work is bounded (semaphores,
  singleflight) and never blocks foreground requests.

## Encryption generations

V1/V2/V3 ciphertext formats coexist (`shared/encryptcore`); V3 uses chunked
AEAD. `ConvertShowName*` decrypts display names; undecodable names surface
as `orig_<upstream>` rather than failing. Playback Range capability,
signed-URL refresh, and first-frame probes live in
`internal/handler/playback_*.go`.

## Mutation guards

`guardProtectedMutation`/`guardProtectedRename`/`guardProtectedBatchMutation`
conservatively reject ambiguous mutations (501/400) rather than risk
operating on the wrong object. Safe ops like `mkdir` pass through with
syntax validation only.

## Observability

- Structured logs (zerolog) + `trace` package per-request fields.
- `GET /metrics` (debug gate): `alist_fs_list_total{result}`,
  `alist_fs_list_duration_seconds`, `alist_upstream_requests_total`,
  `alist_dirsync_snapshot_refresh_total`, probe queue gauges,
  scan-backoff dir count.
- `/debug/status`, `/debug/logs` share the same gate.
- Playback/delete stats persist in Bolt (`stats` bucket); optional
  `stats_password` enables `/api/encrypt/exportStats`.

## Docs map

- `docs/` — evergreen references (encryption chain, DB export, protected
  mutation capabilities, tuning profiles, WebDAV/playback design notes).
- `docs/archive/` — dated acceptance/verification/handoff reports and
  retired root-level analyses. Historical record only; do not treat as
  current behavior.
- `AGENTS.md` — repository workflow rules (agent branches, Draft PRs,
  cloud-heavy CI).
