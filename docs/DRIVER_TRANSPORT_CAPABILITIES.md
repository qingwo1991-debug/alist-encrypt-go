# Fixed OpenList driver transport inventory — P3 preparation

## Boundary: not P2, not all-green

This is **static inventory preparation**, not a runtime transport change, cancellation proof, P2 prerequisite replacement, or approval to enable every driver. Every entry remains `unsupported-needs-review` for the proposed end-to-end transport/cancellation contract, including statically reviewed entries. This does **not** mean ordinary OpenList driver operations are disabled or unsupported upstream. No credentialed tests, heavy Go builds, installs, commits, pushes or cloud validation were performed here. Parent review/cloud gates remain separate.

The fixed source baseline is OpenList **v4.2.2**, upstream commit **b28208bd76ee19c49dabc7f68c1f4e863f571fc6**, from `mobile/openlist-lib/UPSTREAM_VERSION` and `scripts/source_overlay_manifest.json`. Actual build code is `mobile/openlist-lib/drivers`, not pristine upstream and not only `src`. `scripts/init_openlist.sh:28-30,54-83,91-111,117-136` verifies/reapplies a narrow reviewed source overlay, separately applies module overlays, copies `src` into actual packages and restores compatibility patches. The two trees are fingerprinted **independently**; equal hashes are not assumed. The existing overlay gate must still run; this inventory does not replace it.

## Actual registration, not directory guessing

* `drivers/all.go:3-85` blank-imports **81 packages**.
* Their `meta.go` literal constructors call `op.RegisterDriver` **88 times**, with 88 distinct config names. The count includes variants, not just package folders.
* **83 directories** exist; `base` is transport/helper infrastructure, `template` is not imported/registered. Neither is a live registered driver.
* `internal/op/driver.go:18-24,46-58` constructs a driver, reads `Config().Name`, and populates the driver/config maps. `internal/driver/driver.go:16-38,79-104` defines Init/Drop/List/Link and optional Put. There is **no universal driver Read or Refresh method**. Read here means consumption of a Link URL/reader/range-reader; Refresh means auth/session refresh, retry or scheduled work, where present.
* These are source-derived fixed-registry counts, **not an executed runtime `GetDriverNames()` probe**, platform compile result, or dynamic registry proof. The parser deliberately fails closed if this registry ceases to use the reviewed literal shape. Names and evidence are retained per package in JSON.

## Machine-readable contract

`docs/driver_transport_inventory.json` is the authoritative single inventory. It contains static source metadata only: package/config names, SHA-256 fingerprints, review state, transport ownership/kinds, and per-operation `context_hooks`, `transport_ownership`, `unsupported_reason`, `reason`, `evidence`, `assessment`. No endpoint configuration, tokens, credentials, account data or live response payloads are collected.

* `reviewed-static`: an actual call-path review, **not** runtime cancellation verified.
* `unchecked`: the operation has not been traced; empty hooks mean **unknown**, not proof of absence.
* `context_hooks`: concrete boundary observations (e.g. request binding, SDK context, limiter-only context). A context parameter, context-aware stream, limiter wait, callback or SDK constructor alone is not full HTTP cancellation proof.
* `transport_ownership` distinguishes shared/base/global Resty, private HTTP clients/SDKs, mixed paths, and non-HTTP protocols. Do not globally replace shared clients to claim per-storage ownership.
* `Read` separately records who actually consumes returned bytes; Link metadata success says nothing about downstream URL requests, body lifetime, ranges or decrypt/proxy paths.
* `Drop` records real cleanup, not a synthetic success bit. Closing idle HTTP connections does not abort active response bodies. Stopping a cron does not necessarily cancel or join its active callback. SDK logout is not automatically a bounded joined shutdown.
* `cancel_proof` is always **false**; `support_status` is always **unsupported-needs-review**. Promotion requires implementation, operation-specific failure/cancellation/race/lifecycle tests and separate review, not editing these labels.

Coverage: **22/81 packages statically reviewed (23/88 registered names)**; **59/81 packages unchecked (65/88 names)**. **0/88 names are promoted to end-to-end supported or cancellation-proven.** Every one of the 81 packages has all seven operation records. The focused reviews cover Wopan, GoogleDrive, all three OneDrive variants, all three Aliyun variants, 189/TV/PC, 123/base/open/link/share, WebDAV, S3/Doge, Azure, SFTP, FTP, SMB and MEGA. The remaining packages stay explicitly unchecked rather than being classified by `source contains context` heuristics.

## Coverage / next fixed batches

The detailed per-operation matrix and file:line evidence are in JSON. This summary is a queue, **not a green checklist**:

| Fixed batch | Packages / registrations | Current static boundary | Next work (not implemented here) |
| --- | --- | --- | --- |
| HTTP context partial baseline | google_drive, onedrive | Bound List and refresh exist on shared/base clients; per-session ownership is not established; Link metadata and upload auxiliary paths have gaps | Bind all auth/metadata/chunk requests; cancellation during retries and active bodies; Drop/re-init isolation |
| Wopan SDK | wopan | Driver SDK wrapper injects shared base HTTP client; external SDK propagation must not be inferred from wrapper signature | Review fixed SDK internals and inject/own transport with operation and shutdown tests |
| OneDrive variants | onedrive_app, onedrive_sharelink | Mixed private/base/default paths; detached auth/pagination/scheduled work | Separate variant-specific transport injection; bounded refresh/drop; password and GraphQL paths |
| Aliyun variants | aliyundrive, aliyundrive_open, aliyundrive_share | Shared Resty paths; limiter context is not request context | Bound refresh/API/upload metadata and data; avoid global Resty mutation; SDK upload ownership |
| 189 variants | 189, 189_tv, 189pc | Mixed request-bound main calls and detached refresh/retries; cron stop is not callback cancellation | Session-owned refresh and shutdown; family-transfer cleanup and polling; bound all metadata |
| 123 variants | 123, 123_open, 123_link, 123_share | Mixed context requests, helpers, URL-only links and refresh | Trace/initiate/commit upload and retry/auth chains; separate URL Read ownership |
| HTTP protocol/SDK | webdav, s3 (S3/Doge), azure_blob | SDK/client boundaries differ; request context alone does not establish routed ownership | Fixed SDK transport injection and active range/upload cancellation; WebDAV auth helpers |
| Non-HTTP and mixed | sftp, ftp, smb | SSH/SFTP, FTP control/data, SMB TCP sessions are **not HTTP RoundTrippers** | Protocol-specific context/deadline/close/join adapters; do not claim HTTP hooks cover these |
| MEGA fixed fork | mega | Local SDK fork and actual reader/session hooks already partially integrated | Preserve fixed fork/version and prove all operations, active body and session shutdown; no blanket green |
| Remaining unchecked | All other imported packages | Explicit unknown/unsupported-needs-review operation rows | Review in bounded family batches below; no automatic support inference |

Suggested next conservative unchecked batches:

1. Local/delegating/transform/index: `local`, `virtual`, `alias`, `crypt`, `chunk`, `strm`, `url_tree`, `autoindex`, `123_link` downstream consumers. Establish delegation and non-HTTP boundaries before applying HTTP assumptions.
2. SDK and object/storage families: `115*`, `mopan`, `weiyun`, `proton_drive`, `ipfs_api`, `uss`, `halalcloud*`; inspect **pinned SDK** APIs, client ownership and background activity.
3. API/refresh families: `quark*`, `139`, `baidu*`, `pikpak*`, `thunder*`, `dropbox`, `yandex_disk`, `teambition`, `terabox`; trace all refresh/retry/upload auxiliary paths.
4. Web/share/index services: remaining `openlist*`, `alist_v3`, `cloudreve*`, `github*`, `cnb_releases`, `doubao*`, `lanzou`, `ilanzou`, `lenovonas_share`, `mediafire`, `mediatrack`, `misskey`, `netease_music`, `google_photo`, `seafile`, `teldrive`, `kodbox`, `febbox`, `degoo`, `chaoxing`, `wps` and any leftover JSON entries. Inventory membership, not this illustrative list, is authoritative.

## Cheap offline drift gate

From repository root (Python standard library only):

```sh
python3 tools/check_driver_inventory.py
python3 tools/test_driver_inventory.py
python3 mobile/openlist-lib/scripts/test_source_overlay.py
python3 mobile/openlist-lib/scripts/verify_source_overlay.py --check-mirrors
git diff --check
```

The inventory gate fails on newly imported/removed drivers, new/removed directories, literal registration/config-name changes, actual or `src` source/file-set changes, version/module/source-overlay changes, shared transport/model/helper changes, or local MEGA SDK changes. Source hashes include tests and nested driver helpers, because changes there may invalidate evidence. Supporting hashes intentionally over-invalidate rather than silently keeping old reviews. Existing `src`/actual differences are recorded, **not repaired**.

Tests inject added/removed drivers, source/src drift, version/module/SDK/overlay drift, missing operation records, false green promotion and unsupported registry shapes. They do not compile or import the mobile Go dependency graph.

For a deliberate update, inspect the changed actual and mirrored sources plus pinned dependencies, retrace affected operation boundaries, update reasons/evidence and fingerprints together in review, and rerun gates. `python3 tools/check_driver_inventory.py --draft` prints an **unchecked scaffold to stdout**, never refreshes/approves an existing inventory in place. Do not overwrite reviewed data with a scaffold or mechanically copy new hashes to silence drift. Hash freshness is only a review reminder, not authenticity or correctness proof. `tools/assemble_driver_inventory.py --output NEW_FILE REVIEW_SHARD.json ...` is a dependency-free preparation helper for explicitly reviewed shards; it refuses to overwrite existing files. It does not approve source changes or update an existing reviewed inventory automatically.
