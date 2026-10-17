# P4 async download files validation and protection boundary

## Runtime changes

- `download_file_owner.dart`: one application-isolate owner serializes the entire async exists/name/reserve/create command. Reservations survive notification/callback work and transfer queue waiting. Both actual background/notification downloads and progress-callback downloads use this owner. Existing positional writer is unchanged.
- Native disk calls are async, enumeration emits immutable metadata batches of at most 32, yields between batches, and skips individual missing/permission-denied entries. The page cancels superseded scans, ignores stale completions, renders lazy list rows, and reads info asynchronously with duplicate-click protection.
- Cleanup and delete skip reserved paths, including callback downloads absent from task records. No recursive directory deletion. Unsuccessful transfers discard their placeholder/partial file only after the transfer pipeline has joined workers and closed handles. Active task records cannot be removed ahead of their lifecycle owner.
- Creation/scan/cleanup errors are surfaced through existing failure states. No proactive free-space API exists here; ENOSPC/write failures follow failure+joined-discard paths. Directory changes affect future leases only; current leases retain their absolute normalized path.

## Atomicity domain (not HA / not O_EXCL)

This is **single application isolate/process cooperating-owner** exclusion, not a cross-process filesystem lock. Dart `File.create()` is not OS exclusive create. No native exclusive-create API was added. External processes, other isolates, symlink/path-alias manipulation, and external writes can race selection/creation or overwrite an active target; there is **no external overwrite guarantee**. Async IO makes native waits nonblocking but does not imply physical write atomicity. Successfully completed downloads remain ordinary visible files. Cross-process safety would require a real native exclusive create plus lifetime coordination (outside P4 scope).

Cleanup skips active leases rather than cancelling them: 'clear' can succeed while protected active files remain. Cancelled queued admissions are checked before disk creation and after async exists/create; cancellation cannot interrupt an already-running native filesystem operation, but the resulting placeholder is discarded before admission returns. Cleanup never initiates cancellation of writers.

## Regression matrix

- `download_file_owner_test.dart`: 17 gated FS/real-temp tests, exists/list event-loop progress, concurrent same-name reservation, cancel at exists/create, creation permission errors, active/callback cleanup protection, discard after join, missing/permission per-entry handling, immutable bounded batches, scan cancellation, naming.
- `download_manager_page_async_test.dart`: 5 widget tests, gated UI/lazy 10k directory rows, refresh/dispose cancellation, scan recovery, file-info disappearance, permissions, repeated clicks and late results.
- `download_network_resilience_test.dart`: production background + callback concurrent same-name downloads and production delete/clear while both are active; previous exact four-stream interleaving **10 MiB + 7 bytes** test retained. Reservation regression updated for async create semantics.
- `download_async_io_contract.test.mjs`: dependency-free scoped source checker (manager, owner, page, notification, positional writer); explicit exception registry currently empty. No broad generated/config ban. Also checks production owner wiring. Included in existing cloud Flutter job.

## Local evidence / required cloud evidence

Passed `git diff --check` and `node --test mobile/test/download_async_io_contract.test.mjs mobile/test/native_network_bridge_contract.test.mjs` (9/9). These static contracts do **not** prove Flutter execution.

Dart and Flutter were unavailable locally; formatting, Dart analyzer and Flutter tests **not run**. No heavyweight SDK/dependency download, commit or push performed. Parent reviewer must run the full existing PR cloud matrix, especially cached Flutter `flutter pub get --enforce-lockfile`, `flutter analyze --no-pub --no-fatal-infos`, `flutter test --no-pub`, and run `dart format` on changed/new Dart files with an available SDK. New Flutter tests are unexecuted until that succeeds. No external-writer/device/cross-process tests claimed.
