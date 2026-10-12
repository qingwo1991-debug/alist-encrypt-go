# Standalone playback frame probe (stage 1)

Independent HTML + native ES modules; no bundle, package installation, production changes, or external URL discovery. The existing external-player/WebView path does not contain an instrumentable built-in `<video>`, so this tool measures only its own video element, not that production path.

## Run manually (do not use file://)

From the repository root, start your own local static server:

```sh
python3 -m http.server 8765 --bind 127.0.0.1 --directory tools/playback-probe
```

Open `http://127.0.0.1:8765/` in a browser. This command is documentation only: no server is started by tests/tool code. Stop with Ctrl+C. The page works without a bundler or a project build.

1. Enter an HTTP(S) media URL you are authorized to play. Nothing plays/fetches until **Open + play**. Normal playback can cause multiple browser range/segment requests; the probe does not issue separate `fetch` requests or discover random URLs.
2. Choose the cache label for this individual operation: **cold**, **warm**, or **consecutive**. These labels are user-controlled annotations, not assertions about actual cache state. For cold runs, independently clear/disable relevant caches; for warm runs, reopen the same media; for consecutive runs, manually repeat your desired operation. There is no automatic repeat loop or cache purge.
3. Open records one first-frame sample. Seek enters a different finite target in seconds and records one seek sample; each click attempts exactly one sample. Wait for completion before another operation. Native video controls are for inspection, not measurement triggers; do not seek with them while a measurement is pending.
4. Download JSON to keep samples and condition-separated summaries. Stop/page exit invalidates the operation generation and cancels its registered frame callback. New opens/seeks cancel unfinished samples.

## Exact metrics and JSON contract

The JSON has `schema_version: 1`, `metricSemantics`, a whitelisted `environment`, `samples`, and `summary`. The module exports the exact semantics with every report.

- `firstRenderedFrameMs`: `metadata.presentationTime - performance.now()` captured immediately before assigning the source/loading/playing. The previous resource is paused/cleared/loaded before measuring a new source. Only a current-operation `requestVideoFrameCallback` with a finite, nonnegative presentation delta and new `presentedFrames` is successful, after `loadedmetadata` confirms `currentSrc` equals the requested URL. Metadata is a source-readiness guard, never a rendered-frame metric; mismatching sources time out instead of fabricating success.
- `seekRenderedFrameMs`: the same delta from immediately before assigning `currentTime`. A qualifying callback must also follow `seeked`, observe `seeking === false`, have a `presentedFrames` counter above the baseline, and a `mediaTime` within ±0.25 seconds of the requested target. Late old callbacks, pre-seek frames and wrong-target frames do not count.
- `presentationTime` means frame submission for composition; it does **not** prove physical display, photons, absence of occlusion, or a browser window being visible. This is the browser's frame-presentation observation, not a decoder-only/media-event approximation.
- `playing`, `loadeddata`, `seeked`, and elapsed time alone never produce a successful rendered-frame sample. `seeked` is only a guard. Missing request/cancel frame APIs yield `unsupported`, never a fallback success. No qualifying frame within 15 seconds yields `failure`; media/play errors also yield failure with fixed, redacted reasons. Superseded/stopped operations are `cancelled`.
- Seek requires a finite media duration and a different target strictly before the end. Live streams without a finite duration, no-op seeks and nonseekable media are not benchmarked successfully; invalid duration/target yields explicit failure and lack of a seek completion/frame times out. The tolerance can reject coarse/keyframe-only seeks; it must not be relaxed after a run to pretend a stale frame qualified.
- p50/p95 use **nearest rank** (`ceil(p*N)-1` after sorting), separately by metric and cache label. Only successful finite nonnegative values are included. Empty distributions return `{count: 0, p50: null, p95: null}`. Single samples are not meaningful confidence estimates.
- Samples export `sanitizedURL` as scheme + host + `/[redacted]`. Username/password, the entire path, query, and fragment are removed (paths can contain credentials too). Non-HTTP URLs are fully redacted. No original URL, media exception text, page location, or arbitrary environment fields enter JSON. Browser-native network/devtools/history/server logs are outside this export sanitization guarantee. User agent/platform/language remain useful diagnostic fingerprinting information; review before sharing.

## Limits / interpretation

This is **not** a production WebView/external-player latency measurement, browser-to-native tracing, or end-to-end authorization benchmark. It cannot instrument frames from another app, an external player, or a WebView without the frame API. Browser codec/container support, DRM/EME, cookies/authentication, redirects, mixed content, range/seek support, media CORS policy and network conditions may prevent playback or make this result different from a production player. A video element often allows cross-origin playback without canvas-readable access; that does not bypass access controls or guarantee all media servers work. No `crossOrigin` flag or proxy is forced, no custom authorization headers are added. Do not paste credentials into URLs unless you accept browser/network exposure; JSON redaction alone is not a secrecy boundary.

Background tabs, visibility, power saving, scheduler delays, buffering and system load affect callbacks. Foreground/consistent conditions and browser/environment reporting are recommended. Cold/warm/consecutive distributions should not be pooled. This measures one manually chosen source per open, not product coverage or statistical representativeness.

## Focused automated tests

```sh
node --test tools/playback-probe/*.test.mjs
```

Tests use only Node's built-in test/assert modules and stub video/performance/timer interfaces. They verify generation/cancellation, unsupported APIs, stale seek frames, timeout/error handling, percentile filtering and export redaction. They do **not** validate real-browser presentation or codec behavior; actual manual playback is required for those claims. Parent CI can append the same command; no dependency installation is needed (Node 18+ recommended).
