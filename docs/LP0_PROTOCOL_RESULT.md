# LP0 protocol implementation result

Status: authored and statically checked; Go execution is pending the PR cloud matrix. No production service/configuration/database/cloud object changes.

## Changes

- PROPFIND transport listing sizes no longer overwrite confirmed plaintext sizes in the listing metadata store. Confirmed V1/V2/V3 geometry is reused only when the observed ciphertext size agrees; zero plaintext (empty V3) is valid evidence.
- Single-resource Depth:0 may inspect its exact DAV object with the current caller headers. Depth:1 does not synchronously inspect every member. Unknown encrypted getcontentlength is unavailable (404 propstat), not ciphertext masquerading as plaintext.
- The length protection pass uses namespace-aware XML token offsets, accepting arbitrary prefixes and response attributes. It preserves unrelated upstream XML bytes. The older filename rewrite pass still recognizes its existing D:/d:/unprefixed spellings; this change does not claim arbitrary-prefix encrypted filename rewriting support.
- Parsing distinguishes missing/unavailable length (`-1`) from a known empty file (`0`), and ignores explicitly unsuccessful propstats. Snapshot serialization preserves unavailable length rather than later publishing 200 length zero.
- Missing derived filenames may fall back once to a literal slash directory only after a 404, and only accept a matching collection response. Method, body, Depth and caller authentication remain intact. Confirmed directory cache entries avoid repeating this fallback. Retry cannot request the same raw/self-mapped candidate twice.
- V2 open-ended Range at plaintext EOF no longer invokes legacy ciphertext-tail normalization; existing bounded-tail compatibility remains. Acceptance tests add HEAD length and open-ended EOF/416 coverage.

## Verification

- `/usr/local/go/bin/gofmt` and `git diff --check`: passed.
- `python3 -B -m unittest discover -s tools -p test_local_playback_probe.py -v`: 2/2 passed.
- Go tests were **not executed successfully**: previous owner encountered read-only Go cache/module paths and missing cached dependencies with offline mode. No retry, permission workaround, or dependency downloads were attempted by the replacement owner.
- Authored Go fixtures cover confirmed V1/V2/V3/empty sizes, original-name overlay, cold real V2 inspection, unknown/empty snapshot semantics, arbitrary XML prefixes/attributes, real directory slash fallback with a negative cache, missing raw/self-mapped candidates, and proxy HEAD/EOF assertions. Synthetic V3 geometry fixtures do not prove a cold real empty-V3 inspection.

## Integration boundaries

- LP1 renames `verifiedFilenameRawPathKey` / `verifiedFilenameRawPath` to `filenameRawPathKey` / `filenameRawPath` and changes its remember helper. Reconcile the small context-name/test-helper overlap when combining branches.
- LP2 should route the on-demand Depth:0 inspection through shared metadata resolution/coalescing. This initial LP0 path uses DAV plus current caller headers only; it does not implement signed raw-URL or alternate probe-credential fallback, nor claim that such storage is verified here.
- LP4 is responsible for disabling bulk background member probes in trusted-local mode. This branch alone only guarantees no synchronous per-member inspection in Depth:1.
- Phone frames, complete plaintext reference comparison, 60-minute playback and final deployed measurements remain unverified.
