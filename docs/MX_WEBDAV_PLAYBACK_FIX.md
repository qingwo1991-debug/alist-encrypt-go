# MX Player WebDAV playback: length consistency investigation

## Report and evidence

The user reported slow first frame or repeated buffering in MX Player when browsing and playing via WebDAV. The exported mobile log identifies release `v2026.10.12.395` and V2 AES-CTR media. The private log and original filenames are not part of this change.

Two observed objects have ciphertext/plaintext lengths of `1090044820/1090044788` and `4827259717/4827259685`, respectively. The 32-byte difference is the detected V2 header. The client repeatedly requested `bytes=1090044808-` and `bytes=4827259705-`, each 20 bytes beyond the plaintext EOF. The redirect requests then completed with HTTP 200 in tens or hundreds of microseconds, consistent with the existing empty-tail compatibility branch. Later requests also probed the plaintext EOF itself.

These observations support a representation-length inconsistency, not a proven network outage or codec failure. Cancellation and broken-pipe messages identify interrupted local HTTP streams but do not establish why the player canceled them. Request duration includes body lifetime and is not a first-frame measurement. The log does not capture final downstream headers or include HEAD requests.

## Docker/mobile comparison

The user confirms the same file, phone, MX Player and network work reliably with the Docker server but not the Android bundled server. This controlled comparison substantially narrows the investigation toward the server implementation/configuration difference. It does not by itself identify every contributing cause.

The repository's Docker/root stream implementation (`internal/proxy/stream_download.go`) excludes upstream Content-Length/Content-Range/Accept-Ranges when copying headers, then explicitly generates plaintext length and range headers for both complete and partial responses. Its WebDAV rewrite (`internal/handler/webdav_rewrite.go`) also adjusts listing lengths using confirmed V2 metadata. The mobile legacy WebDAV path does not implement the equivalent complete-GET header correction in the reported release. These are concrete code differences; they are not a claim that the user's particular Docker image has been inspected.

## Code-confirmed issues in the reported version

- PROPFIND transforms names but emits the backend `getcontentlength` unchanged, even when resolved encryption metadata is available.
- WebDAV legacy complete V2 GET copies ciphertext Content-Length before removing the encrypted header; only some Range branches overwrite the length afterward. This path remains used when the V2 stream engine is enabled.
- V2 HEAD does not share the GET representation-length and redirect handling. The log does not prove MX used HEAD; this is a separate code-level inconsistency.
- Legacy suffix and ignored-Range fallback paths can disagree with the redirect implementation, especially on short files and bounded ranges.

Never subtract 32 from arbitrary file sizes or shift the client's plaintext Range backward. V1, V2, V3 and unencrypted files require their own confirmed metadata. V3 overhead is not a fixed 32-byte difference.

## Validation requirements

Cloud regressions should cover actual downstream headers and bodies, not just the upstream logs: full GET read to EOF over real HTTP, HEAD with no body, PROPFIND property ordering, plaintext-tail reads based on published metadata, cold and warm routes, short suffix ranges, and upstream servers ignoring Range. Directory handling must remain bounded and must not probe every file over the network or perform per-entry SQLite reads. Unknown metadata must not be guessed.

The existing empty-tail compatibility response is not evidence that MX recovered. Changing its behavior globally requires consideration of other clients. Any retained cold-directory or compatibility limitation must be recorded rather than presented as fully fixed.

## Scope and cold-directory boundary

The safe listing correction uses confirmed metadata, not an inferred header size. A cold directory may still expose upstream lengths for entries whose content format has not been resolved; probing every object during directory listing would introduce a different first-frame/resource problem. Single-object Depth:0 metadata lookup is limited to the exact requested object and a maximum 1.5-second request-owned probe (or a shorter configured timeout). HEAD and GET must obtain the actual representation metadata with request-owned cancellation. Already-transformed cached directory snapshots must not be treated as fresh ciphertext observations or have their lengths reduced again.

A fresh ciphertext-size mismatch invalidates inherited encryption metadata rather than retaining the previous object's plaintext size. Matching size alone is not proof of immutable object identity; the existing cache freshness and origin rules remain relevant. Same-size replacement and client-side stale directory metadata require explicit consideration in device acceptance.

## Manual MX verification still required

After installing a release containing the fix, refresh the WebDAV directory or remove/re-add the stale item so MX does not retain ciphertext sizes. Test the same media with cold and warm directory caches, initial play, switching files, seeks near both ends, and repeated play. Record the APK version, MX version, network/VPN state, timestamps and newly exported logs. Successful automated regressions do not replace this device test and do not establish physical first-frame timing.

## Implemented listing safeguards

The mobile listing rewrite buffers one XML response at a time, with a 1 MiB / 65,536-token limit, rather than retaining the whole directory. It resolves properties regardless of whether href precedes the length. Only successful property sets and complete metadata tuples can supply an adjusted length. A fresh single-object proof that fails, changes format or disagrees with the raw size cannot inherit an old V2 tuple via cache merge. Already-transformed directory snapshots are replayed verbatim.

Tests include real HTTP PROPFIND followed by a tail GET derived from the published XML length, confirmed V2/V3 and unknown metadata, changed/expired sizes, collections and original objects, no-network directory rewrites, snapshot replay, and request cancellation. Complete GET and ignored-Range fallback now frame the plaintext response with the exact requested length and bound its reader. Short-file suffix ranges are parsed in plaintext coordinates before mapping upstream. HEAD obtains confirmed plaintext geometry without exposing an encrypted CDN redirect. Resolved GET uses the existing playback orchestrator, retaining routing hints, redirect credential handling, signed-URL refresh and bounded fallback rather than introducing a simplified network path. Raw `decode=0` reads still perform filename mapping before skipping content decryption.

Real HTTP regressions exercise V1/V2, direct and storage-redirect routes, honored and ignored Range, full GET/HEAD, bounded/open/suffix reads, prefix-skip admission and raw filename-mapped reads. V3 continues using its existing separate dispatch and full test suite. Existing beyond-EOF empty-200 compatibility is retained for redirected GET, while standard HEAD/direct range validation can return 416; this remaining client-compatibility difference requires device validation. Exact cloud results and final PR/main release verification will be recorded in the delivery PR once available.
