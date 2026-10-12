# Reviewed playback source overlay

`playback_resilience_files.txt` is the narrow list of maintained upstream-tree
playback patches and their offline tests. `source_overlay_manifest.json` records
**pristine upstream** SHA-256 fingerprints, not hashes of our patched copies.
Its baseline is OpenList `v4.2.2`, commit
`b28208bd76ee19c49dabc7f68c1f4e863f571fc6`, obtained from the GitHub tag ref
and that exact commit's source archive. `null` means the path does not exist in
that pristine commit; an upstream file added there is a conflict, not permission
to overwrite it.

## Gates

```sh
python3 mobile/openlist-lib/scripts/test_source_overlay.py
python3 mobile/openlist-lib/scripts/verify_source_overlay.py --check-mirrors
```

The mirror check requires every listed actual build file and `src` copy to be
regular non-symlink files with equal bytes. It does **not** assert those files
are pristine. It also verifies the checked-in `UPSTREAM_VERSION` matches the
reviewed manifest. Both files must be updated together when changing a patch.

`init_openlist.sh` first runs the mirror and requested-tag check. It then clones
into a private staging directory and verifies the actual HEAD commit and all
pristine path fingerprints before applying **any** listed overlay. All source
patches are preflighted before the first copy. Clone, pin, content-conflict, or
missing-overlay failures leave the previous `src` and actual package tree
untouched. Only a fully verified, overlaid checkout replaces `src`. The
preflight is not a filesystem transaction against concurrent external writers;
do not run concurrent init/edit operations.

This overlay covers the listed readiness, cancellation, singleflight, cloud
provider, routed driver-client and retry patches, including the stage-five MEGA
reader and helper additions. It does not claim a whole-tree upstream merge or
cover historical model/buffer/WPS/static compatibility backup mechanisms. The
separate controlled **module** overlay still pins shared crypto and the MEGA
fork; these source checks do not modify dependency graphs, add checksums, or run
tidy. Heavy Go/gomobile/Android builds remain in GitHub Actions.

## Deliberate upstream upgrades

Changing `OPENLIST_TAG` or `UPSTREAM_VERSION` fails closed, even if affected
upstream content happens to have the same bytes. Resolve the exact new tag to
its commit, inspect pristine content against both the previous baseline and our
patches, perform a three-way review/rebase, and then regenerate reviewed original
fingerprints from that exact new commit. Update the manifest tag/commit and both
patch mirrors in the same reviewed PR. Do not generate a baseline from patched
`src`, accept patched fingerprints as pristine, or remove the gate to allow an
unreviewed upgrade. A moved tag at the same name is also rejected.
