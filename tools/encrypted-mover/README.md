# encrypted-mover

A lightweight two-node scheduler for the fixed magnet-list workflow.

- odd/even source-line assignment; BTIH de-duplication in SQLite
- one active aria2 task per node; no seeding
- 12 GiB selected-task limit and 5 GiB disk reserve
- video >= 200 MiB plus subtitle-only selection
- decisive metadata/no-progress/low-speed/runtime eviction
- V2 AES-CTR streaming encryption; no ciphertext file is written locally
- encrypted filenames with .bin suffix
- direct upload to local OpenList at 127.0.0.1:5244
- OpenList upload undone/done tracking and final exact-size/V2-header verification
- upload preflight remote duplicate verification

The daemon never uses the encryption proxy port. OpenList receives ciphertext of exactly plaintext-size + 32 bytes.

## Commands

    encrypted-mover --config /etc/encrypted-mover/config.json daemon
    encrypted-mover --config /etc/encrypted-mover/config.json sync
    encrypted-mover --config /etc/encrypted-mover/config.json status
    encrypted-mover --config /etc/encrypted-mover/config.json add 'magnet:?xt=...'
    encrypted-mover --config /etc/encrypted-mover/config.json source-add NAME URL
    encrypted-mover --config /etc/encrypted-mover/config.json source-list
    encrypted-mover --config /etc/encrypted-mover/config.json source-disable NAME
    encrypted-mover --config /etc/encrypted-mover/config.json retry ID
    encrypted-mover --config /etc/encrypted-mover/config.json cancel ID

Task sources are ordinary UTF-8 text files with one magnet URI per non-comment line. The source can be maintained in GitHub/Gist and is polled by refresh interval.

## Recovery and deletion rules

- Stalled download tasks are force-removed with their partial files, then cooled down for 24 hours.
- Upload failures preserve completed downloads and resume in `upload_retry`.
- Local plaintext is removed only after OpenList task success (or verified taskless completion), exact `plain+32` size, and a valid AECTR2 header carrying the original size.
- Existing verified remote objects cause immediate local deletion and `skipped_existing`.
- The 5 GiB reserve is enforced before downloading, while downloading, and while streaming into OpenList.
- Source parity uses the ordinal of non-comment magnet lines.
