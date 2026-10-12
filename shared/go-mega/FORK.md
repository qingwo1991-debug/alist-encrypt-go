# Fixed MEGA cancellation fork

Original module: `github.com/t3rm1n4l/go-mega`, exact upstream commit
`a19cff0ec7b5ccca340d51f4b71e01266c92bb24`, corresponding to the already pinned
`v0.0.0-20241213151442-a19cff0ec7b5`. Original MIT LICENSE, dependency checksums,
crypto/file format logic and upstream tests are retained. Source fetched from
https://github.com/t3rm1n4l/go-mega/tree/a19cff0ec7b5ccca340d51f4b71e01266c92bb24 .

Changes add context variants for login, API metadata/mutations, download and
upload requests; synchronous API serialization and retry backoff are cancellable.
Actual HTTP uses `NewRequestWithContext` and context-aware dialing. A session
owns an independent context and at most one event poller. `Close` first cancels
real transfers, then joins the poller and admitted operations; successful sessions
do not inherit the login caller's timeout. No abandoned network goroutine wrapper
is used. Go 1.21 minimum reflects `context.AfterFunc`.

The OpenList module and its source mirror use depth-correct local replacements.
The controlled overlay script validates module identity and installs these
replacements without replacing or regenerating the upstream checksum graph.

Cloud offline acceptance:

```sh
go test -race -mod=readonly -timeout=5m -run 'Test(Context|Close|Backoff)' ./...
```

These tests use loopback requests and no MEGA account. Upstream account/network
integration tests remain present, but are not claimed to have run offline.
Mobile driver tests additionally cover concurrent reader Close cancellation before
waiting for the Read mutex, single MAC verification, and canceled retry timers.
Driver-owned HTTP clients are supplied through OpenList's neutral transport
factory; no global Resty proxy mutation is introduced.
