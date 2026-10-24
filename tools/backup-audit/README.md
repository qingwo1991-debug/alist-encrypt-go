# Offline rehearsal audit inventory

This standalone Go command imports only stdlib and `go.etcd.io/bbolt`; it never imports the server/storage constructors, initializes buckets, repairs records, contacts an upstream, or sends cloud writes.

```sh
go test ./tools/backup-audit -count=1
go build -o /private/backup-audit ./tools/backup-audit
/private/backup-audit \
  --allow-root /private/immutable-rehearsal-copy \
  --db /private/immutable-rehearsal-copy/data/alist-encrypt.db \
  --output /private/new-audit-report.json
```

Use a trusted **offline immutable copy only**. Stop all processes that could open that copy. Do not open a live database or call a hot filesystem copy a consistent backup. `--allow-root` is mandatory; filesystem root, broad `/root` or `/app`, and known production roots `/root/docker` and `/app/{data,conf,configs}` are rejected. Lexical and resolved database paths must both stay inside the supplied copy root. Symlinks escaping that root and hard-linked database files are rejected. Linux/Unix `Nlink` support is required; unsupported file-info implementations fail closed. An adversarially writable directory or path race is outside this trusted-local tool's guarantees.

The database opens with bbolt `ReadOnly: true` and a one-second lock timeout. Input is capped at 512 MiB, traversal at one million entries and 32 nested levels; OS file I/O is not a hard-deadline operation. Ctrl-C / SIGTERM requests cooperative cancellation. The tool refuses to create a nonexistent database, and report creation is exclusive, mode `0600`, never overwrites an existing file/symlink. Errors expose fixed codes, not raw paths or data.

Reports include:

- Allowlisted audit/alias/recovery and derived playback/index bucket presence, **top-level** value counts, top-level nested-bucket counts, and stable SHA-256 over recursively framed ordered keys/values.
- Filename reservation status counters `pending`, `complete`, `failed`, `unknown`, and `invalid_json`. Unknown/malformed values are never counted as successful records; arbitrary status text is not emitted.
- Users/password-rule/config bucket presence and top-level counts only: their values are not hashed, decoded, or emitted.
- Number of other root buckets, without exposing arbitrary bucket names.
- Database size and read-transaction watermark for context, not consistency proof.

Digests are for comparing exact bytes in the **same bucket** between stopped copies. Derived indexes/caches, transaction ID and database size may legitimately differ after startup/rebuild; compare durable audit buckets separately. Missing versus empty buckets are distinct. Nested audit structures are inventoried, not validated. Full database integrity, audit/recovery semantics, reverse-index consistency, encryption rules outside Bolt, current snapshot consistency, source media integrity, and successful production migration **are not established** by this report. `inventory_only=true` and `snapshot_consistency_validated=false` deliberately preserve that boundary. Exit 0 only means inventory/report creation succeeded, not that a rehearsal or recovery was accepted.

Tests use temporary synthetic Bolt files only and cover status classification, secret redaction, no source mutation, digest stability/change detection, root/symlink/hardlink guards, writer-lock timeout, cancellation, and exclusive output permissions.
