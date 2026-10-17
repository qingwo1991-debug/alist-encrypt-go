# Offline root-Bolt restore: deliberately component-only

`store-maint` is separate from the service bootstrap. It has no clear/unfence,
provider enumeration, automatic rollback, SQLite restore or MySQL restore mode.
The command does not stop processes; stop the service first. Do not run it against
production without separate operational authorization and a recovery rehearsal.

## Commands

```text
store-maint verify --bundle /absolute/snapshot.tar --max-bytes 1073741824
store-maint restore --store-dir /absolute/data --bundle /absolute/snapshot.tar \
  --config /absolute/conf/config.json --config-sha256 <independently-pinned-sha256>
```

Every supplied path must already exist, be absolute/canonical, and have no symlink
components. The existing DB must be a regular file. The data directory and bundle
parents must be operator-owned/trusted and not mutable by an attacker. Temporary
files are 0600 in private 0700 staging directories. The service and tool share an
OS lifetime `.store-maint.lock`, acquired before DB open with a bounded wait. Do
not unlink that lock file. Unix uses flock and Windows uses LockFileEx, so normal
Windows service startup remains supported. Other platforms explicitly return
unsupported. Windows/filesystems lacking directory fsync may refuse the restore
operation; a prepared marker, if already published, remains restrictive.

The service retains this lock through shutdown/store close. Independent old
binaries or direct NewStore callers do not participate; they must also be stopped.
A DB lock conflict fails rather than authorizing another writer. OS filesystem
calls and bbolt mmap/check are cooperatively cancelable, not hard deadlines.

## Config is external, not silently omitted

`alist-encrypt.db` contains a Bolt config bucket but is not the separately persisted
runtime `conf/config.json`/configPath. The operator supplies the latter plus its
independently pinned SHA256. Validation parses those bytes directly, requires core
fields and matching absolute data_dir, validates endpoint/rules, rejects a configured
external database, and never calls config.Load, creates defaults, generates secrets,
or changes the supplied file. Preserve that file separately as sensitive material.
A DB-only bundle has no historical config digest: the supplied hash proves the
operator's byte selection, **not historical DB/config correspondence**. All reports
say root-bolt, external-required and full_restore=false. Other auxiliary files,
MySQL, SQLite and global application buffers are outside this restore.

## Protocol and failure behavior

1. Acquire common exclusive lifetime ownership; validate pinned external config.
2. Copy the input bundle to private local staging, then validate the actual copy
   using the strict bundle/hash/schema/Bolt structure and audit-index validator.
   Extraction accepts only the already-validated two owned bundle members. It
   never calls NewStore or initializes the source snapshot.
3. Create and validate a read-transaction rollback snapshot of the **current** DB
   through a read-only connection. Publish it as `pre-restore-<op>.tar`; do not
   delete it on later errors.
4. Persist `prepared`, then `restoring`, sidecar with atomic rename and file plus
   directory fsync, before mutating any target DB bytes.
5. Add `recovery_generation_v1` in the verified private DB copy's config bucket;
   invalidate FileInfo raw_url/raw_url_auth_scope/sign, refusing unknown entity
   fields rather than blindly dropping future schema. Geometry and original
   timestamps are preserved. The original snapshot hash was verified first; these deliberate local changes
   produces a new transaction watermark/hash which is independently revalidated.
   Source and installed hashes are reported separately, not confused.
6. Rename the private DB over the stopped target on the same filesystem, fsync
   the directory, then durably publish `reconciliation-required`.

The sidecar is the durable phase journal; root DB is the only replaced component.
This is not a multi-file/global transaction. Errors after prepared leave a fence;
errors after rename can mean the new DB is installed while the sidecar still says
restoring. Never interpret command failure as proof that the old DB remains live.
The retained rollback bundle can be verified and preserved for a separately
approved manual repair protocol. This CLI deliberately refuses any nested restore
when an existing sidecar (including invalid state) or sticky DB key/bucket exists,
so it cannot overwrite the only durable operation history. It offers no rollback
override, force or generic clear; future audited repair must preserve old journals
and retain fencing. Do not remove state files to bypass this restriction.

Startup inspects the sticky DB key before bucket initialization; even a missing
sidecar fences a marked DB. Present invalid/unknown sidecars fence independently.
There is no approved-generation/unfence transition yet: any sticky key is restrictive
and no generation match can authorize writes. Deleting *both* marker and database
key, or using an older unfenced binary, is outside the protection protocol.
Existing timestamps, original names and reservation states are not rewritten;
adding the sticky key does not renew cache TTLs. FileInfo transport URLs/signs and
their credential scope are cleared, forcing fresh transport resolution. The
rollback/source bundle still contains sensitive historical bytes and requires
private storage. Original-name reservations/indices and alias confirmation times
are not cleared or renewed; runtime reads retain normal scope/TTL validation.
The rollback filename is derivable from the durable sidecar's operation_id as
`pre-restore-<operation_id>.tar`, so a crash does not depend on the stdout report.

The report always says reconciliation unknown because no provider enumeration was
performed. In particular new remote objects absent from the restored DB remain
unknown. A successful local restore is not successful reconciliation. External
writers are not fenced; P8 must establish audited evidence and explicit state
transitions before any future解除/clear feature.

## Validation evidence and remaining matrix

Added fixtures cover strict ownership contention, original-state restoration,
verified rollback presence, unchanged TTL value, sticky missing-sidecar startup,
config digest mismatch, relative/symlink paths, cancellation, injected database
publish rename and post-rename directory-sync failures. Faults retain a durable
fence and rollback bundle. No production operation is used by these fixtures.

Formatting/diff checks are local; Go compilation and tests run in cloud CI under
the repository's cloud-first policy. A subprocess kill at every journal step,
actual power-loss durability, hostile concurrent directory replacement, disk-full
at every individual write/fsync, and a production/provider recovery rehearsal are
not claimed by this PR. Runtime backup-owner cancellation remains separate work.
