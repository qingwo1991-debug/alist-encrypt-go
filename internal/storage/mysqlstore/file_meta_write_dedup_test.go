package mysqlstore

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestNoOpWriteSkippedInMemory: the same row buffered twice in one process
// produces a single INSERT, and a third identical write after the flush
// produces none (lastFlushed fast path, no SELECT).
func TestNoOpWriteSkippedInMemory(t *testing.T) {
	s, d := newFakeMetaStore(t)
	s.SetStableProviderHost("alist.example")
	row := FileMetaRecord{OriginalPath: "/m/a.mp4", Size: 100, ContentVersion: 3, CiphertextSize: 164, HeaderLen: 64, NonceField: []byte("n1"), ChunkSize: 4096, KDFIterations: 10, RawURL: "https://cdn/a", Sign: "s"}

	mustUpsert(t, s, row)
	mustUpsert(t, s, row) // identical pending write collapses into the same buffer slot
	flushMeta(t, s)
	if d.inserts != 1 {
		t.Fatalf("inserts=%d, want 1", d.inserts)
	}
	mustUpsert(t, s, row)
	if n := len(s.fileMetaBuffer.drain()); n != 0 {
		t.Fatalf("identical write after flush was enqueued (%d records); want it dropped in memory", n)
	}
}

// TestNoOpWriteSkippedAfterRestart: the in-memory maps are empty (new process)
// but the database already holds an identical row. The flush must perform one
// PK SELECT, recognise the row as unchanged and write nothing.
func TestNoOpWriteSkippedAfterRestart(t *testing.T) {
	s, d := newFakeMetaStore(t)
	s.SetStableProviderHost("alist.example")
	row := FileMetaRecord{OriginalPath: "/m/a.mp4", Size: 100, ContentVersion: 3, CiphertextSize: 164, HeaderLen: 64, NonceField: []byte("n1"), ChunkSize: 4096, KDFIterations: 10, RawURL: "https://cdn/a", RawURLAuthScope: "scope", Sign: "s", EncryptedPath: "/m/a.bin", Name: "a.mp4", ETag: "e", ContentType: "video/mp4", StatusCode: 206}
	mustUpsert(t, s, row)
	flushMeta(t, s)
	if d.inserts != 1 {
		t.Fatalf("inserts=%d, want 1", d.inserts)
	}

	// "Restart": a brand-new Store over the same database, empty memory maps.
	restarted, _ := newFakeMetaStoreOver(t, d)
	restarted.SetStableProviderHost("alist.example")
	// The write stamp (updated_at/last_accessed/upstream_fetched_at=now) is
	// exactly what a restart rewrites today; it must not count as a change.
	mustUpsert(t, restarted, row)
	flushMeta(t, restarted)
	if d.inserts != 1 {
		t.Fatalf("restart rewrote an unchanged row: inserts=%d, want 1", d.inserts)
	}
	// The skipped row is now remembered, so the next identical write costs
	// neither a SELECT nor an INSERT.
	before := d.inserts
	mustUpsert(t, restarted, row)
	if n := len(restarted.fileMetaBuffer.drain()); n != 0 || d.inserts != before {
		t.Fatalf("remembered row not used: enqueued=%d inserts=%d", n, d.inserts)
	}
}

// TestChangedRawURLStillWritten: a refreshed signed URL (or sign) is always
// written, both in-memory and after a restart.
func TestChangedRawURLStillWritten(t *testing.T) {
	s, d := newFakeMetaStore(t)
	s.SetStableProviderHost("alist.example")
	row := FileMetaRecord{OriginalPath: "/m/a.mp4", Size: 100, ContentVersion: 3, CiphertextSize: 164, HeaderLen: 64, NonceField: []byte("n1"), ChunkSize: 4096, KDFIterations: 10, RawURL: "https://cdn/a?sig=1", Sign: "s1"}
	mustUpsert(t, s, row)
	flushMeta(t, s)

	refreshed := row
	refreshed.RawURL = "https://cdn/a?sig=2"
	mustUpsert(t, s, refreshed)
	flushMeta(t, s)
	if d.inserts != 2 {
		t.Fatalf("refreshed raw_url not written: inserts=%d, want 2", d.inserts)
	}
	if got := d.rows[s.StableFileMetaKeyHash("/m/a.mp4")].RawURL; got != refreshed.RawURL {
		t.Fatalf("stored raw_url=%q", got)
	}

	restarted, _ := newFakeMetaStoreOver(t, d)
	restarted.SetStableProviderHost("alist.example")
	refreshed.RawURL = "https://cdn/a?sig=3"
	refreshed.Sign = "s3"
	mustUpsert(t, restarted, refreshed)
	flushMeta(t, restarted)
	if d.inserts != 3 {
		t.Fatalf("refreshed raw_url after restart not written: inserts=%d, want 3", d.inserts)
	}
	stored := d.rows[s.StableFileMetaKeyHash("/m/a.mp4")]
	if stored.RawURL != "https://cdn/a?sig=3" || stored.Sign != "s3" {
		t.Fatalf("stored row not refreshed: %+v", stored)
	}
}

// TestExplicitUpstreamFetchChangeWritten: a caller-recorded fetch time that
// moved forces a write even when every other column is identical; the
// DAO-style "now" stamp on an otherwise identical row does not.
func TestExplicitUpstreamFetchChangeWritten(t *testing.T) {
	s, d := newFakeMetaStore(t)
	s.SetStableProviderHost("alist.example")
	fetched := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	row := FileMetaRecord{OriginalPath: "/m/a.mp4", Size: 100, RawURL: "https://cdn/a", UpstreamFetchedAt: fetched}
	mustUpsert(t, s, row)
	flushMeta(t, s)
	if d.inserts != 1 {
		t.Fatalf("inserts=%d, want 1", d.inserts)
	}

	// Same content, newer explicit fetch time: written.
	newer := row
	newer.UpstreamFetchedAt = fetched.Add(time.Hour)
	mustUpsert(t, s, newer)
	flushMeta(t, s)
	if d.inserts != 2 {
		t.Fatalf("explicit upstream_fetched_at change not written: inserts=%d", d.inserts)
	}

	// Same content, same explicit fetch time: skipped.
	mustUpsert(t, s, newer)
	if n := len(s.fileMetaBuffer.drain()); n != 0 {
		t.Fatalf("unchanged explicit-fetch row enqueued: %d", n)
	}

	// Same content with no fetch time (pure write stamp): skipped after restart.
	restarted, _ := newFakeMetaStoreOver(t, d)
	restarted.SetStableProviderHost("alist.example")
	mustUpsert(t, restarted, FileMetaRecord{OriginalPath: "/m/a.mp4", Size: 100, RawURL: "https://cdn/a"})
	flushMeta(t, restarted)
	if d.inserts != 2 {
		t.Fatalf("write stamp alone caused a rewrite: inserts=%d, want 2", d.inserts)
	}
}

// TestSizeReconciliationPreservedOnDedupPath: a size-only write whose Size is
// the ciphertext size must be reconciled to the stored plaintext size by the
// merger before the no-op check, so it is correctly recognised as unchanged
// (and NOT as a size change), exactly as the old per-request GetFileMeta +
// preserveV2FileMetaRecord did.
func TestSizeReconciliationPreservedOnDedupPath(t *testing.T) {
	s, d := newFakeMetaStore(t)
	s.SetStableProviderHost("alist.example")
	mergerCalls := 0
	s.SetFileMetaStoredRowMerger(func(stored, incoming *FileMetaRecord) {
		mergerCalls++
		// Same shape as handler.preserveV2FileMetaRecord for the V3 case.
		if stored.ContentVersion == 3 && len(incoming.NonceField) == 0 && incoming.ContentVersion <= 0 && incoming.Size == stored.CiphertextSize {
			incoming.Size = stored.Size
			incoming.CiphertextSize = stored.CiphertextSize
			incoming.HeaderLen = stored.HeaderLen
			incoming.ChunkSize = stored.ChunkSize
			incoming.KDFIterations = stored.KDFIterations
			incoming.NonceField = append([]byte(nil), stored.NonceField...)
			incoming.ContentVersion = stored.ContentVersion
			incoming.RawURL = stored.RawURL
		}
	})
	full := FileMetaRecord{OriginalPath: "/m/v3.mp4", Size: 12345, CiphertextSize: 16448, ContentVersion: 3, HeaderLen: 64, NonceField: []byte("n1"), ChunkSize: 4096, KDFIterations: 1234, RawURL: "https://cdn/a", StatusCode: 206, ETag: "e1", ContentType: "video/mp4"}
	mustUpsert(t, s, full)
	flushMeta(t, s)

	restarted, _ := newFakeMetaStoreOver(t, d)
	restarted.SetStableProviderHost("alist.example")
	restarted.SetFileMetaStoredRowMerger(s.mergeStoredRow)
	// Size-only observation carrying the CIPHERTEXT size.
	mustUpsert(t, restarted, FileMetaRecord{OriginalPath: "/m/v3.mp4", Size: 16448, StatusCode: 206})
	flushMeta(t, restarted)
	if d.inserts != 1 {
		t.Fatalf("size-only write rewrote the row (inserts=%d); reconciliation should have made it a no-op", d.inserts)
	}
	if mergerCalls == 0 {
		t.Fatal("merger was not invoked on the flush path")
	}
	stored := d.rows[restarted.StableFileMetaKeyHash("/m/v3.mp4")]
	if stored.Size != 12345 || stored.ChunkSize != 4096 || stored.KDFIterations != 1234 || stored.StatusCode != 206 || stored.ETag != "e1" {
		t.Fatalf("stored geometry disturbed: %+v", stored)
	}

	// The DAO-style write (no status/etag/content-type, fresh stamp) is a
	// no-op too: unobserved fields inherit the stored values.
	mustUpsert(t, restarted, FileMetaRecord{OriginalPath: "/m/v3.mp4", Size: 12345, CiphertextSize: 16448, ContentVersion: 3, HeaderLen: 64, NonceField: []byte("n1"), ChunkSize: 4096, KDFIterations: 1234, RawURL: "https://cdn/a"})
	flushMeta(t, restarted)
	if d.inserts != 1 {
		t.Fatalf("DAO-style identical write rewrote the row: inserts=%d", d.inserts)
	}

	// A DAO-style write that adds a real field (encrypted-path mapping) IS
	// written, and the written row keeps the resolver's status/etag.
	mustUpsert(t, restarted, FileMetaRecord{OriginalPath: "/m/v3.mp4", Size: 12345, CiphertextSize: 16448, ContentVersion: 3, HeaderLen: 64, NonceField: []byte("n1"), ChunkSize: 4096, KDFIterations: 1234, RawURL: "https://cdn/a", EncryptedPath: "/m/v3.bin"})
	flushMeta(t, restarted)
	if d.inserts != 2 {
		t.Fatalf("mapping write not persisted: inserts=%d", d.inserts)
	}
	stored = d.rows[restarted.StableFileMetaKeyHash("/m/v3.mp4")]
	if stored.EncryptedPath != "/m/v3.bin" || stored.StatusCode != 206 || stored.ETag != "e1" || stored.ContentType != "video/mp4" {
		t.Fatalf("mapping write clobbered stored observations: %+v", stored)
	}

	// A genuinely different plaintext size IS written.
	mustUpsert(t, restarted, FileMetaRecord{OriginalPath: "/m/v3.mp4", Size: 999, StatusCode: 206})
	flushMeta(t, restarted)
	if d.inserts != 3 {
		t.Fatalf("real size change not written: inserts=%d", d.inserts)
	}
}

// TestSizeReconciliationPreservedInBuffer: the in-buffer V2/V3 merge is
// untouched: a size-only write following a geometry write inherits the
// plaintext size, and a replacement container does not.
func TestSizeReconciliationPreservedInBuffer(t *testing.T) {
	s, _ := newFakeMetaStore(t)
	original := FileMetaRecord{OriginalPath: "/plain", Size: 12345, CiphertextSize: 16448, ContentVersion: 3, HeaderLen: 64, NonceField: []byte("1234567890abcdef"), ChunkSize: 4096, KDFIterations: 1234}
	mustUpsert(t, s, original)
	mustUpsert(t, s, FileMetaRecord{OriginalPath: "/plain", Size: 16448})
	records := s.fileMetaBuffer.drain()
	if len(records) != 1 || records[0].Size != 12345 || records[0].ChunkSize != 4096 || records[0].KDFIterations != 1234 {
		t.Fatalf("buffer lost metadata: %+v", records)
	}
	mustUpsert(t, s, FileMetaRecord{OriginalPath: "/plain", ContentVersion: 3, NonceField: []byte("fedcba0987654321"), Size: 100})
	records = s.fileMetaBuffer.drain()
	if len(records) != 1 || records[0].ChunkSize != 0 || records[0].KDFIterations != 0 || records[0].Size != 100 {
		t.Fatalf("replacement inherited geometry: %+v", records)
	}
}

// TestOneRowPerPathForNewWrites: writes for the same path from different
// provider hosts (rotating raw URL hosts) all land on ONE stable key whose
// key_hash equals KeyHash(alistHost, path), so the legacy key-hash lookup
// GetFileMeta(ProviderKey(alistURL), path) resolves it.
func TestOneRowPerPathForNewWrites(t *testing.T) {
	s, d := newFakeMetaStore(t)
	s.SetStableProviderHost("alist.example:5244")
	for _, host := range []string{"cdn1.example", "cdn2.example", "webdav.example"} {
		mustUpsert(t, s, FileMetaRecord{ProviderHost: host, OriginalPath: "/m/a.mp4", Size: 100, RawURL: "https://" + host + "/a"})
	}
	flushMeta(t, s)
	if len(d.rows) != 1 {
		t.Fatalf("rows=%d, want 1 (one row per path)", len(d.rows))
	}
	key := KeyHash("alist.example:5244", "/m/a.mp4")
	r, ok := d.rows[key]
	if !ok {
		t.Fatalf("row not stored under the alist-origin key hash")
	}
	if r.ProviderHost != "alist.example:5244" {
		t.Fatalf("provider_host=%q, want stable host", r.ProviderHost)
	}
	got, found, err := s.GetFileMeta(context.Background(), "alist.example:5244", "/m/a.mp4")
	if err != nil || !found || got.KeyHash != key {
		t.Fatalf("legacy key-hash lookup missed the stable row: found=%v err=%v", found, err)
	}
}

// TestDedupeMigrationPicksSurvivor: three legacy rows for one path; the one
// with a raw_url (newest fetch) survives, is re-keyed under the stable key,
// and the other two are deactivated (not deleted).
func TestDedupeMigrationPicksSurvivor(t *testing.T) {
	s, d := newFakeMetaStore(t)
	s.SetStableProviderHost("alist.example")
	now := time.Now()
	legacy := []FileMetaRecord{
		{ProviderHost: "cdn1.example", OriginalPath: "/m/a.mp4", Size: 1, Active: true, UpdatedAt: now, UpstreamFetchedAt: now.Add(-3 * time.Hour)},
		{ProviderHost: "webdav.example", OriginalPath: "/m/a.mp4", Size: 2, Active: true, UpdatedAt: now.Add(-time.Minute), UpstreamFetchedAt: now.Add(-time.Hour), RawURL: "https://webdav.example/a?sig=1", Sign: "sig1", RawURLAuthScope: "scope", EncryptedPath: "/m/a.bin", Name: "a.mp4"},
		{ProviderHost: "cdn2.example", OriginalPath: "/m/a.mp4", Size: 3, ContentVersion: 3, CiphertextSize: 64, Active: true, UpdatedAt: now.Add(-2 * time.Hour), UpstreamFetchedAt: now.Add(-2 * time.Hour)},
	}
	for i := range legacy {
		legacy[i].KeyHash = KeyHash(legacy[i].ProviderHost, legacy[i].OriginalPath)
		d.rows[legacy[i].KeyHash] = legacy[i]
	}

	summary, err := s.RunFileMetaDedupe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary.Paths != 1 || summary.RowsRewritten != 1 || summary.RowsDeactivated != 3 {
		t.Fatalf("summary=%+v", summary)
	}
	stable := KeyHash("alist.example", "/m/a.mp4")
	survivor, ok := d.rows[stable]
	if !ok {
		t.Fatal("survivor was not rewritten under the stable key")
	}
	if survivor.RawURL != "https://webdav.example/a?sig=1" || survivor.Sign != "sig1" || survivor.EncryptedPath != "/m/a.bin" {
		t.Fatalf("wrong survivor: %+v", survivor)
	}
	if !survivor.Active {
		t.Fatal("survivor is not active")
	}
	for _, r := range legacy {
		if d.rows[r.KeyHash].Active {
			t.Fatalf("legacy row %s still active", r.KeyHash)
		}
		if _, exists := d.rows[r.KeyHash]; !exists {
			t.Fatalf("legacy row %s was deleted; migration must only deactivate", r.KeyHash)
		}
	}
	active := activeRows(d, "/m/a.mp4")
	if len(active) != 1 || active[0].KeyHash != stable {
		t.Fatalf("active rows after migration=%+v", active)
	}

	// Idempotent: a second run is a no-op.
	again, err := s.RunFileMetaDedupe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if again.Paths != 0 || again.RowsRewritten != 0 || again.RowsDeactivated != 0 {
		t.Fatalf("second run was not a no-op: %+v", again)
	}

	// Reversible: flipping is_active back restores the legacy rows untouched.
	for _, r := range legacy {
		row := d.rows[r.KeyHash]
		row.Active = true
		d.rows[r.KeyHash] = row
	}
	if n := len(activeRows(d, "/m/a.mp4")); n != 4 {
		t.Fatalf("reversal did not restore legacy rows: active=%d", n)
	}
}

// TestDedupeMigrationPrefersCompletenessWhenNoRawURL and keeps an existing
// stable row rather than re-keying a legacy one over it.
// TestDedupeMigrationKeepsExistingStableRow: an existing stable row is the
// base and is never clobbered — its own values win — but it is COMPLETED
// with information only the legacy duplicates hold (here: the signed URL),
// so deactivating them cannot drop it.
func TestDedupeMigrationKeepsExistingStableRow(t *testing.T) {
	s, d := newFakeMetaStore(t)
	s.SetStableProviderHost("alist.example")
	now := time.Now()
	stable := KeyHash("alist.example", "/m/b.mp4")
	d.rows[stable] = FileMetaRecord{KeyHash: stable, ProviderHost: "alist.example", OriginalPath: "/m/b.mp4", Size: 10, Active: true, UpdatedAt: now}
	for _, host := range []string{"cdn1.example", "cdn2.example"} {
		k := KeyHash(host, "/m/b.mp4")
		d.rows[k] = FileMetaRecord{KeyHash: k, ProviderHost: host, OriginalPath: "/m/b.mp4", Size: 99, Active: true, UpdatedAt: now, UpstreamFetchedAt: now.Add(-time.Hour), RawURL: "https://" + host + "/b", Sign: "sig-" + host}
	}
	summary, err := s.RunFileMetaDedupe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary.RowsRewritten != 1 || summary.RowsDeactivated != 2 {
		t.Fatalf("summary=%+v", summary)
	}
	got := d.rows[stable]
	// The stable row's own size wins (not the legacy 99) ...
	if got.Size != 10 || !got.Active || got.ProviderHost != "alist.example" {
		t.Fatalf("existing stable row was disturbed: %+v", got)
	}
	// ... but it gained the newest legacy signed URL.
	if got.RawURL != "https://cdn1.example/b" || got.Sign != "sig-cdn1.example" {
		t.Fatalf("stable row not completed with the legacy URL: %+v", got)
	}
	if n := len(activeRows(d, "/m/b.mp4")); n != 1 {
		t.Fatalf("active rows=%d, want 1", n)
	}

	// When the stable row already holds everything the duplicates have, the
	// migration only deactivates and writes nothing.
	stable2 := KeyHash("alist.example", "/m/c.mp4")
	d.rows[stable2] = FileMetaRecord{KeyHash: stable2, ProviderHost: "alist.example", OriginalPath: "/m/c.mp4", Size: 10, Active: true, UpdatedAt: now, RawURL: "https://cdn.example/c", Sign: "s", EncryptedPath: "/m/c.bin"}
	k := KeyHash("cdn1.example", "/m/c.mp4")
	d.rows[k] = FileMetaRecord{KeyHash: k, ProviderHost: "cdn1.example", OriginalPath: "/m/c.mp4", Size: 10, Active: true, UpdatedAt: now, RawURL: "https://cdn1.example/c", Sign: "s", EncryptedPath: "/m/c.bin"}
	summary, err = s.RunFileMetaDedupe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary.RowsRewritten != 0 || summary.RowsDeactivated != 1 {
		t.Fatalf("complete stable row: summary=%+v", summary)
	}
	if got := d.rows[stable2]; got.RawURL != "https://cdn.example/c" {
		t.Fatalf("complete stable row was rewritten: %+v", got)
	}
}

// TestDedupeMigrationBatches: more than one batch of duplicate paths is
// paged through the keyset cursor without skipping or repeating paths.
func TestDedupeMigrationBatches(t *testing.T) {
	s, d := newFakeMetaStore(t)
	s.SetStableProviderHost("alist.example")
	now := time.Now()
	const paths = fileMetaDedupeBatchPaths + 37 // 2 batches
	for i := 0; i < paths; i++ {
		p := "/" + strings.Repeat("0", 6-len(itoa(i))) + itoa(i) + ".mp4"
		for j, host := range []string{"cdnA.example", "cdnB.example"} {
			k := KeyHash(host, p)
			d.rows[k] = FileMetaRecord{KeyHash: k, ProviderHost: host, OriginalPath: p, Size: int64(j), Active: true, UpdatedAt: now, UpstreamFetchedAt: now}
			if j == 1 {
				d.rows[k] = FileMetaRecord{KeyHash: k, ProviderHost: host, OriginalPath: p, Size: int64(j), Active: true, UpdatedAt: now, UpstreamFetchedAt: now, RawURL: "https://" + host + "/x"}
			}
		}
	}
	summary, err := s.RunFileMetaDedupe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary.Batches != 2 {
		t.Fatalf("batches=%d, want 2", summary.Batches)
	}
	if summary.Paths != paths || summary.RowsRewritten != paths || summary.RowsDeactivated != 2*paths {
		t.Fatalf("summary=%+v", summary)
	}
	activeCount := 0
	for _, r := range d.rows {
		if r.Active {
			activeCount++
		}
	}
	if activeCount != paths {
		t.Fatalf("active rows=%d, want %d", activeCount, paths)
	}
	for i := 0; i < paths; i++ {
		p := "/" + strings.Repeat("0", 6-len(itoa(i))) + itoa(i) + ".mp4"
		rows := activeRows(d, p)
		if len(rows) != 1 || rows[0].KeyHash != KeyHash("alist.example", p) || rows[0].RawURL == "" {
			t.Fatalf("path %s not collapsed onto the stable raw_url row: %+v", p, rows)
		}
	}
}

// TestDedupeLookupFailureFallsBackToWrite: if the dedup row SELECT errors the
// row is written (pre-dedup behaviour), never silently dropped.
func TestDedupeLookupFailureFallsBackToWrite(t *testing.T) {
	s, d := newFakeMetaStore(t)
	s.SetStableProviderHost("alist.example")
	// Pre-existing identical row (simulating a restart).
	stable := KeyHash("alist.example", "/m/a.mp4")
	d.rows[stable] = FileMetaRecord{KeyHash: stable, ProviderHost: "alist.example", OriginalPath: "/m/a.mp4", Size: 100, Active: true, UpdatedAt: time.Now()}
	d.failKeyLookup = true
	mustUpsert(t, s, FileMetaRecord{OriginalPath: "/m/a.mp4", Size: 100})
	flushMeta(t, s)
	if d.inserts != 1 {
		t.Fatalf("row was dropped on lookup error: inserts=%d, want 1", d.inserts)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [8]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}
