package mysqlstore

import (
	"testing"
	"time"
)

// TestMySQLWriteDedupeIntegration executes the dedup filter, the changed
// ON DUPLICATE KEY clauses and the duplicate-path migration against a real
// MySQL: the GROUP BY / BINARY / UPDATE ... IN statements and the IF()
// column rules cannot be validated by the in-process fake driver.
// MYSQL_TEST_DSN opts in using the isolated-database fixture.
func TestMySQLWriteDedupeIntegration(t *testing.T) {
	ctx, s, _ := newMySQLIntegrationStore(t)
	s.SetStableProviderHost("alist.example:5244")
	if err := s.ensureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	countActive := func(path string) (n int, keys []string) {
		rows, err := s.db.QueryContext(ctx, "SELECT key_hash FROM "+TableName("file_meta")+" WHERE BINARY original_path = BINARY ? AND is_active=1 ORDER BY key_hash", path)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			var k string
			if err := rows.Scan(&k); err != nil {
				t.Fatal(err)
			}
			n++
			keys = append(keys, k)
		}
		return n, keys
	}
	updatedAt := func(key string) time.Time {
		var ts time.Time
		if err := s.db.QueryRowContext(ctx, "SELECT updated_at FROM "+TableName("file_meta")+" WHERE key_hash=?", key).Scan(&ts); err != nil {
			t.Fatal(err)
		}
		return ts
	}

	// 1) A restart (fresh Store, empty memory maps) must not rewrite an
	//    informationally identical row; a refreshed raw_url must be written.
	base := time.Now().Add(-time.Hour).Truncate(time.Second)
	row := FileMetaRecord{ProviderHost: "alist.example:5244", OriginalPath: "/dedupe/a.mp4", Size: 12345, CiphertextSize: 16448, ContentVersion: 3, HeaderLen: 64,
		NonceField: []byte("0123456789abcdef"), ChunkSize: 4096, KDFIterations: 1234, RawURL: "https://cdn.example/a?sig=1", RawURLAuthScope: "scope", Sign: "s1",
		EncryptedPath: "/dedupe/a.bin", Name: "a.mp4", ETag: "e1", ContentType: "video/mp4", StatusCode: 206, Active: true, UpdatedAt: base, LastAccessed: base, UpstreamFetchedAt: base}
	row.KeyHash = KeyHash(row.ProviderHost, row.OriginalPath)
	if err := s.upsertFileMeta(ctx, []FileMetaRecord{row}); err != nil {
		t.Fatal(err)
	}
	before := updatedAt(row.KeyHash)
	time.Sleep(1100 * time.Millisecond) // DATETIME(0): make any rewrite observable

	// Same buffers NewStore wires, so the real flushBuffers can be driven.
	restarted := &Store{db: s.db, strategyBuffer: newStrategyBuffer(), fileMetaBuffer: newFileMetaBuffer(), rangeCompatBuffer: newRangeCompatBuffer()}
	restarted.SetStableProviderHost("alist.example:5244")
	// Same content; the write stamps are "now". This is exactly the rewrite a
	// restart performs today and must become a no-op.
	if err := restarted.UpsertFileMeta(ctx, FileMetaRecord{ProviderHost: "alist.example:5244", OriginalPath: row.OriginalPath, Size: row.Size, CiphertextSize: row.CiphertextSize, ContentVersion: 3, HeaderLen: 64,
		NonceField: row.NonceField, ChunkSize: 4096, KDFIterations: 1234, RawURL: row.RawURL, RawURLAuthScope: "scope", Sign: "s1",
		EncryptedPath: row.EncryptedPath, Name: row.Name, ETag: "e1", ContentType: "video/mp4", StatusCode: 206, Active: true}); err != nil {
		t.Fatal(err)
	}
	restarted.flushBuffers(ctx)
	if got := updatedAt(row.KeyHash); !got.Equal(before) {
		t.Fatalf("restart rewrote an unchanged row: updated_at %v -> %v", before, got)
	}
	// Refreshed signed URL is written and the stored row keeps its observations.
	if err := restarted.UpsertFileMeta(ctx, FileMetaRecord{ProviderHost: "alist.example:5244", OriginalPath: row.OriginalPath, Size: row.Size, RawURL: "https://cdn.example/a?sig=2", Sign: "s2", Active: true}); err != nil {
		t.Fatal(err)
	}
	restarted.flushBuffers(ctx)
	var rawURL, sign, etag string
	var status int
	var chunk uint32
	if err := s.db.QueryRowContext(ctx, "SELECT raw_url, sign, etag, status_code, chunk_size FROM "+TableName("file_meta")+" WHERE key_hash=?", row.KeyHash).Scan(&rawURL, &sign, &etag, &status, &chunk); err != nil {
		t.Fatal(err)
	}
	if rawURL != "https://cdn.example/a?sig=2" || sign != "s2" || etag != "e1" || status != 206 || chunk != 4096 {
		t.Fatalf("refresh lost stored observations: raw_url=%q sign=%q etag=%q status=%d chunk=%d", rawURL, sign, etag, status, chunk)
	}

	// 2) Unobserved status/etag/content_type no longer clobber the stored row
	//    (the DAO writer never sets them; the size resolver does).
	if err := s.upsertFileMeta(ctx, []FileMetaRecord{{KeyHash: row.KeyHash, ProviderHost: row.ProviderHost, OriginalPath: row.OriginalPath, Size: 5, Active: true}}); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRowContext(ctx, "SELECT etag, status_code FROM "+TableName("file_meta")+" WHERE key_hash=?", row.KeyHash).Scan(&etag, &status); err != nil {
		t.Fatal(err)
	}
	if etag != "e1" || status != 206 {
		t.Fatalf("unobserved fields clobbered stored row: etag=%q status=%d", etag, status)
	}

	// 3) Duplicate-path migration on legacy multi-host rows. Insert directly so
	//    the rows carry their historical (raw-URL host) key hashes.
	legacy := []FileMetaRecord{
		{ProviderHost: "cdn1.example", OriginalPath: "/legacy/x.mp4", Size: 1, StatusCode: 206},
		{ProviderHost: "webdav.example", OriginalPath: "/legacy/x.mp4", Size: 2, RawURL: "https://webdav.example/x?sig=1", Sign: "w1", RawURLAuthScope: "scope", EncryptedPath: "/legacy/x.bin", Name: "x.mp4"},
		{ProviderHost: "cdn2.example", OriginalPath: "/legacy/x.mp4", Size: 3, ContentVersion: 3, CiphertextSize: 64, HeaderLen: 64, NonceField: []byte("nonce-2"), ChunkSize: 4096, KDFIterations: 9},
	}
	now := time.Now()
	for i := range legacy {
		l := legacy[i]
		l.KeyHash = KeyHash(l.ProviderHost, l.OriginalPath)
		l.UpdatedAt = now.Add(-time.Duration(3-i) * time.Hour)
		l.LastAccessed = l.UpdatedAt
		l.UpstreamFetchedAt = l.UpdatedAt
		l.Active = true
		if err := s.upsertFileMeta(ctx, []FileMetaRecord{l}); err != nil {
			t.Fatal(err)
		}
	}
	if n, _ := countActive("/legacy/x.mp4"); n != 3 {
		t.Fatalf("fixture: active=%d", n)
	}
	summary, err := s.RunFileMetaDedupe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Paths != 1 || summary.RowsRewritten != 1 || summary.RowsDeactivated != 3 {
		t.Fatalf("summary=%+v", summary)
	}
	stable := KeyHash("alist.example:5244", "/legacy/x.mp4")
	n, keys := countActive("/legacy/x.mp4")
	if n != 1 || keys[0] != stable {
		t.Fatalf("active rows after migration: n=%d keys=%v", n, keys)
	}
	survivor, found, err := s.GetFileMeta(ctx, "alist.example:5244", "/legacy/x.mp4")
	if err != nil || !found {
		t.Fatalf("key-hash lookup after migration: found=%v err=%v", found, err)
	}
	if survivor.RawURL != "https://webdav.example/x?sig=1" || survivor.Sign != "w1" || survivor.EncryptedPath != "/legacy/x.bin" || survivor.ProviderHost != "alist.example:5244" {
		t.Fatalf("wrong survivor: %+v", survivor)
	}
	// The geometry row's confirmed content metadata must have been merged
	// into the survivor: deactivating the duplicates must not lose it.
	if survivor.ContentVersion != 3 || string(survivor.NonceField) != "nonce-2" || survivor.HeaderLen != 64 || survivor.ChunkSize != 4096 || survivor.KDFIterations != 9 || survivor.CiphertextSize != 64 {
		t.Fatalf("survivor lost the geometry row's content metadata: %+v", survivor)
	}
	if survivor.StatusCode != 206 {
		t.Fatalf("survivor lost status observation: %+v", survivor)
	}
	// Legacy rows are deactivated, not deleted (reversible).
	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+TableName("file_meta")+" WHERE BINARY original_path = BINARY ?", "/legacy/x.mp4").Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total != 4 {
		t.Fatalf("rows for path=%d, want 4 (3 legacy + survivor); migration must not delete", total)
	}
	// Path lookup (read side, requires content_version > 0) still resolves
	// the path to the stable row, because geometry was merged into it.
	byPath, found, err := s.GetFileMetaByPath(ctx, "/legacy/x.mp4")
	if err != nil || !found || byPath == nil || byPath.KeyHash != stable {
		key := "<nil>"
		if byPath != nil {
			key = byPath.KeyHash
		}
		t.Fatalf("path lookup after migration: found=%v err=%v key=%s", found, err, key)
	}
	// Idempotent.
	again, err := s.RunFileMetaDedupe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if again.Paths != 0 || again.RowsRewritten != 0 || again.RowsDeactivated != 0 {
		t.Fatalf("second run not a no-op: %+v", again)
	}

	// 4) Batching over the keyset cursor with more than one page of paths, and
	//    exact (binary) path grouping for case-differing paths.
	for i := 0; i < 7; i++ {
		for _, host := range []string{"cdnA.example", "cdnB.example"} {
			p := "/batch/p" + string(rune('0'+i)) + ".mp4"
			l := FileMetaRecord{KeyHash: KeyHash(host, p), ProviderHost: host, OriginalPath: p, Size: int64(i), Active: true, UpdatedAt: now, LastAccessed: now, UpstreamFetchedAt: now}
			if host == "cdnB.example" {
				l.RawURL = "https://cdnB.example/" + p
			}
			if err := s.upsertFileMeta(ctx, []FileMetaRecord{l}); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Case-differing paths must stay separate rows under the default collation.
	for _, p := range []string{"/batch/Case.mp4", "/batch/case.mp4"} {
		for _, host := range []string{"cdnA.example", "cdnB.example"} {
			l := FileMetaRecord{KeyHash: KeyHash(host, p), ProviderHost: host, OriginalPath: p, Size: 1, Active: true, UpdatedAt: now, LastAccessed: now, UpstreamFetchedAt: now, RawURL: "https://" + host + p}
			if err := s.upsertFileMeta(ctx, []FileMetaRecord{l}); err != nil {
				t.Fatal(err)
			}
		}
	}
	summary, err = s.RunFileMetaDedupe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Paths != 9 || summary.RowsRewritten != 9 || summary.RowsDeactivated != 18 {
		t.Fatalf("batch summary=%+v", summary)
	}
	for _, p := range []string{"/batch/Case.mp4", "/batch/case.mp4"} {
		if n, keys := countActive(p); n != 1 || keys[0] != KeyHash("alist.example:5244", p) {
			t.Fatalf("case-sensitive path %s collapsed incorrectly: n=%d keys=%v", p, n, keys)
		}
	}
}
