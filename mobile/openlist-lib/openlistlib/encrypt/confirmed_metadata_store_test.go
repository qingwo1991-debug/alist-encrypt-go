package encrypt

import (
	"database/sql"
	"math"
	"path/filepath"
	"reflect"
	"testing"
)

func confirmedStoreForTest(t *testing.T, filename string) *localStore {
	t.Helper()
	db, err := sql.Open("sqlite3", filename)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	if err := initConfirmedMetadataSchema(db); err != nil {
		t.Fatal(err)
	}
	if err := initConfirmedMetadataSchema(db); err != nil {
		t.Fatal(err)
	}
	return &localStore{db: db}
}

func confirmedRecordForTest() confirmedMetadataRecord {
	return confirmedMetadataRecord{
		Identity:   confirmedMetadataIdentity{"https://origin.invalid/dav/object", "credential-hash", "rule-hash"},
		Meta:       ContentMeta{EncType: EncTypeAESCTR, Version: ContentVersionV2, HeaderLen: 32, PlainSize: 100, CiphertextSize: 132, NonceField: []byte("0123456789abcdef")},
		Provenance: confirmedMetadataProvenanceInspection, ConfirmedAt: 100, ValidatedAt: 101,
		ETag: `"object-version"`, LastModified: "Wed, 01 Jan 2025 00:00:00 GMT", ValidatorScope: "origin-representation", Generation: 2,
	}
}

func TestConfirmedMetadataStoreAllInvalidation(t *testing.T) {
	if testing.Short() {
		t.Skip("CGO SQLite in short mode")
	}
	s := confirmedStoreForTest(t, filepath.Join(t.TempDir(), "confirmed.db"))
	if err := initLocalSchema(s.db); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO local_media_size (key, provider_host, original_path, size, last_accessed, updated_at) VALUES (?, ?, ?, ?, ?, ?)`, "legacy", "origin.invalid", "/dav/object", 100, 100, 100); err != nil {
		t.Fatal(err)
	}
	first := confirmedRecordForTest()
	second := confirmedRecordForTest()
	second.Identity.CredentialScope = "another-user"
	other := confirmedRecordForTest()
	other.Identity.ObjectID = "https://origin.invalid/dav/other-object"
	for _, rec := range []confirmedMetadataRecord{first, second, other} {
		if err := s.PutConfirmedMetadata(rec); err != nil {
			t.Fatal(err)
		}
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := s.DeleteAllConfirmedMetadata(); err != nil {
			t.Fatal(err)
		}
	}
	for _, rec := range []confirmedMetadataRecord{first, second, other} {
		if _, ok := s.GetConfirmedMetadata(rec.Identity); ok {
			t.Fatal("full invalidation retained confirmed evidence")
		}
	}
	if size, ok := s.GetSize("legacy"); !ok || size != 100 {
		t.Fatal("confirmed invalidation altered legacy size table")
	}
}

func TestConfirmedMetadataStoreObjectInvalidation(t *testing.T) {
	if testing.Short() {
		t.Skip("CGO SQLite in short mode")
	}
	s := confirmedStoreForTest(t, filepath.Join(t.TempDir(), "confirmed.db"))
	first := confirmedRecordForTest()
	second := confirmedRecordForTest()
	second.Identity.CredentialScope = "another-user"
	second.Identity.CryptoFingerprint = "another-rule"
	other := confirmedRecordForTest()
	other.Identity.ObjectID = "https://origin.invalid/dav/other-object"
	for _, rec := range []confirmedMetadataRecord{first, second, other} {
		if err := s.PutConfirmedMetadata(rec); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.DeleteConfirmedMetadataObject(""); err == nil {
		t.Fatal("empty object identity accepted")
	}
	if err := s.DeleteConfirmedMetadataObject(first.Identity.ObjectID); err != nil {
		t.Fatal(err)
	}
	for _, id := range []confirmedMetadataIdentity{first.Identity, second.Identity} {
		if _, ok := s.GetConfirmedMetadata(id); ok {
			t.Fatal("mutated object retained a credential/rule scope")
		}
	}
	if got, ok := s.GetConfirmedMetadata(other.Identity); !ok || !reflect.DeepEqual(got, other) {
		t.Fatal("object-wide invalidation deleted an unrelated object")
	}
}

func TestConfirmedMetadataIdentityLengthFraming(t *testing.T) {
	a := confirmedMetadataIdentity{"a::b", "c", "d"}
	b := confirmedMetadataIdentity{"a", "b::c", "d"}
	if a.Key() == b.Key() || len(a.Key()) != 64 {
		t.Fatal("identity key framing failed")
	}
	if a.Key() != a.Key() {
		t.Fatal("identity key not deterministic")
	}
}

func TestConfirmedMetadataRecordValidation(t *testing.T) {
	good := confirmedRecordForTest()
	empty := good
	empty.Meta = ContentMeta{EncType: EncTypeAESCTR, Version: ContentVersionV3, HeaderLen: V3HeaderSize, CiphertextSize: V3HeaderSize, NonceField: []byte("0123456789abcdef"), ChunkSize: 4096, KDFIterations: 1}
	if !validConfirmedMetadataRecord(empty) {
		t.Fatal("valid empty V3 rejected")
	}
	legacy := good
	legacy.Meta = LegacyContentMeta(EncTypeAESCTR, 100)
	if !validConfirmedMetadataRecord(legacy) {
		t.Fatal("confirmed V1 rejected")
	}
	mutations := []struct {
		name   string
		mutate func(*confirmedMetadataRecord)
	}{
		{"list provenance", func(r *confirmedMetadataRecord) { r.Provenance = "list" }},
		{"missing scope", func(r *confirmedMetadataRecord) { r.Identity.CredentialScope = "" }},
		{"missing confirmation", func(r *confirmedMetadataRecord) { r.ConfirmedAt = 0 }},
		{"validation before confirmation", func(r *confirmedMetadataRecord) { r.ValidatedAt = 99 }},
		{"incomplete nonce", func(r *confirmedMetadataRecord) { r.Meta.NonceField = nil }},
		{"wrong header", func(r *confirmedMetadataRecord) { r.Meta.HeaderLen = 31 }},
		{"same size inconsistent", func(r *confirmedMetadataRecord) { r.Meta.CiphertextSize++ }},
		{"inferred cipher", func(r *confirmedMetadataRecord) { r.Meta.CiphertextSize = 0 }},
		{"overflow", func(r *confirmedMetadataRecord) { r.Meta.PlainSize = math.MaxInt64 }},
		{"unknown version", func(r *confirmedMetadataRecord) { r.Meta.Version = 4 }},
		{"generation overflow", func(r *confirmedMetadataRecord) { r.Generation = math.MaxUint64 }},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			rec := good
			tc.mutate(&rec)
			if validConfirmedMetadataRecord(rec) {
				t.Fatal("invalid record accepted")
			}
		})
	}
	legacy.Meta.NonceField = []byte{1}
	if validConfirmedMetadataRecord(legacy) {
		t.Fatal("V1 with crypto nonce accepted")
	}
	empty.Meta.CiphertextSize++
	if validConfirmedMetadataRecord(empty) {
		t.Fatal("invalid V3 geometry accepted")
	}
}

func TestConfirmedMetadataStoreDurableAtomicAndIsolated(t *testing.T) {
	if testing.Short() {
		t.Skip("CGO SQLite in short mode")
	}
	filename := filepath.Join(t.TempDir(), "confirmed.db")
	s := confirmedStoreForTest(t, filename)
	rec := confirmedRecordForTest()
	if err := s.PutConfirmedMetadata(rec); err != nil {
		t.Fatal(err)
	}
	got, ok := s.GetConfirmedMetadata(rec.Identity)
	if !ok || !reflect.DeepEqual(got, rec) {
		t.Fatalf("roundtrip: ok=%v got=%+v", ok, got)
	}
	rec.Meta.NonceField[0] = 'x'
	got.Meta.NonceField[1] = 'y'
	again, ok := s.GetConfirmedMetadata(rec.Identity)
	if !ok || string(again.Meta.NonceField) != "0123456789abcdef" {
		t.Fatal("nonce aliases stored data")
	}
	other := rec.Identity
	other.CredentialScope = "another-user"
	if _, ok := s.GetConfirmedMetadata(other); ok {
		t.Fatal("credential isolation failed")
	}
	other = rec.Identity
	other.CryptoFingerprint = "another-rule"
	if _, ok := s.GetConfirmedMetadata(other); ok {
		t.Fatal("crypto isolation failed")
	}
	restarted := confirmedStoreForTest(t, filename)
	if _, ok := restarted.GetConfirmedMetadata(rec.Identity); !ok {
		t.Fatal("write was not immediately durable")
	}
	// Atomic replacement clears fields from the previous container/version.
	replacement := confirmedRecordForTest()
	replacement.Meta = LegacyContentMeta(EncTypeAESCTR, 132)
	replacement.ETag = ""
	replacement.LastModified = ""
	replacement.ValidatorScope = ""
	replacement.Generation++
	replacement.ValidatedAt++
	if err := s.PutConfirmedMetadata(replacement); err != nil {
		t.Fatal(err)
	}
	got, ok = s.GetConfirmedMetadata(rec.Identity)
	if !ok || !reflect.DeepEqual(got, replacement) {
		t.Fatalf("tuple not replaced atomically: %+v", got)
	}
	old := confirmedRecordForTest()
	if err := s.PutConfirmedMetadata(old); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetConfirmedMetadata(rec.Identity)
	if !reflect.DeepEqual(got, replacement) {
		t.Fatal("older generation resurrected metadata")
	}
	bad := replacement
	bad.Provenance = "import"
	if err := s.PutConfirmedMetadata(bad); err == nil {
		t.Fatal("untrusted write accepted")
	}
	if _, err := s.db.Exec(`UPDATE confirmed_metadata SET ciphertext_size=1 WHERE object_key=?`, rec.Identity.Key()); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.GetConfirmedMetadata(rec.Identity); ok {
		t.Fatal("corrupt geometry accepted on read")
	}
	if err := s.DeleteConfirmedMetadata(rec.Identity); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.GetConfirmedMetadata(rec.Identity); ok {
		t.Fatal("deleted metadata found")
	}
}
