package storage

import (
	"bytes"
	"errors"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func filenameTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func filenameTestRecord() FilenameRecord {
	return FilenameRecord{Origin: "http://alist:5244", EncryptedPath: "/enc/short.bin", OriginalPath: "/enc/long original.mp4", DisplayName: "short.bin", AuthScope: strings.Repeat("a", 64), RuleFingerprint: strings.Repeat("b", 64), CiphertextSize: 132}
}
func TestFilenameReservationDurability(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := s.ReserveFilename(filenameTestRecord())
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != FilenamePending || len(rec.Token) != 32 || rec.CreatedAt.IsZero() {
		t.Fatalf("bad reservation: %+v", rec)
	}
	if err = s.FinishFilenameReservation(rec.Origin, rec.EncryptedPath, "wrong", FilenameComplete); !errors.Is(err, ErrFilenameTokenMismatch) {
		t.Fatalf("wrong token: %v", err)
	}
	if err = s.FinishFilenameReservation(rec.Origin, rec.EncryptedPath, rec.Token, FilenameFailed); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, ok, err := s.GetFilenameReservation(rec.Origin, rec.EncryptedPath)
	if err != nil || !ok || got.Status != FilenameFailed || got.Token != rec.Token {
		t.Fatalf("reopen: %+v %v %v", got, ok, err)
	}
	if _, err = s.ReserveFilename(filenameTestRecord()); !errors.Is(err, ErrFilenameReserved) {
		t.Fatalf("failed reservation must remain protected: %v", err)
	}
	got, ok, err = s.GetFilenameReservationByOriginal(rec.Origin, rec.OriginalPath, rec.AuthScope, rec.RuleFingerprint)
	if err != nil || !ok || got.EncryptedPath != rec.EncryptedPath {
		t.Fatalf("original lookup: %+v %v %v", got, ok, err)
	}
	_, ok, err = s.GetFilenameReservationByOriginal(rec.Origin, rec.OriginalPath, strings.Repeat("c", 64), rec.RuleFingerprint)
	if err != nil || ok {
		t.Fatalf("cross auth: %v %v", ok, err)
	}
}
func TestFilenameReservationConcurrentUnique(t *testing.T) {
	s := filenameTestStore(t)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := filenameTestRecord()
			if i%2 == 0 {
				rec.AuthScope = strings.Repeat("c", 64)
			}
			_, err := s.ReserveFilename(rec)
			if err == nil {
				wins.Add(1)
			} else if !errors.Is(err, ErrFilenameReserved) {
				t.Errorf("reserve: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("winners=%d", wins.Load())
	}
}
func TestFilenameReservationValidation(t *testing.T) {
	s := filenameTestStore(t)
	for _, change := range []func(*FilenameRecord){func(r *FilenameRecord) { r.Origin = "http://user:secret@alist" }, func(r *FilenameRecord) { r.EncryptedPath = "/enc/../short.bin" }, func(r *FilenameRecord) { r.OriginalPath = "relative" }, func(r *FilenameRecord) { r.AuthScope = "secret" }} {
		rec := filenameTestRecord()
		change(&rec)
		if _, err := s.ReserveFilename(rec); err == nil {
			t.Fatal("invalid record accepted")
		}
	}
}
func filenameTestAlias() VerifiedMediaAlias {
	return VerifiedMediaAlias{Origin: "http://alist:5244", EncryptedPath: "/enc/cipher.bin", DisplayPath: "/enc/orig_cipher.mp4", AuthScope: strings.Repeat("a", 64), RuleFingerprint: strings.Repeat("b", 64), CiphertextSize: 132, PlainSize: 100, ContentVersion: encryption.ContentVersionV2, HeaderLen: 32, NonceField: bytes.Repeat([]byte{7}, 16), EncType: encryption.EncTypeAESCTR, VerifiedAt: time.Now().UTC(), MIME: "video/mp4", Ext: ".mp4", Provenance: VerifiedMediaAliasProvenance}
}
func TestVerifiedMediaAliasScopeGeometryAndReverse(t *testing.T) {
	s := filenameTestStore(t)
	rec := filenameTestAlias()
	if err := s.PutVerifiedMediaAlias(rec); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.GetVerifiedMediaAlias(rec.Origin, rec.EncryptedPath, rec.AuthScope, rec.RuleFingerprint, 132)
	if err != nil || !ok || !bytes.Equal(got.NonceField, rec.NonceField) {
		t.Fatalf("get: %+v %v %v", got, ok, err)
	}
	got.NonceField[0] = 90
	got, ok, err = s.GetVerifiedMediaAliasByDisplay(rec.Origin, rec.DisplayPath, rec.AuthScope, rec.RuleFingerprint, 132)
	if err != nil || !ok || got.NonceField[0] != 7 {
		t.Fatalf("reverse/clone: %+v %v %v", got, ok, err)
	}
	for _, auth := range []string{strings.Repeat("c", 64), rec.AuthScope} {
		size := int64(132)
		if auth == rec.AuthScope {
			size = 133
		}
		_, ok, err = s.GetVerifiedMediaAlias(rec.Origin, rec.EncryptedPath, auth, rec.RuleFingerprint, size)
		if err != nil || ok {
			t.Fatalf("scope/size leak: %v %v", ok, err)
		}
	}
	other := rec
	other.EncryptedPath = "/enc/other.bin"
	if err = s.PutVerifiedMediaAlias(other); !errors.Is(err, ErrMediaAliasConflict) {
		t.Fatalf("reverse conflict: %v", err)
	}
	other.AuthScope = strings.Repeat("c", 64)
	if err = s.PutVerifiedMediaAlias(other); err != nil {
		t.Fatalf("isolated scope alias: %v", err)
	}
	rec.DisplayPath = "/enc/new.mp4"
	rec.VerifiedAt = time.Now().UTC()
	if err = s.PutVerifiedMediaAlias(rec); err != nil {
		t.Fatal(err)
	}
	_, ok, err = s.GetVerifiedMediaAliasByDisplay(rec.Origin, "/enc/orig_cipher.mp4", rec.AuthScope, rec.RuleFingerprint, 0)
	if err != nil || ok {
		t.Fatalf("old reverse remained: %v %v", ok, err)
	}
}
func TestVerifiedMediaAliasValidationAndExpiry(t *testing.T) {
	s := filenameTestStore(t)
	for _, change := range []func(*VerifiedMediaAlias){func(r *VerifiedMediaAlias) { r.NonceField = nil }, func(r *VerifiedMediaAlias) { r.CiphertextSize++ }, func(r *VerifiedMediaAlias) { r.Provenance = "listing" }, func(r *VerifiedMediaAlias) { r.Ext = ".exe" }, func(r *VerifiedMediaAlias) { r.MIME = "application/octet-stream" }, func(r *VerifiedMediaAlias) { r.HeaderLen = 0 }, func(r *VerifiedMediaAlias) { r.PlainSize = -1 }} {
		r := filenameTestAlias()
		change(&r)
		if err := s.PutVerifiedMediaAlias(r); err == nil {
			t.Fatalf("invalid alias admitted: %+v", r)
		}
	}
	r := filenameTestAlias()
	r.VerifiedAt = time.Now().Add(-25 * time.Hour)
	if err := s.PutVerifiedMediaAlias(r); err != nil {
		t.Fatal(err)
	}
	_, ok, err := s.GetVerifiedMediaAlias(r.Origin, r.EncryptedPath, r.AuthScope, r.RuleFingerprint, 0)
	if err != nil || ok {
		t.Fatalf("expired alias returned: %v %v", ok, err)
	}
	_, ok, err = s.GetVerifiedMediaAliasByDisplay(r.Origin, r.DisplayPath, r.AuthScope, r.RuleFingerprint, 0)
	if err != nil || ok {
		t.Fatalf("expired reverse returned: %v %v", ok, err)
	}
}
func TestVerifiedMediaAliasEmptyV3(t *testing.T) {
	s := filenameTestStore(t)
	r := filenameTestAlias()
	r.ContentVersion = encryption.ContentVersionV3
	r.PlainSize = 0
	r.HeaderLen = encryption.V3HeaderSize
	r.CiphertextSize = encryption.V3HeaderSize
	r.ChunkSize = 4096
	r.KDFIterations = 600000
	if err := s.PutVerifiedMediaAlias(r); err != nil {
		t.Fatalf("empty V3: %v", err)
	}
	r.CiphertextSize++
	if err := s.PutVerifiedMediaAlias(r); err == nil {
		t.Fatal("invalid empty V3 geometry accepted")
	}
}
