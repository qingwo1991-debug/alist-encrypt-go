package storage

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestFilenameRecoveryPreservesFailedAuditAndWriteFence(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	rec := filenameTestRecord()
	alias := filenameTestAlias()
	rec.OriginalPath, rec.EncryptedPath, rec.CiphertextSize = alias.DisplayPath, alias.EncryptedPath, alias.CiphertextSize
	rec, err = s.ReserveFilename(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.FinishFilenameReservation(rec.Origin, rec.EncryptedPath, rec.Token, FilenameFailed); err != nil {
		t.Fatal(err)
	}
	rec, _, _ = s.GetFilenameReservation(rec.Origin, rec.EncryptedPath)
	recovery := FilenameRecovery{AuditDigest: FilenameAuditDigest(rec), PrefixSHA256: strings.Repeat("c", 64), Evidence: alias}
	if err := s.PutFilenameRecovery(rec, recovery); err != nil {
		t.Fatal(err)
	}
	if err := s.PutFilenameRecovery(rec, recovery); err != nil {
		t.Fatal(err)
	}
	got, _, _ := s.GetFilenameReservation(rec.Origin, rec.EncryptedPath)
	if !reflect.DeepEqual(got, rec) {
		t.Fatal("failed audit changed")
	}
	if _, err := s.ReserveFilename(rec); err != ErrFilenameReserved {
		t.Fatalf("write fence lost: %v", err)
	}
	saved, found, err := s.GetFilenameRecovery(rec)
	if err != nil || !found || !bytes.Equal(saved.Evidence.NonceField, alias.NonceField) {
		t.Fatal("binding missing", err)
	}
	recovery.Evidence.NonceField[0]++
	if err := s.PutFilenameRecovery(rec, recovery); err == nil {
		t.Fatal("replacement admitted")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	reopened, ok, err := s.GetFilenameRecovery(rec)
	if err != nil || !ok || reopened.PrefixSHA256 != saved.PrefixSHA256 {
		t.Fatal("recovery lost after restart", err)
	}
	got, _, _ = s.GetFilenameReservation(rec.Origin, rec.EncryptedPath)
	if !reflect.DeepEqual(got, rec) {
		t.Fatal("restart changed failed audit")
	}
	rec.UpdatedAt = rec.UpdatedAt.Add(1)
	if _, found, _ := s.GetFilenameRecovery(rec); found {
		t.Fatal("changed audit admitted")
	}
}

func TestFilenameRecoveryRejectsPendingAndAmbiguity(t *testing.T) {
	s := filenameTestStore(t)
	alias := filenameTestAlias()
	rec := filenameTestRecord()
	rec.OriginalPath, rec.EncryptedPath, rec.CiphertextSize = alias.DisplayPath, alias.EncryptedPath, alias.CiphertextSize
	rec, err := s.ReserveFilename(rec)
	if err != nil {
		t.Fatal(err)
	}
	recovery := FilenameRecovery{AuditDigest: FilenameAuditDigest(rec), PrefixSHA256: strings.Repeat("c", 64), Evidence: alias}
	if err := s.PutFilenameRecovery(rec, recovery); err == nil {
		t.Fatal("pending admitted")
	}
	if err := s.FinishFilenameReservation(rec.Origin, rec.EncryptedPath, rec.Token, FilenameFailed); err != nil {
		t.Fatal(err)
	}
	rec, _, _ = s.GetFilenameReservation(rec.Origin, rec.EncryptedPath)
	recovery.AuditDigest = FilenameAuditDigest(rec)
	other := rec
	other.EncryptedPath = "/enc/another.bin"
	other.AuthScope = strings.Repeat("d", 64)
	if _, err := s.ReserveFilename(other); err != nil {
		t.Fatal(err)
	}
	if err := s.PutFilenameRecovery(rec, recovery); err == nil {
		t.Fatal("ambiguous mapping admitted")
	}
}
