package storage

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func filenameRetryWriteRecord(t *testing.T, s *Store, rec FilenameRecord) FilenameRecord {
	t.Helper()
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Set(filenameReservations, string(filenameKey(rec.Origin, rec.EncryptedPath)), raw); err != nil {
		t.Fatal(err)
	}
	return rec
}

func filenameRetryFailedRecord(t *testing.T, s *Store, rec FilenameRecord) FilenameRecord {
	t.Helper()
	rec, err := s.ReserveFilename(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.FinishFilenameReservation(rec.Origin, rec.EncryptedPath, rec.Token, FilenameFailed); err != nil {
		t.Fatal(err)
	}
	rec, found, err := s.GetFilenameReservation(rec.Origin, rec.EncryptedPath)
	if err != nil || !found {
		t.Fatalf("failed reservation: found=%v err=%v", found, err)
	}
	rec.CreatedAt = time.Now().UTC().Add(-3 * FilenameRetryMinAge)
	rec.UpdatedAt = time.Now().UTC().Add(-2 * FilenameRetryMinAge)
	return filenameRetryWriteRecord(t, s, rec)
}

func filenameRetryAudits(t *testing.T, s *Store) map[string]FilenameRetryAudit {
	t.Helper()
	audits := make(map[string]FilenameRetryAudit)
	if err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("filename_retry_audit_v1"))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, raw []byte) error {
			var audit FilenameRetryAudit
			if err := json.Unmarshal(raw, &audit); err != nil {
				return err
			}
			audits[string(k)] = audit
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	return audits
}

func filenameRetryAssertUnchanged(t *testing.T, s *Store, rec FilenameRecord) {
	t.Helper()
	got, found, err := s.GetFilenameReservation(rec.Origin, rec.EncryptedPath)
	if err != nil || !found || !reflect.DeepEqual(got, rec) {
		t.Fatalf("reservation changed: got=%+v found=%v err=%v", got, found, err)
	}
	got, found, err = s.GetFilenameReservationByOriginal(rec.Origin, rec.OriginalPath, rec.AuthScope, rec.RuleFingerprint)
	if err != nil || !found || !reflect.DeepEqual(got, rec) {
		t.Fatalf("original index changed: got=%+v found=%v err=%v", got, found, err)
	}
}

func filenameRetryAssertReleased(t *testing.T, s *Store, rec FilenameRecord) {
	t.Helper()
	if _, found, err := s.GetFilenameReservation(rec.Origin, rec.EncryptedPath); err != nil || found {
		t.Fatalf("primary remains: found=%v err=%v", found, err)
	}
	if _, found, err := s.GetFilenameReservationByOriginal(rec.Origin, rec.OriginalPath, rec.AuthScope, rec.RuleFingerprint); err != nil || found {
		t.Fatalf("original mapping remains: found=%v err=%v", found, err)
	}
	if _, found, err := s.FindFilenameReservationForRead(rec.Origin, rec.OriginalPath); err != nil || found {
		t.Fatalf("read mapping/cache remains: found=%v err=%v", found, err)
	}
	if err := s.db.View(func(tx *bolt.Tx) error {
		id := filenameKey(rec.Origin, rec.EncryptedPath)
		for _, entry := range []struct{ bucket, key []byte }{
			{filenameReservations, id},
			{filenameOriginalIndex, filenameKey(rec.Origin, rec.OriginalPath, rec.AuthScope, rec.RuleFingerprint)},
			{filenameReadIndex, filenameCandidateKey(rec, id)},
			{filenameRecoveries, id},
		} {
			if b := tx.Bucket(entry.bucket); b != nil && b.Get(entry.key) != nil {
				t.Errorf("released key remains in %s", entry.bucket)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestReleaseFailedFilenameRejectsStaleAudit(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*FilenameRecord)
	}{
		{"origin", func(r *FilenameRecord) { r.Origin = "https://other.example" }},
		{"encrypted-path", func(r *FilenameRecord) { r.EncryptedPath = "/enc/other.bin" }},
		{"original-path", func(r *FilenameRecord) { r.OriginalPath = "/enc/other.mp4" }},
		{"display-name", func(r *FilenameRecord) { r.DisplayName += ".changed" }},
		{"rule", func(r *FilenameRecord) { r.RuleFingerprint = strings.Repeat("c", 64) }},
		{"auth", func(r *FilenameRecord) { r.AuthScope = strings.Repeat("c", 64) }},
		{"size", func(r *FilenameRecord) { r.CiphertextSize++ }},
		{"token", func(r *FilenameRecord) { r.Token = strings.Repeat("0", 32) }},
		{"empty-token", func(r *FilenameRecord) { r.Token = "" }},
		{"status", func(r *FilenameRecord) { r.Status = FilenamePending }},
		{"created-at", func(r *FilenameRecord) { r.CreatedAt = r.CreatedAt.Add(time.Nanosecond) }},
		{"updated-at", func(r *FilenameRecord) { r.UpdatedAt = r.UpdatedAt.Add(time.Nanosecond) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := filenameTestStore(t)
			rec := filenameRetryFailedRecord(t, s, filenameTestRecord())
			expected := rec
			tc.change(&expected)
			if err := s.ReleaseFailedFilename(expected); !errors.Is(err, ErrFilenameRetryConflict) {
				t.Fatalf("stale audit accepted: %v", err)
			}
			filenameRetryAssertUnchanged(t, s, rec)
			if audits := filenameRetryAudits(t, s); len(audits) != 0 {
				t.Fatalf("conflict archived an audit: %+v", audits)
			}
		})
	}
}

func TestReleaseFailedFilenameRequiresFailedAndMinimumAge(t *testing.T) {
	if FilenameRetryMinAge != 10*time.Minute {
		t.Fatalf("retry minimum age=%v", FilenameRetryMinAge)
	}
	for _, tc := range []struct {
		name   string
		change func(*FilenameRecord)
	}{
		{"pending", func(r *FilenameRecord) { r.Status = FilenamePending }},
		{"complete", func(r *FilenameRecord) { r.Status = FilenameComplete }},
		{"unknown-status", func(r *FilenameRecord) { r.Status = "unknown" }},
		{"missing-updated-at", func(r *FilenameRecord) { r.UpdatedAt = time.Time{} }},
		{"future-updated-at", func(r *FilenameRecord) { r.UpdatedAt = time.Now().UTC().Add(time.Hour) }},
		{"young-failure", func(r *FilenameRecord) { r.UpdatedAt = time.Now().UTC().Add(-FilenameRetryMinAge + time.Minute) }},
		{"old-created-recent-failure", func(r *FilenameRecord) {
			r.CreatedAt = time.Now().UTC().Add(-24 * time.Hour)
			r.UpdatedAt = time.Now().UTC().Add(-time.Minute)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := filenameTestStore(t)
			rec := filenameRetryFailedRecord(t, s, filenameTestRecord())
			tc.change(&rec)
			filenameRetryWriteRecord(t, s, rec)
			if err := s.ReleaseFailedFilename(rec); !errors.Is(err, ErrFilenameRetryConflict) {
				t.Fatalf("ineligible audit accepted: %v", err)
			}
			filenameRetryAssertUnchanged(t, s, rec)
			if audits := filenameRetryAudits(t, s); len(audits) != 0 {
				t.Fatal("ineligible audit archived")
			}
		})
	}
	t.Run("minimum-age-reached", func(t *testing.T) {
		s := filenameTestStore(t)
		rec := filenameRetryFailedRecord(t, s, filenameTestRecord())
		rec.UpdatedAt = time.Now().UTC().Add(-FilenameRetryMinAge)
		filenameRetryWriteRecord(t, s, rec)
		if err := s.ReleaseFailedFilename(rec); err != nil {
			t.Fatalf("minimum age rejected: %v", err)
		}
		filenameRetryAssertReleased(t, s, rec)
	})
}

func TestReleaseFailedFilenameRejectsMissingAndUnavailable(t *testing.T) {
	s := filenameTestStore(t)
	rec := filenameTestRecord()
	rec.Status, rec.Token = FilenameFailed, strings.Repeat("a", 32)
	if err := s.ReleaseFailedFilename(rec); !errors.Is(err, ErrFilenameRetryConflict) {
		t.Fatalf("missing reservation: %v", err)
	}
	for _, unavailable := range []*Store{nil, {}} {
		if err := unavailable.ReleaseFailedFilename(rec); err == nil {
			t.Fatal("unavailable store permitted release")
		}
	}
}

func filenameRetryAssertAliasReleased(t *testing.T, s *Store, alias VerifiedMediaAlias) {
	t.Helper()
	for _, entry := range []struct{ bucket, key []byte }{
		{verifiedMediaAliases, filenameKey(alias.Origin, alias.EncryptedPath, alias.AuthScope, alias.RuleFingerprint)},
		{verifiedMediaReverse, filenameKey(alias.Origin, alias.DisplayPath, alias.AuthScope, alias.RuleFingerprint)},
	} {
		raw, err := s.Get(entry.bucket, string(entry.key))
		if err != nil || raw != nil {
			t.Fatalf("released alias remains in %s: %q err=%v", entry.bucket, raw, err)
		}
	}
}

func TestReleaseFailedFilenameDurabilityCacheAndOldFinishCAS(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	rec := filenameRetryFailedRecord(t, s, filenameTestRecord())
	recovery := filenameRetryRecovery(t, s, rec, strings.Repeat("c", 64))
	if err := s.PutVerifiedMediaAlias(recovery.Evidence); err != nil {
		t.Fatal(err)
	}
	// Warm the positive read cache; release must invalidate it before returning.
	if got, found, err := s.FindFilenameReservationForRead(rec.Origin, rec.OriginalPath); err != nil || !found || !reflect.DeepEqual(got, rec) {
		t.Fatalf("warm read: got=%+v found=%v err=%v", got, found, err)
	}
	writes := s.WriteTxnCount()
	before := time.Now().UTC()
	if err := s.ReleaseFailedFilename(rec); err != nil {
		t.Fatal(err)
	}
	after := time.Now().UTC()
	if s.WriteTxnCount()-writes != 1 {
		t.Fatal("release did not use one store update")
	}
	filenameRetryAssertReleased(t, s, rec)
	filenameRetryAssertAliasReleased(t, s, recovery.Evidence)
	audits := filenameRetryAudits(t, s)
	audit, found := audits[FilenameAuditDigest(rec)]
	if !found || len(audits) != 1 || !reflect.DeepEqual(audit.Record, rec) || audit.ReleasedAt.Before(before) || audit.ReleasedAt.After(after) {
		t.Fatalf("incomplete archived audit: %+v", audits)
	}
	if err := s.ReleaseFailedFilename(rec); !errors.Is(err, ErrFilenameRetryConflict) {
		t.Fatalf("repeated release: %v", err)
	}
	if err := s.FinishFilenameReservation(rec.Origin, rec.EncryptedPath, rec.Token, FilenameComplete); !errors.Is(err, ErrFilenameTokenMismatch) {
		t.Fatalf("released token finished: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	filenameRetryAssertReleased(t, s, rec)
	filenameRetryAssertAliasReleased(t, s, recovery.Evidence)
	if reopened := filenameRetryAudits(t, s); !reflect.DeepEqual(reopened, audits) {
		t.Fatalf("audit changed on restart: %+v", reopened)
	}
	// Both physical and original claims were removed, so an identical new upload
	// is permitted, but its token cannot be finished or released by the old one.
	next, err := s.ReserveFilename(filenameTestRecord())
	if err != nil {
		t.Fatal(err)
	}
	if next.Token == rec.Token {
		t.Fatal("new reservation reused released token")
	}
	for _, status := range []string{FilenameComplete, FilenameFailed} {
		if err := s.FinishFilenameReservation(rec.Origin, rec.EncryptedPath, rec.Token, status); !errors.Is(err, ErrFilenameTokenMismatch) {
			t.Fatalf("old finish status=%s: %v", status, err)
		}
	}
	if err := s.ReleaseFailedFilename(rec); !errors.Is(err, ErrFilenameRetryConflict) {
		t.Fatalf("old release deleted new claim: %v", err)
	}
	filenameRetryAssertUnchanged(t, s, next)
	if err := s.FinishFilenameReservation(next.Origin, next.EncryptedPath, next.Token, FilenameFailed); err != nil {
		t.Fatal(err)
	}
	next, _, err = s.GetFilenameReservation(next.Origin, next.EncryptedPath)
	if err != nil {
		t.Fatal(err)
	}
	next.CreatedAt = time.Now().UTC().Add(-3 * FilenameRetryMinAge)
	next.UpdatedAt = time.Now().UTC().Add(-2 * FilenameRetryMinAge)
	filenameRetryWriteRecord(t, s, next)
	if err := s.ReleaseFailedFilename(rec); !errors.Is(err, ErrFilenameRetryConflict) {
		t.Fatalf("old audit released a different aged failed claim: %v", err)
	}
	filenameRetryAssertUnchanged(t, s, next)
	if err := s.ReleaseFailedFilename(next); err != nil {
		t.Fatal(err)
	}
	audits = filenameRetryAudits(t, s)
	if len(audits) != 2 || !reflect.DeepEqual(audits[FilenameAuditDigest(rec)], audit) || !reflect.DeepEqual(audits[FilenameAuditDigest(next)].Record, next) {
		t.Fatalf("repeated retry replaced prior audit: %+v", audits)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	filenameRetryAssertReleased(t, s, next)
	if reopened := filenameRetryAudits(t, s); !reflect.DeepEqual(reopened, audits) {
		t.Fatal("retry audit history did not survive restart")
	}
}

func filenameRetryRecovery(t *testing.T, s *Store, rec FilenameRecord, auth string) FilenameRecovery {
	t.Helper()
	evidence := filenameTestAlias()
	evidence.Origin, evidence.EncryptedPath, evidence.DisplayPath = rec.Origin, rec.EncryptedPath, rec.OriginalPath
	evidence.AuthScope, evidence.RuleFingerprint, evidence.CiphertextSize = auth, rec.RuleFingerprint, rec.CiphertextSize
	recovery := FilenameRecovery{AuditDigest: FilenameAuditDigest(rec), PrefixSHA256: strings.Repeat("c", 64), Evidence: evidence}
	if err := s.PutFilenameRecovery(rec, recovery); err != nil {
		t.Fatal(err)
	}
	return recovery
}

func TestReleaseFailedFilenameInvalidatesOnlyTargetRecoveryAndAliases(t *testing.T) {
	s := filenameTestStore(t)
	rec := filenameRetryFailedRecord(t, s, filenameTestRecord())
	targetRecovery := filenameRetryRecovery(t, s, rec, strings.Repeat("c", 64))
	other := filenameTestRecord()
	other.EncryptedPath, other.OriginalPath = "/enc/other.bin", "/enc/other original.mp4"
	other = filenameRetryFailedRecord(t, s, other)
	otherRecovery := filenameRetryRecovery(t, s, other, other.AuthScope)

	// A sibling has the same original path, but a separate scoped reverse claim.
	sibling := filenameTestRecord()
	sibling.EncryptedPath, sibling.AuthScope = "/enc/sibling.bin", strings.Repeat("e", 64)
	sibling, err := s.ReserveFilename(sibling)
	if err != nil {
		t.Fatal(err)
	}
	targets := []VerifiedMediaAlias{targetRecovery.Evidence, targetRecovery.Evidence, targetRecovery.Evidence}
	targets[1].AuthScope, targets[1].DisplayPath = rec.AuthScope, "/enc/different display.mp4"
	targets[2].AuthScope, targets[2].RuleFingerprint, targets[2].DisplayPath = strings.Repeat("d", 64), strings.Repeat("f", 64), "/enc/different rule.mp4"
	kept := []VerifiedMediaAlias{otherRecovery.Evidence, targetRecovery.Evidence, targetRecovery.Evidence}
	kept[1].Origin = "https://other.example"
	kept[2].EncryptedPath, kept[2].AuthScope = sibling.EncryptedPath, sibling.AuthScope
	for _, alias := range append(targets, kept...) {
		if err := s.PutVerifiedMediaAlias(alias); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.ReleaseFailedFilename(rec); err != nil {
		t.Fatal(err)
	}
	if _, found, err := s.GetFilenameRecovery(rec); err != nil || found {
		t.Fatalf("target recovery remains: found=%v err=%v", found, err)
	}
	if recovery, found, err := s.GetFilenameRecovery(other); err != nil || !found || !reflect.DeepEqual(recovery, otherRecovery) {
		t.Fatalf("other recovery changed: got=%+v found=%v err=%v", recovery, found, err)
	}
	filenameRetryAssertUnchanged(t, s, other)
	filenameRetryAssertUnchanged(t, s, sibling)
	if got, found, err := s.FindFilenameReservationForRead(rec.Origin, rec.OriginalPath); err != nil || !found || !reflect.DeepEqual(got, sibling) {
		t.Fatalf("sibling read candidate lost: got=%+v found=%v err=%v", got, found, err)
	}
	for _, alias := range targets {
		if _, found, err := s.GetVerifiedMediaAlias(alias.Origin, alias.EncryptedPath, alias.AuthScope, alias.RuleFingerprint, 0); err != nil || found {
			t.Fatalf("target alias remains: %+v found=%v err=%v", alias, found, err)
		}
		if _, found, err := s.GetVerifiedMediaAliasByDisplay(alias.Origin, alias.DisplayPath, alias.AuthScope, alias.RuleFingerprint, 0); err != nil || found {
			t.Fatalf("target reverse alias remains: %+v found=%v err=%v", alias, found, err)
		}
		filenameRetryAssertAliasReleased(t, s, alias)
	}
	for _, alias := range kept {
		got, found, err := s.GetVerifiedMediaAlias(alias.Origin, alias.EncryptedPath, alias.AuthScope, alias.RuleFingerprint, 0)
		if err != nil || !found || !reflect.DeepEqual(got, alias) {
			t.Fatalf("other alias changed: got=%+v found=%v err=%v", got, found, err)
		}
		got, found, err = s.GetVerifiedMediaAliasByDisplay(alias.Origin, alias.DisplayPath, alias.AuthScope, alias.RuleFingerprint, 0)
		if err != nil || !found || !reflect.DeepEqual(got, alias) {
			t.Fatalf("other reverse alias changed: got=%+v found=%v err=%v", got, found, err)
		}
	}
}

func TestReleaseFailedFilenamePreservesReverseKeysOwnedByOthers(t *testing.T) {
	s := filenameTestStore(t)
	rec := filenameRetryFailedRecord(t, s, filenameTestRecord())
	other := filenameTestRecord()
	other.EncryptedPath, other.OriginalPath = "/enc/other.bin", "/enc/other.mp4"
	other, err := s.ReserveFilename(other)
	if err != nil {
		t.Fatal(err)
	}
	alias := filenameTestAlias()
	alias.EncryptedPath, alias.DisplayPath = rec.EncryptedPath, "/enc/not original.mp4"
	otherAlias := alias
	otherAlias.EncryptedPath, otherAlias.DisplayPath = other.EncryptedPath, other.OriginalPath
	for _, a := range []VerifiedMediaAlias{alias, otherAlias} {
		if err := s.PutVerifiedMediaAlias(a); err != nil {
			t.Fatal(err)
		}
	}
	originalKey := filenameKey(rec.Origin, rec.OriginalPath, rec.AuthScope, rec.RuleFingerprint)
	otherID := filenameKey(other.Origin, other.EncryptedPath)
	aliasReverse := filenameKey(alias.Origin, alias.DisplayPath, alias.AuthScope, alias.RuleFingerprint)
	otherAliasID := filenameKey(otherAlias.Origin, otherAlias.EncryptedPath, otherAlias.AuthScope, otherAlias.RuleFingerprint)
	if err := s.Set(filenameOriginalIndex, string(originalKey), otherID); err != nil {
		t.Fatal(err)
	}
	if err := s.Set(verifiedMediaReverse, string(aliasReverse), otherAliasID); err != nil {
		t.Fatal(err)
	}
	if err := s.ReleaseFailedFilename(rec); err != nil {
		t.Fatal(err)
	}
	for _, entry := range []struct{ bucket, key, value []byte }{
		{filenameOriginalIndex, originalKey, otherID},
		{verifiedMediaReverse, aliasReverse, otherAliasID},
	} {
		raw, err := s.Get(entry.bucket, string(entry.key))
		if err != nil || !bytes.Equal(raw, entry.value) {
			t.Fatalf("foreign reverse ownership deleted in %s: %q err=%v", entry.bucket, raw, err)
		}
	}
	filenameRetryAssertUnchanged(t, s, other)
	if got, found, err := s.GetVerifiedMediaAliasByDisplay(otherAlias.Origin, otherAlias.DisplayPath, otherAlias.AuthScope, otherAlias.RuleFingerprint, 0); err != nil || !found || !reflect.DeepEqual(got, otherAlias) {
		t.Fatalf("other alias changed: got=%+v found=%v err=%v", got, found, err)
	}
}

func TestReleaseFailedFilenameRollsBackAuditAndDeletion(t *testing.T) {
	s := filenameTestStore(t)
	rec := filenameRetryFailedRecord(t, s, filenameTestRecord())
	recovery := filenameRetryRecovery(t, s, rec, rec.AuthScope)
	if err := s.PutVerifiedMediaAlias(recovery.Evidence); err != nil {
		t.Fatal(err)
	}
	// A corrupt proof cannot be safely classified. Fail closed after the primary
	// deletion attempt, proving audit, indexes and recovery all roll back too.
	if err := s.Set(verifiedMediaAliases, "corrupt", []byte("{")); err != nil {
		t.Fatal(err)
	}
	if err := s.ReleaseFailedFilename(rec); err == nil {
		t.Fatal("corrupt alias did not abort transaction")
	}
	filenameRetryAssertUnchanged(t, s, rec)
	if got, found, err := s.FindFilenameReservationForRead(rec.Origin, rec.OriginalPath); err != nil || !found || !reflect.DeepEqual(got, rec) {
		t.Fatalf("rollback lost read index: got=%+v found=%v err=%v", got, found, err)
	}
	if got, found, err := s.GetFilenameRecovery(rec); err != nil || !found || !reflect.DeepEqual(got, recovery) {
		t.Fatalf("rollback lost recovery: got=%+v found=%v err=%v", got, found, err)
	}
	if got, found, err := s.GetVerifiedMediaAliasByDisplay(rec.Origin, rec.OriginalPath, rec.AuthScope, rec.RuleFingerprint, 0); err != nil || !found || !reflect.DeepEqual(got, recovery.Evidence) {
		t.Fatalf("rollback lost alias: got=%+v found=%v err=%v", got, found, err)
	}
	if len(filenameRetryAudits(t, s)) != 0 {
		t.Fatal("failed transaction retained retry audit")
	}
}

func TestReleaseFailedFilenameConcurrentCAS(t *testing.T) {
	s := filenameTestStore(t)
	rec := filenameRetryFailedRecord(t, s, filenameTestRecord())
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.ReleaseFailedFilename(rec); err == nil {
				wins.Add(1)
			} else if !errors.Is(err, ErrFilenameRetryConflict) {
				t.Errorf("release: %v", err)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 || len(filenameRetryAudits(t, s)) != 1 {
		t.Fatalf("concurrent releases: wins=%d", wins.Load())
	}
	filenameRetryAssertReleased(t, s, rec)
}
