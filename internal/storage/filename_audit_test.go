package storage

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestFilenameAuditNamesBoundsAndDryRunConservation(t *testing.T) {
	s := filenameTestStore(t)
	rec, err := s.ReserveFilename(filenameTestRecord())
	if err != nil {
		t.Fatal(err)
	}
	q := FilenameAuditQuery{Origin: rec.Origin, Prefix: "/enc", From: rec.CreatedAt.Add(-time.Hour), Until: rec.CreatedAt.Add(time.Hour), Limit: 1}
	page, err := s.FilenameAudit(q)
	if err != nil || len(page.Records) != 1 {
		t.Fatalf("page %+v %v", page, err)
	}
	raw, _ := json.Marshal(page)
	for _, secret := range []string{rec.OriginalPath, rec.Token, rec.AuthScope, rec.RuleFingerprint, "OriginalPath", "Token"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("secret in JSON: %s", raw)
		}
	}
	if page.Records[0].LocalInvariant != "ok" {
		t.Fatal(page)
	}
	q.Names = true
	page, err = s.FilenameAudit(q)
	if err != nil || page.Records[0].OriginalPath != rec.OriginalPath {
		t.Fatalf("names %+v %v", page, err)
	}
	check := FilenameCheck{OpID: strings.Repeat("a", 32), At: time.Now(), CallerDigest: strings.Repeat("b", 64), QueryDigest: strings.Repeat("c", 64), Checked: 1, Remote: "unknown"}
	if err = s.AppendFilenameCheck(check); err != nil {
		t.Fatal(err)
	}
	if err = s.AppendFilenameCheck(check); err == nil {
		t.Fatal("op ID overwritten")
	}
	got, ok, err := s.GetFilenameReservation(rec.Origin, rec.EncryptedPath)
	if err != nil || !ok || got != rec {
		t.Fatalf("mutated reservation %+v %v", got, err)
	}
	if _, err = s.ReserveFilename(filenameTestRecord()); err != ErrFilenameReserved {
		t.Fatalf("occupancy released: %v", err)
	}
	q.Limit = 0
	if _, err = s.FilenameAudit(q); err == nil {
		t.Fatal("unbounded query accepted")
	}
}
func TestFilenameAuditDuplicateReverseInvariantAndPaging(t *testing.T) {
	s := filenameTestStore(t)
	rec, err := s.ReserveFilename(filenameTestRecord())
	if err != nil {
		t.Fatal(err)
	}
	duplicate := rec
	duplicate.EncryptedPath = "/enc/other.bin"
	// Simulate historical/manual corruption: two physical records for one original.
	err = s.update(func(tx *bolt.Tx) error {
		raw, _ := json.Marshal(duplicate)
		return tx.Bucket(filenameReservations).Put(filenameKey(duplicate.Origin, duplicate.EncryptedPath), raw)
	})
	if err != nil {
		t.Fatal(err)
	}
	q := FilenameAuditQuery{Origin: rec.Origin, Prefix: "/enc", From: rec.CreatedAt.Add(-time.Hour), Until: rec.CreatedAt.Add(time.Hour), Limit: 1}
	count, violations := 0, 0
	for {
		p, e := s.FilenameAudit(q)
		if e != nil {
			t.Fatal(e)
		}
		for _, r := range p.Records {
			count++
			if r.LocalInvariant == "violation" {
				violations++
			}
		}
		if p.After == "" {
			break
		}
		q.After = p.After
	}
	if count != 2 || violations != 1 {
		t.Fatalf("count=%d violations=%d", count, violations)
	}
}
