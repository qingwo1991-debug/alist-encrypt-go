package storage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestFilenameAuditCorruptionFailsBeforeFiltering(t *testing.T) {
	cases := []struct {
		name   string
		change func(*FilenameRecord)
		key    string
		raw    string
	}{
		{name: "malformed", raw: `{"OriginalPath":"private-corrupt-name",`},
		{name: "null", raw: `null`}, {name: "empty", raw: `{}`},
		{name: "array", raw: `[]`}, {name: "string", raw: `"private-corrupt-name"`},
		{name: "invalid-key", key: "not-a-hash"},
		{name: "mismatched-key", key: strings.Repeat("f", 64)},
		{name: "missing-origin", change: func(r *FilenameRecord) { r.Origin = "" }},
		{name: "missing-created", change: func(r *FilenameRecord) { r.CreatedAt = time.Time{} }},
		{name: "missing-original", change: func(r *FilenameRecord) { r.OriginalPath = "" }},
		{name: "missing-token", change: func(r *FilenameRecord) { r.Token = "" }},
		{name: "missing-status", change: func(r *FilenameRecord) { r.Status = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := filenameTestStore(t)
			rec, err := s.ReserveFilename(filenameTestRecord())
			if err != nil {
				t.Fatal(err)
			}
			if tc.change != nil {
				tc.change(&rec)
			}
			key := filenameKey(rec.Origin, rec.EncryptedPath)
			if tc.key != "" {
				key = []byte(tc.key)
			}
			raw, _ := json.Marshal(rec)
			if tc.raw != "" {
				raw = []byte(tc.raw)
			}
			err = s.update(func(tx *bolt.Tx) error {
				b := tx.Bucket(filenameReservations)
				c := b.Cursor()
				k, _ := c.First()
				if err := b.Delete(k); err != nil {
					return err
				}
				return b.Put(key, raw)
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, prefix := range []string{"/enc", "/filtered-out"} {
				q := FilenameAuditQuery{Origin: "http://alist:5244", Prefix: prefix, From: time.Now().Add(-time.Hour), Until: time.Now().Add(time.Hour), Limit: 1, Names: true}
				page, err := s.FilenameAudit(q)
				if err == nil || err.Error() != "invalid filename audit record" || len(page.Records) != 0 || page.After != "" {
					t.Fatal("corruption must fail with generic error and no partial page/cursor")
				}
			}
		})
	}
}
func TestFilenameAuditInvalidKeyAtScanBudgetFailsSamePage(t *testing.T) {
	s := filenameTestStore(t)
	rec, err := s.ReserveFilename(filenameTestRecord())
	if err != nil {
		t.Fatal(err)
	}
	err = s.update(func(tx *bolt.Tx) error {
		b := tx.Bucket(filenameReservations)
		if err := tx.DeleteBucket(filenameReservations); err != nil {
			return err
		}
		b, err = tx.CreateBucket(filenameReservations)
		if err != nil {
			return err
		}
		records := make(map[string][]byte, 1000)
		keys := make([]string, 0, 1000)
		for i := 0; i < 1000; i++ {
			r := rec
			r.EncryptedPath = fmt.Sprintf("/enc/%04d.bin", i)
			k := string(filenameKey(r.Origin, r.EncryptedPath))
			raw, _ := json.Marshal(r)
			records[k] = raw
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys[:999] {
			if err := b.Put([]byte(k), records[k]); err != nil {
				return err
			}
		}
		// This lexically last invalid key is the 1000th scanned record, exactly
		// where the old implementation returned an unusable continuation.
		raw, _ := json.Marshal(rec)
		if err := b.Put([]byte("z-invalid-key"), raw); err != nil {
			return err
		}
		return b.Put([]byte("zz-later-key"), raw)
	})
	if err != nil {
		t.Fatal(err)
	}
	q := FilenameAuditQuery{Origin: rec.Origin, Prefix: "/filtered-out", From: rec.CreatedAt.Add(-time.Hour), Until: rec.CreatedAt.Add(time.Hour), Limit: 1}
	p, err := s.FilenameAudit(q)
	if err == nil || err.Error() != "invalid filename audit record" || p.After != "" || len(p.Records) != 0 {
		t.Fatal("scan-budget corruption must fail this page without continuation")
	}
}

func TestFilenameAuditMissingPrimaryWithReverseFails(t *testing.T) {
	s := filenameTestStore(t)
	now := time.Now()
	q := FilenameAuditQuery{Origin: "http://alist:5244", Prefix: "/", From: now.Add(-time.Hour), Until: now.Add(time.Hour), Limit: 1}
	if p, err := s.FilenameAudit(q); err != nil || len(p.Records) != 0 {
		t.Fatal("pristine database must be empty")
	}
	if _, err := s.ReserveFilename(filenameTestRecord()); err != nil {
		t.Fatal(err)
	}
	if err := s.update(func(tx *bolt.Tx) error { return tx.DeleteBucket(filenameReservations) }); err != nil {
		t.Fatal(err)
	}
	if _, err := s.FilenameAudit(q); err == nil || err.Error() != "invalid filename audit record" {
		t.Fatal("orphan reverse bucket must fail closed")
	}
}

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
