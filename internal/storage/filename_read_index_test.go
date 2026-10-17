package storage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// Real serialized primary records, inserted in one fixture transaction as an
// old binary would do. Sorting is Bolt's actual hashed primary ID ordering.
func filenameReadFixture(tb testing.TB, n int) (*Store, FilenameRecord, FilenameRecord, FilenameRecord) {
	tb.Helper()
	s, err := NewStore(tb.TempDir())
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { s.Close() })
	var head, tail, ambiguous FilenameRecord
	err = s.update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(filenameReservations)
		if err != nil {
			return err
		}
		for i := 0; i < n; i++ {
			rec := filenameTestRecord()
			rec.EncryptedPath = fmt.Sprintf("/enc/%08d.bin", i)
			rec.OriginalPath = fmt.Sprintf("/enc/%08d original.mp4", i)
			rec.Status = FilenameComplete
			if i < 2 {
				rec.OriginalPath = "/enc/ambiguous.mp4"
				ambiguous = rec
			}
			raw, _ := json.Marshal(rec)
			if err := b.Put(filenameKey(rec.Origin, rec.EncryptedPath), raw); err != nil {
				return err
			}
		}
		c := b.Cursor()
		// Choose true first/last unambiguous primary candidates, not insertion order.
		for k, v := c.First(); k != nil; k, v = c.Next() {
			json.Unmarshal(v, &head)
			if head.OriginalPath != ambiguous.OriginalPath {
				break
			}
		}
		for k, v := c.Last(); k != nil; k, v = c.Prev() {
			json.Unmarshal(v, &tail)
			if tail.OriginalPath != ambiguous.OriginalPath {
				break
			}
		}
		return nil
	})
	if err != nil {
		tb.Fatal(err)
	}
	if err := s.RebuildFilenameReadIndex(); err != nil {
		tb.Fatal(err)
	}
	return s, head, tail, ambiguous
}

func TestFilenameReadIndexScales(t *testing.T) {
	for _, n := range []int{1000, 10000, 100000} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			s, head, tail, amb := filenameReadFixture(t, n)
			progress := s.FilenameReadIndexStatus()
			if progress.State != FilenameReadIndexReady || progress.Scanned != uint64(n) || progress.Total != uint64(n) {
				t.Fatalf("progress=%+v", progress)
			}
			writes := s.WriteTxnCount()
			for _, rec := range []FilenameRecord{head, tail} {
				before := s.FilenameReadTxnCount()
				for i := 0; i < 10; i++ {
					got, ok, err := s.FindFilenameReservationForRead(rec.Origin, rec.OriginalPath)
					if err != nil || !ok || got.EncryptedPath != rec.EncryptedPath {
						t.Fatalf("lookup: %v %v %+v", err, ok, got)
					}
				}
				if got := s.FilenameReadTxnCount() - before; got != 1 {
					t.Fatalf("hot hit transactions=%d", got)
				}
			}
			before := s.FilenameReadTxnCount()
			for i := 0; i < 10; i++ {
				_, ok, err := s.FindFilenameReservationForRead(head.Origin, "/missing")
				if err != nil || ok {
					t.Fatalf("miss=%v %v", ok, err)
				}
			}
			if got := s.FilenameReadTxnCount() - before; got != 1 {
				t.Fatalf("hot negative transactions=%d", got)
			}
			for i := 0; i < 3; i++ {
				_, ok, err := s.FindFilenameReservationForRead(amb.Origin, amb.OriginalPath)
				if !errors.Is(err, ErrFilenameReadAmbiguous) || ok {
					t.Fatalf("ambiguity=%v %v", ok, err)
				}
			}
			if s.WriteTxnCount() != writes {
				t.Fatal("lookup wrote database")
			}
		})
	}
}

func TestFilenameReadIndexReopenOldWriterAndAuditUnchanged(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := s.ReserveFilename(filenameTestRecord())
	if err != nil {
		t.Fatal(err)
	}
	id := filenameKey(rec.Origin, rec.EncryptedPath)
	before, err := s.Get(filenameReservations, string(id))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RebuildFilenameReadIndex(); err != nil {
		t.Fatal(err)
	}
	after, _ := s.Get(filenameReservations, string(id))
	if !bytes.Equal(before, after) {
		t.Fatal("rebuild rewrote audit")
	}
	s.Close()
	db, err := bolt.Open(filepath.Join(dir, "alist-encrypt.db"), 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate rollback binary changing primary while leaving a READY old index.
	rec.OriginalPath = "/enc/literal%2f.mp4"
	raw, _ := json.Marshal(rec)
	if err := db.Update(func(tx *bolt.Tx) error { return tx.Bucket(filenameReservations).Put(id, raw) }); err != nil {
		t.Fatal(err)
	}
	db.Close()
	s, err = NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, ok, err := s.FindFilenameReservationForRead(rec.Origin, "/enc/long original.mp4"); err != nil || ok {
		t.Fatalf("old mapping: %v %v", ok, err)
	}
	if got, ok, err := s.FindFilenameReservationForRead(rec.Origin, rec.OriginalPath); err != nil || !ok || got.OriginalPath != rec.OriginalPath {
		t.Fatalf("rollback new mapping: %+v %v %v", got, ok, err)
	}
	if _, ok, err := s.FindFilenameReservationForRead(rec.Origin, "/enc/literal/.mp4"); err != nil || ok {
		t.Fatal("literal percent decoded")
	}
}

func TestFilenameReadIndexCacheMutationAndFailClosed(t *testing.T) {
	s := filenameTestStore(t)
	rec := filenameTestRecord()
	if _, ok, err := s.FindFilenameReservationForRead(rec.Origin, rec.OriginalPath); err != nil || ok {
		t.Fatal(err)
	}
	rec, err := s.ReserveFilename(rec)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok, err := s.FindFilenameReservationForRead(rec.Origin, rec.OriginalPath); err != nil || !ok || got.Status != FilenamePending {
		t.Fatal("negative cache survived reserve")
	}
	if err := s.FinishFilenameReservation(rec.Origin, rec.EncryptedPath, rec.Token, FilenameComplete); err != nil {
		t.Fatal(err)
	}
	if got, ok, err := s.FindFilenameReservationForRead(rec.Origin, rec.OriginalPath); err != nil || !ok || got.Status != FilenameComplete {
		t.Fatal("positive cache survived finish")
	}
	other := rec
	other.EncryptedPath = "/enc/other.bin"
	other.AuthScope = fmt.Sprintf("%064x", 2)
	other, err = s.ReserveFilename(other)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.FindFilenameReservationForRead(rec.Origin, rec.OriginalPath); ok || !errors.Is(err, ErrFilenameReadAmbiguous) {
		t.Fatal("cached unique survived ambiguity")
	}
	if err := s.Delete(filenameReservations, string(filenameKey(other.Origin, other.EncryptedPath))); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.FindFilenameReservationForRead(rec.Origin, rec.OriginalPath); err != nil || !ok {
		t.Fatalf("delete membership: %v %v", ok, err)
	}
	if err := s.update(func(tx *bolt.Tx) error { return tx.DeleteBucket(filenameReadIndex) }); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.FindFilenameReservationForRead(rec.Origin, rec.OriginalPath); ok || !errors.Is(err, ErrFilenameReadIndexNotReady) {
		t.Fatalf("corruption not closed: %v %v", ok, err)
	}
	if s.FilenameReadIndexStatus().State != FilenameReadIndexRebuild {
		t.Fatal("rebuild status missing")
	}
	if err := s.RebuildFilenameReadIndex(); err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{FilenameReadIndexNotReady, FilenameReadIndexBuilding, FilenameReadIndexRebuild} {
		s.setFilenameReadState(state)
		before := s.FilenameReadTxnCount()
		if _, ok, err := s.FindFilenameReservationForRead(rec.Origin, rec.OriginalPath); ok || !errors.Is(err, ErrFilenameReadIndexNotReady) {
			t.Fatalf("state %s: %v %v", state, ok, err)
		}
		if s.FilenameReadTxnCount() != before {
			t.Fatal("unready lookup touched Bolt")
		}
	}
}

func TestFilenameReadIndexConcurrentFinish(t *testing.T) {
	s := filenameTestStore(t)
	rec, err := s.ReserveFilename(filenameTestRecord())
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_, ok, err := s.FindFilenameReservationForRead(rec.Origin, rec.OriginalPath)
				if err != nil || !ok {
					t.Errorf("read=%v %v", ok, err)
				}
			}
		}()
	}
	if err := s.FinishFilenameReservation(rec.Origin, rec.EncryptedPath, rec.Token, FilenameFailed); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if got, ok, err := s.FindFilenameReservationForRead(rec.Origin, rec.OriginalPath); err != nil || !ok || got.Status != FilenameFailed {
		t.Fatal("stale finalized state")
	}
}

func BenchmarkFilenameReadIndex(b *testing.B) {
	for _, n := range []int{1000, 10000, 100000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			s, head, tail, amb := filenameReadFixture(b, n)
			for _, tc := range []struct {
				name, path string
				found      bool
				amb        bool
			}{{"head", head.OriginalPath, true, false}, {"tail", tail.OriginalPath, true, false}, {"miss", "/missing", false, false}, {"ambiguity", amb.OriginalPath, false, true}} {
				b.Run(tc.name, func(b *testing.B) {
					s.FindFilenameReservationForRead(head.Origin, tc.path)
					txns, writes := s.FilenameReadTxnCount(), s.WriteTxnCount()
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						_, ok, err := s.FindFilenameReservationForRead(head.Origin, tc.path)
						if ok != tc.found || (tc.amb && !errors.Is(err, ErrFilenameReadAmbiguous)) || (!tc.amb && err != nil) {
							b.Fatal(ok, err)
						}
					}
					b.StopTimer()
					b.ReportMetric(float64(s.FilenameReadTxnCount()-txns)/float64(b.N), "read-tx/op")
					if s.WriteTxnCount() != writes {
						b.Fatal("hot lookup wrote")
					}
				})
			}
		})
	}
}
