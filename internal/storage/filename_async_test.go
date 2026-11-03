package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func filenameTestUploadTask(t *testing.T, s *Store, record FilenameRecord, taskID string) FilenameUploadTask {
	t.Helper()
	rec, err := s.ReserveFilename(record)
	if err != nil {
		t.Fatal(err)
	}
	return FilenameUploadTask{Origin: rec.Origin, TaskID: taskID, EncryptedPath: rec.EncryptedPath, Token: rec.Token, AuthScope: rec.AuthScope, RuleFingerprint: rec.RuleFingerprint}
}

func TestFilenameUploadTaskDurabilityAndCompletion(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	receipt := filenameTestUploadTask(t, s, filenameTestRecord(), "task-1")
	for i := 0; i < 2; i++ {
		if err := s.BindFilenameUploadTask(receipt); err != nil {
			t.Fatalf("idempotent bind %d: %v", i, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.GetFilenameUploadTask(receipt.Origin, receipt.TaskID, receipt.AuthScope)
	if err != nil || !ok || got != receipt {
		t.Fatalf("reopen: %+v %v %v", got, ok, err)
	}
	rec, ok, err := s.GetFilenameReservation(receipt.Origin, receipt.EncryptedPath)
	if err != nil || !ok || rec.Status != FilenamePending {
		t.Fatalf("bind changed pending reservation: %+v %v %v", rec, ok, err)
	}
	if err := s.FinishFilenameReservation(receipt.Origin, receipt.EncryptedPath, receipt.Token, FilenameComplete); err != nil {
		t.Fatal(err)
	}
	got, ok, err = s.GetFilenameUploadTask(receipt.Origin, receipt.TaskID, receipt.AuthScope)
	if err != nil || !ok || got != receipt {
		t.Fatalf("completed receipt: %+v %v %v", got, ok, err)
	}
	if err := s.BindFilenameUploadTask(receipt); !errors.Is(err, ErrFilenameUploadTaskNotPending) {
		t.Fatalf("bind must require pending: %v", err)
	}
}

func TestFilenameUploadTaskBindingValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*FilenameUploadTask)
		want   error
	}{
		{"token", func(r *FilenameUploadTask) { r.Token = "wrong" }, ErrFilenameTokenMismatch},
		{"auth", func(r *FilenameUploadTask) { r.AuthScope = strings.Repeat("c", 64) }, ErrFilenameUploadTaskReservationMismatch},
		{"rule", func(r *FilenameUploadTask) { r.RuleFingerprint = strings.Repeat("c", 64) }, ErrFilenameUploadTaskReservationMismatch},
		{"origin", func(r *FilenameUploadTask) { r.Origin = "http://other:5244" }, ErrFilenameUploadTaskReservationMismatch},
		{"path", func(r *FilenameUploadTask) { r.EncryptedPath = "/enc/other.bin" }, ErrFilenameUploadTaskReservationMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := filenameTestStore(t)
			receipt := filenameTestUploadTask(t, s, filenameTestRecord(), "task-1")
			bad := receipt
			tc.change(&bad)
			if err := s.BindFilenameUploadTask(bad); !errors.Is(err, tc.want) {
				t.Fatalf("bind: %v; want %v", err, tc.want)
			}
			if err := s.BindFilenameUploadTask(receipt); err != nil {
				t.Fatalf("failed transaction polluted indexes: %v", err)
			}
		})
	}
}

func TestFilenameUploadTaskConflictAndIsolation(t *testing.T) {
	s := filenameTestStore(t)
	r := filenameTestUploadTask(t, s, filenameTestRecord(), "shared-id")
	if err := s.BindFilenameUploadTask(r); err != nil {
		t.Fatal(err)
	}
	other := r
	other.TaskID = "different-id"
	if err := s.BindFilenameUploadTask(other); !errors.Is(err, ErrFilenameUploadTaskConflict) {
		t.Fatalf("same reservation bound twice: %v", err)
	}
	record := filenameTestRecord()
	record.EncryptedPath = "/enc/other.bin"
	record.OriginalPath = "/enc/other original.mp4"
	other = filenameTestUploadTask(t, s, record, r.TaskID)
	if err := s.BindFilenameUploadTask(other); !errors.Is(err, ErrFilenameUploadTaskConflict) {
		t.Fatalf("same task overwritten: %v", err)
	}
	other.TaskID = "unused-id"
	if err := s.BindFilenameUploadTask(other); err != nil {
		t.Fatalf("conflict poisoned reverse index: %v", err)
	}
	for _, scope := range []string{strings.Repeat("c", 64), strings.Repeat("d", 64)} {
		got, ok, err := s.GetFilenameUploadTask(r.Origin, r.TaskID, scope)
		if err != nil || ok || got != (FilenameUploadTask{}) {
			t.Fatalf("cross-auth leak: %+v %v %v", got, ok, err)
		}
	}
	record.EncryptedPath = "/enc/auth.bin"
	record.AuthScope = strings.Repeat("c", 64)
	authReceipt := filenameTestUploadTask(t, s, record, r.TaskID)
	if err := s.BindFilenameUploadTask(authReceipt); err != nil {
		t.Fatalf("task ID must be auth isolated: %v", err)
	}
	record.Origin = "https://other.example"
	originReceipt := filenameTestUploadTask(t, s, record, r.TaskID)
	if err := s.BindFilenameUploadTask(originReceipt); err != nil {
		t.Fatalf("task ID must be origin isolated: %v", err)
	}
	for _, receipt := range []FilenameUploadTask{r, authReceipt, originReceipt} {
		got, ok, err := s.GetFilenameUploadTask(receipt.Origin, receipt.TaskID, receipt.AuthScope)
		if err != nil || !ok || got != receipt {
			t.Fatalf("scoped receipt: %+v %v %v", got, ok, err)
		}
	}
}

func TestFilenameUploadTaskRejectsStaleReservation(t *testing.T) {
	for _, field := range []string{"missing", "token", "auth", "rule", "origin", "path", "failed"} {
		t.Run(field, func(t *testing.T) {
			s := filenameTestStore(t)
			r := filenameTestUploadTask(t, s, filenameTestRecord(), "task-1")
			if err := s.BindFilenameUploadTask(r); err != nil {
				t.Fatal(err)
			}
			rec, _, err := s.GetFilenameReservation(r.Origin, r.EncryptedPath)
			if err != nil {
				t.Fatal(err)
			}
			switch field {
			case "token":
				rec.Token = "changed"
			case "auth":
				rec.AuthScope = strings.Repeat("c", 64)
			case "rule":
				rec.RuleFingerprint = strings.Repeat("c", 64)
			case "origin":
				rec.Origin = "https://other.example"
			case "path":
				rec.EncryptedPath = "/enc/other.bin"
			case "failed":
				rec.Status = FilenameFailed
			}
			err = s.update(func(tx *bolt.Tx) error {
				key := filenameKey(r.Origin, r.EncryptedPath)
				if field == "missing" {
					return tx.Bucket(filenameReservations).Delete(key)
				}
				raw, err := json.Marshal(rec)
				if err != nil {
					return err
				}
				// Simulate corruption/staleness below the normal primary/index guard.
				return tx.Bucket(filenameReservations).Put(key, raw)
			})
			if err != nil {
				t.Fatal(err)
			}
			got, ok, err := s.GetFilenameUploadTask(r.Origin, r.TaskID, r.AuthScope)
			if err == nil || ok || got != (FilenameUploadTask{}) {
				t.Fatalf("stale receipt exposed: %+v %v %v", got, ok, err)
			}
		})
	}
}

func TestFilenameUploadTaskConcurrentUnique(t *testing.T) {
	s := filenameTestStore(t)
	r := filenameTestUploadTask(t, s, filenameTestRecord(), "task")
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			receipt := r
			receipt.TaskID = fmt.Sprintf("task-%d", i)
			if err := s.BindFilenameUploadTask(receipt); err == nil {
				wins.Add(1)
			} else if !errors.Is(err, ErrFilenameUploadTaskConflict) {
				t.Errorf("bind: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("winners=%d", wins.Load())
	}
}
