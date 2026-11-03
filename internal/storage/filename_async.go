package storage

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"strings"

	bolt "go.etcd.io/bbolt"
)

var (
	ErrFilenameUploadTaskConflict            = errors.New("filename upload task already bound")
	ErrFilenameUploadTaskReservationMismatch = errors.New("filename upload task reservation mismatch")
	ErrFilenameUploadTaskNotPending          = errors.New("filename upload task reservation is not pending")
	filenameUploadTasks                      = []byte("filename_upload_tasks_v1")
	filenameUploadTaskReservations           = []byte("filename_upload_task_reservations_v1")
)

// FilenameUploadTask is a durable receipt, not a copy of the upstream task or
// request. AuthScope and RuleFingerprint are hashes; credentials, URLs with
// credentials, and upstream task payloads must never be stored here.
type FilenameUploadTask struct {
	Origin, TaskID, EncryptedPath, Token, AuthScope, RuleFingerprint string
}

func validFilenameTaskID(id string) bool {
	return id != "" && strings.TrimSpace(id) == id && !strings.ContainsAny(id, "\x00\r\n\t")
}

func validFilenameUploadTask(rec FilenameUploadTask) bool {
	return validFilenameOrigin(rec.Origin) && validFilenameTaskID(rec.TaskID) &&
		validFilenamePath(rec.EncryptedPath) && rec.Token != "" &&
		validFilenameScope(rec.AuthScope) && validFilenameScope(rec.RuleFingerprint)
}

// filenameUploadTaskReservation checks the primary reservation inside the same
// transaction as the receipt read/write. Neither a stale receipt nor an index
// alone is authority to finalize an upload.
func filenameUploadTaskReservation(tx *bolt.Tx, receipt FilenameUploadTask) (FilenameRecord, error) {
	var rec FilenameRecord
	b := tx.Bucket(filenameReservations)
	if b == nil || b.Get(filenameKey(receipt.Origin, receipt.EncryptedPath)) == nil {
		return rec, ErrFilenameUploadTaskReservationMismatch
	}
	if err := json.Unmarshal(b.Get(filenameKey(receipt.Origin, receipt.EncryptedPath)), &rec); err != nil {
		return FilenameRecord{}, err
	}
	if subtle.ConstantTimeCompare([]byte(rec.Token), []byte(receipt.Token)) != 1 {
		return FilenameRecord{}, ErrFilenameTokenMismatch
	}
	if rec.Origin != receipt.Origin || rec.EncryptedPath != receipt.EncryptedPath || rec.AuthScope != receipt.AuthScope || rec.RuleFingerprint != receipt.RuleFingerprint {
		return FilenameRecord{}, ErrFilenameUploadTaskReservationMismatch
	}
	return rec, nil
}

// BindFilenameUploadTask binds one upstream task to one pending reservation.
// Both uniqueness checks and the reservation check are atomic. It deliberately
// does not change reservation status: a failed upstream task may retry its ID.
func (s *Store) BindFilenameUploadTask(receipt FilenameUploadTask) error {
	if err := s.filenameReady(); err != nil {
		return err
	}
	if !validFilenameUploadTask(receipt) {
		return errors.New("invalid filename upload task receipt")
	}
	return s.update(func(tx *bolt.Tx) error {
		rec, err := filenameUploadTaskReservation(tx, receipt)
		if err != nil {
			return err
		}
		if rec.Status != FilenamePending {
			return ErrFilenameUploadTaskNotPending
		}
		b, err := tx.CreateBucketIfNotExists(filenameUploadTasks)
		if err != nil {
			return err
		}
		idx, err := tx.CreateBucketIfNotExists(filenameUploadTaskReservations)
		if err != nil {
			return err
		}
		key := filenameKey(receipt.Origin, receipt.TaskID, receipt.AuthScope)
		reverse := filenameKey(receipt.Origin, receipt.EncryptedPath, receipt.Token)
		if old := b.Get(key); old != nil {
			var previous FilenameUploadTask
			if err := json.Unmarshal(old, &previous); err != nil {
				return err
			}
			if previous != receipt {
				return ErrFilenameUploadTaskConflict
			}
		}
		if old := idx.Get(reverse); old != nil && !bytes.Equal(old, key) {
			return ErrFilenameUploadTaskConflict
		}
		raw, err := json.Marshal(receipt)
		if err != nil {
			return err
		}
		if err := b.Put(key, raw); err != nil {
			return err
		}
		return idx.Put(reverse, key)
	})
}

// GetFilenameUploadTask is scoped to the current origin and auth identity. A
// missing receipt (including another identity's task) is not found. A persisted
// receipt whose reservation no longer matches is an error and returns no data.
// Completed reservations remain readable for idempotent task status polling.
func (s *Store) GetFilenameUploadTask(origin, taskID, authScope string) (FilenameUploadTask, bool, error) {
	if err := s.filenameReady(); err != nil {
		return FilenameUploadTask{}, false, err
	}
	if !validFilenameOrigin(origin) || !validFilenameTaskID(taskID) || !validFilenameScope(authScope) {
		return FilenameUploadTask{}, false, errors.New("invalid filename upload task lookup")
	}
	var receipt FilenameUploadTask
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(filenameUploadTasks)
		if b == nil {
			return nil
		}
		key := filenameKey(origin, taskID, authScope)
		raw := b.Get(key)
		if raw == nil {
			return nil
		}
		if err := json.Unmarshal(raw, &receipt); err != nil {
			return err
		}
		if !validFilenameUploadTask(receipt) || receipt.Origin != origin || receipt.TaskID != taskID || receipt.AuthScope != authScope {
			return ErrFilenameUploadTaskReservationMismatch
		}
		rec, err := filenameUploadTaskReservation(tx, receipt)
		if err != nil {
			return err
		}
		if rec.Status != FilenamePending && rec.Status != FilenameComplete {
			return ErrFilenameUploadTaskReservationMismatch
		}
		idx := tx.Bucket(filenameUploadTaskReservations)
		if idx == nil || !bytes.Equal(idx.Get(filenameKey(receipt.Origin, receipt.EncryptedPath, receipt.Token)), key) {
			return ErrFilenameUploadTaskReservationMismatch
		}
		found = true
		return nil
	})
	if err != nil || !found {
		return FilenameUploadTask{}, false, err
	}
	return receipt, true, nil
}
