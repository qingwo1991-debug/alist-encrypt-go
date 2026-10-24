package dao

import (
	"errors"
	"github.com/alist-encrypt-go/internal/storage"
)

// Filename reservations use the durable local store, independently of ordinary
// mutable file metadata. Missing persistence must never permit a protected write.
func (d *FileDAO) ReserveFilename(record storage.FilenameRecord) (storage.FilenameRecord, error) {
	if d == nil || d.store == nil {
		return storage.FilenameRecord{}, errors.New("filename reservation store unavailable")
	}
	return d.store.ReserveFilename(record)
}
func (d *FileDAO) GetFilenameReservation(origin, raw string) (storage.FilenameRecord, bool, error) {
	if d == nil || d.store == nil {
		return storage.FilenameRecord{}, false, errors.New("filename reservation store unavailable")
	}
	return d.store.GetFilenameReservation(origin, raw)
}
func (d *FileDAO) GetFilenameReservationByOriginal(origin, original, auth, rule string) (storage.FilenameRecord, bool, error) {
	if d == nil || d.store == nil {
		return storage.FilenameRecord{}, false, errors.New("filename reservation store unavailable")
	}
	return d.store.GetFilenameReservationByOriginal(origin, original, auth, rule)
}

// FindFilenameReservationForRead supplies only a candidate raw path. Callers
// must authorize that exact resource using the current request credentials.
func (d *FileDAO) FindFilenameReservationForRead(origin, original string) (storage.FilenameRecord, bool, error) {
	if d == nil || d.store == nil {
		return storage.FilenameRecord{}, false, nil
	}
	return d.store.FindFilenameReservationForRead(origin, original)
}

// ReleaseFailedFilename archives and releases only an unchanged, aged failed
// reservation. Missing local persistence must never allow another protected write.
func (d *FileDAO) ReleaseFailedFilename(expected storage.FilenameRecord) error {
	if d == nil || d.store == nil {
		return errors.New("filename reservation store unavailable")
	}
	return d.store.ReleaseFailedFilename(expected)
}

func (d *FileDAO) FinishFilenameReservation(origin, raw, token, status string) error {
	if d == nil || d.store == nil {
		return errors.New("filename reservation store unavailable")
	}
	return d.store.FinishFilenameReservation(origin, raw, token, status)
}
