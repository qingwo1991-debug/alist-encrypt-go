package dao

import (
	"errors"
	"github.com/alist-encrypt-go/internal/storage"
)

func (d *FileDAO) PutFilenameRecovery(rec storage.FilenameRecord, recovery storage.FilenameRecovery) error {
	if d == nil || d.store == nil {
		return errors.New("filename storage unavailable")
	}
	return d.store.PutFilenameRecovery(rec, recovery)
}
func (d *FileDAO) GetFilenameRecovery(rec storage.FilenameRecord) (storage.FilenameRecovery, bool, error) {
	if d == nil || d.store == nil {
		return storage.FilenameRecovery{}, false, errors.New("filename storage unavailable")
	}
	return d.store.GetFilenameRecovery(rec)
}
