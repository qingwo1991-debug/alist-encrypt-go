package dao

import (
	"errors"
	"github.com/alist-encrypt-go/internal/storage"
)

func (d *FileDAO) PutVerifiedMediaAlias(rec storage.VerifiedMediaAlias) error {
	if d == nil || d.store == nil {
		return errors.New("verified media alias store unavailable")
	}
	return d.store.PutVerifiedMediaAlias(rec)
}
func (d *FileDAO) GetVerifiedMediaAlias(origin, raw, auth, rule string, size int64) (storage.VerifiedMediaAlias, bool, error) {
	if d == nil || d.store == nil {
		return storage.VerifiedMediaAlias{}, false, errors.New("verified media alias store unavailable")
	}
	return d.store.GetVerifiedMediaAlias(origin, raw, auth, rule, size)
}
func (d *FileDAO) GetVerifiedMediaAliasByDisplay(origin, display, auth, rule string, size int64) (storage.VerifiedMediaAlias, bool, error) {
	if d == nil || d.store == nil {
		return storage.VerifiedMediaAlias{}, false, errors.New("verified media alias store unavailable")
	}
	return d.store.GetVerifiedMediaAliasByDisplay(origin, display, auth, rule, size)
}
