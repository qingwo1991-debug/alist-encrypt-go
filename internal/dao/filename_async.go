package dao

import (
	"errors"

	"github.com/alist-encrypt-go/internal/storage"
)

// BindFilenameUploadTask persists only the credential-free receipt. Missing
// durable storage must never silently discard an asynchronous upload binding.
func (d *FileDAO) BindFilenameUploadTask(receipt storage.FilenameUploadTask) error {
	if d == nil || d.store == nil {
		return errors.New("filename upload task store unavailable")
	}
	return d.store.BindFilenameUploadTask(receipt)
}

func (d *FileDAO) GetFilenameUploadTask(origin, taskID, authScope string) (storage.FilenameUploadTask, bool, error) {
	if d == nil || d.store == nil {
		return storage.FilenameUploadTask{}, false, errors.New("filename upload task store unavailable")
	}
	return d.store.GetFilenameUploadTask(origin, taskID, authScope)
}
