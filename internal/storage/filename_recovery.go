package storage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	encryption "github.com/alist-encrypt-go/shared/encryptcore"
	bolt "go.etcd.io/bbolt"
)

var filenameRecoveries = []byte("filename_recoveries_v1")

// FilenameRecovery is an additive administrative read binding, never an upload
// completion. The original failed audit and its exclusive write claim survive.
// Evidence describes a bounded decrypted prefix, not full-file authenticity.
type FilenameRecovery struct {
	AuditDigest  string
	PrefixSHA256 string
	Evidence     VerifiedMediaAlias
}

func FilenameAuditDigest(rec FilenameRecord) string {
	raw, _ := json.Marshal(rec)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func validFilenameRecovery(rec FilenameRecord, recovery FilenameRecovery) bool {
	e := recovery.Evidence
	return e.ContentVersion == encryption.ContentVersionV2 && validFilenameScope(recovery.PrefixSHA256) && rec.Status == FilenameFailed && recovery.AuditDigest == FilenameAuditDigest(rec) &&
		e.Origin == rec.Origin && e.EncryptedPath == rec.EncryptedPath && e.DisplayPath == rec.OriginalPath &&
		e.RuleFingerprint == rec.RuleFingerprint && e.CiphertextSize == rec.CiphertextSize && validMediaAlias(e)
}

// PutFilenameRecovery atomically rechecks the failed audit and uniqueness. It
// never updates primary audit bytes, reverse upload indexes or read candidates.
func (s *Store) PutFilenameRecovery(rec FilenameRecord, recovery FilenameRecovery) error {
	if err := s.filenameReady(); err != nil {
		return err
	}
	if !validFilenameRecovery(rec, recovery) {
		return errors.New("invalid filename recovery")
	}
	return s.update(func(tx *bolt.Tx) error {
		b := tx.Bucket(filenameReservations)
		if b == nil {
			return errors.New("missing filename audit")
		}
		id := filenameKey(rec.Origin, rec.EncryptedPath)
		var current FilenameRecord
		if err := json.Unmarshal(b.Get(id), &current); err != nil {
			return err
		}
		if FilenameAuditDigest(current) != recovery.AuditDigest {
			return errors.New("filename audit changed")
		}
		idx := tx.Bucket(filenameReadIndex)
		if idx == nil || !bytes.Equal(idx.Get(filenameReadIndexMarker), []byte{1}) {
			return ErrFilenameReadIndexNotReady
		}
		prefix := filenameKey(rec.Origin, rec.OriginalPath)
		c := idx.Cursor()
		k, _ := c.Seek(prefix)
		if !bytes.Equal(k, filenameCandidateKey(rec, id)) {
			return ErrFilenameReadAmbiguous
		}
		k, _ = c.Next()
		if bytes.HasPrefix(k, prefix) {
			return ErrFilenameReadAmbiguous
		}
		recoveries, err := tx.CreateBucketIfNotExists(filenameRecoveries)
		if err != nil {
			return err
		}
		raw, err := json.Marshal(recovery)
		if err != nil {
			return err
		}
		if old := recoveries.Get(id); old != nil {
			var previous FilenameRecovery
			if err := json.Unmarshal(old, &previous); err != nil {
				return err
			}
			if previous.AuditDigest != recovery.AuditDigest || previous.PrefixSHA256 != recovery.PrefixSHA256 {
				return errors.New("filename recovery conflict")
			}
			// Repeated administrative admission cannot silently replace object identity.
			a, z := previous.Evidence, recovery.Evidence
			if a.ContentVersion != z.ContentVersion || a.EncType != z.EncType || a.PlainSize != z.PlainSize || a.HeaderLen != z.HeaderLen || !bytes.Equal(a.NonceField, z.NonceField) || a.ChunkSize != z.ChunkSize || a.KDFIterations != z.KDFIterations {
				return errors.New("filename recovery object changed")
			}
			return nil
		}
		return recoveries.Put(id, raw)
	})
}

func (s *Store) GetFilenameRecovery(rec FilenameRecord) (FilenameRecovery, bool, error) {
	var recovery FilenameRecovery
	if err := s.filenameReady(); err != nil {
		return recovery, false, err
	}
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(filenameRecoveries)
		if b == nil {
			return nil
		}
		raw := b.Get(filenameKey(rec.Origin, rec.EncryptedPath))
		if raw == nil {
			return nil
		}
		if err := json.Unmarshal(raw, &recovery); err != nil {
			return err
		}
		found = validFilenameRecovery(rec, recovery)
		return nil
	})
	return recovery, found, err
}
