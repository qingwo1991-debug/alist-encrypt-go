package storage

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"time"

	bolt "go.etcd.io/bbolt"
)

// FilenameRetryMinAge is the minimum time a failed reservation must remain
// untouched before an explicit administrative release can permit another upload.
const FilenameRetryMinAge = 10 * time.Minute

var (
	ErrFilenameRetryConflict = errors.New("filename retry audit changed or not eligible")
	filenameRetryAudit       = []byte("filename_retry_audit_v1")
)

// FilenameRetryAudit retains the complete failed reservation after its exclusive
// write claim is released. Releasing never changes the old audit record.
type FilenameRetryAudit struct {
	Record     FilenameRecord `json:"record"`
	ReleasedAt time.Time      `json:"released_at"`
}

// ReleaseFailedFilename atomically compares the entire expected audit, archives
// it, and removes only this physical filename's reservation and derived bindings.
// It does not delete or otherwise modify any remote object.
func (s *Store) ReleaseFailedFilename(expected FilenameRecord) error {
	if err := s.filenameReady(); err != nil {
		return err
	}
	if !validFilenameOrigin(expected.Origin) || !validFilenamePath(expected.EncryptedPath) || expected.Status != FilenameFailed || expected.Token == "" {
		return ErrFilenameRetryConflict
	}
	digest := FilenameAuditDigest(expected)
	return s.update(func(tx *bolt.Tx) error {
		b := tx.Bucket(filenameReservations)
		if b == nil {
			return ErrFilenameRetryConflict
		}
		id := filenameKey(expected.Origin, expected.EncryptedPath)
		raw := b.Get(id)
		if raw == nil {
			return ErrFilenameRetryConflict
		}
		var current FilenameRecord
		if err := json.Unmarshal(raw, &current); err != nil {
			return err
		}
		now := time.Now().UTC()
		if current.Status != FilenameFailed || current.Status != expected.Status || subtle.ConstantTimeCompare([]byte(current.Token), []byte(expected.Token)) != 1 || FilenameAuditDigest(current) != digest || current.UpdatedAt.IsZero() || current.UpdatedAt.After(now.Add(-FilenameRetryMinAge)) {
			return ErrFilenameRetryConflict
		}
		audit, err := tx.CreateBucketIfNotExists(filenameRetryAudit)
		if err != nil {
			return err
		}
		// A previous release is immutable, including its original release time.
		if audit.Get([]byte(digest)) != nil {
			return ErrFilenameRetryConflict
		}
		archived, err := json.Marshal(FilenameRetryAudit{Record: current, ReleasedAt: now})
		if err != nil {
			return err
		}
		if err := audit.Put([]byte(digest), archived); err != nil {
			return err
		}
		if err := putFilenamePrimary(tx, id, nil); err != nil {
			return err
		}
		if idx := tx.Bucket(filenameOriginalIndex); idx != nil {
			reverse := filenameKey(current.Origin, current.OriginalPath, current.AuthScope, current.RuleFingerprint)
			if bytes.Equal(idx.Get(reverse), id) {
				if err := idx.Delete(reverse); err != nil {
					return err
				}
			}
		}
		if recoveries := tx.Bucket(filenameRecoveries); recoveries != nil {
			if err := recoveries.Delete(id); err != nil {
				return err
			}
		}
		return invalidateFilenameRetryAliases(tx, current.Origin, current.EncryptedPath)
	})
}

func invalidateFilenameRetryAliases(tx *bolt.Tx, origin, encryptedPath string) error {
	aliases := tx.Bucket(verifiedMediaAliases)
	if aliases == nil {
		return nil
	}
	// Alias keys include auth and rule, so the same physical object can have
	// several proofs. All become stale when its write claim is released.
	var targets []VerifiedMediaAlias
	if err := aliases.ForEach(func(k, raw []byte) error {
		var alias VerifiedMediaAlias
		if err := json.Unmarshal(raw, &alias); err != nil {
			return err
		}
		if alias.Origin == origin && alias.EncryptedPath == encryptedPath {
			if !bytes.Equal(k, filenameKey(alias.Origin, alias.EncryptedPath, alias.AuthScope, alias.RuleFingerprint)) {
				return errors.New("invalid verified media alias key")
			}
			targets = append(targets, alias)
		}
		return nil
	}); err != nil {
		return err
	}
	reverse := tx.Bucket(verifiedMediaReverse)
	for _, alias := range targets {
		id := filenameKey(alias.Origin, alias.EncryptedPath, alias.AuthScope, alias.RuleFingerprint)
		if reverse != nil {
			key := filenameKey(alias.Origin, alias.DisplayPath, alias.AuthScope, alias.RuleFingerprint)
			if bytes.Equal(reverse.Get(key), id) {
				if err := reverse.Delete(key); err != nil {
					return err
				}
			}
		}
		if err := aliases.Delete(id); err != nil {
			return err
		}
	}
	return nil
}
