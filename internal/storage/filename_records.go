package storage

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/url"
	"path"
	"strings"
	"time"

	encryption "github.com/alist-encrypt-go/shared/encryptcore"
	bolt "go.etcd.io/bbolt"
)

const (
	FilenamePending              = "pending"
	FilenameComplete             = "complete"
	FilenameFailed               = "failed"
	VerifiedMediaAliasProvenance = "verified-video-signature"
)

var (
	ErrFilenameReserved      = errors.New("physical filename already reserved")
	ErrFilenameTokenMismatch = errors.New("filename reservation token mismatch")
	ErrMediaAliasConflict    = errors.New("verified media display alias already occupied")
	filenameReservations     = []byte("filename_reservations_v1")
	filenameOriginalIndex    = []byte("filename_original_index_v1")
	verifiedMediaAliases     = []byte("verified_media_aliases_v1")
	verifiedMediaReverse     = []byte("verified_media_reverse_v1")
)

// FilenameRecord is a durable pre-upload audit record. Failed and completed
// records remain reserved until a future explicit administrative operation.
// These reservations are local to this Bolt store, not distributed MySQL locks.
type FilenameRecord struct {
	Origin          string
	EncryptedPath   string
	OriginalPath    string
	DisplayName     string
	RuleFingerprint string
	AuthScope       string
	CiphertextSize  int64
	Status          string
	Token           string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// VerifiedMediaAlias is admitted only by a caller that has actually verified a
// decrypted video signature. Geometry from a list/import is not provenance.
// Neither download URLs nor credentials belong in this record.
type VerifiedMediaAlias struct {
	Origin          string
	EncryptedPath   string
	DisplayPath     string
	AuthScope       string
	RuleFingerprint string
	CiphertextSize  int64
	PlainSize       int64
	ContentVersion  int
	HeaderLen       int64
	NonceField      []byte
	ChunkSize       uint32
	KDFIterations   uint32
	EncType         encryption.EncType
	ETag            string
	LastModified    string
	ValidatorScope  string
	VerifiedAt      time.Time
	MIME            string
	Ext             string
	Provenance      string
}

func filenameKey(parts ...string) []byte {
	h := sha256.New()
	for i, p := range parts {
		if i != 0 {
			h.Write([]byte{0})
		}
		h.Write([]byte(p))
	}
	return []byte(hex.EncodeToString(h.Sum(nil)))
}
func validFilenameOrigin(origin string) bool {
	if strings.TrimSpace(origin) != origin || strings.ContainsAny(origin, "\x00\r\n\t ") {
		return false
	}
	u, err := url.Parse(origin)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && u.Path == "" && u.Opaque == ""
}
func validFilenamePath(p string) bool {
	return p != "/" && strings.HasPrefix(p, "/") && path.Clean(p) == p && !strings.ContainsAny(p, "\x00\r\n\\")
}
func validFilenameScope(scope string) bool {
	if len(scope) != 64 {
		return false
	}
	b, err := hex.DecodeString(scope)
	return err == nil && len(b) == 32
}
func (s *Store) filenameReady() error {
	if s == nil || s.db == nil {
		return errors.New("filename storage unavailable")
	}
	return nil
}
func (s *Store) ReserveFilename(rec FilenameRecord) (FilenameRecord, error) {
	if err := s.filenameReady(); err != nil {
		return FilenameRecord{}, err
	}
	if !validFilenameOrigin(rec.Origin) || !validFilenamePath(rec.EncryptedPath) || !validFilenamePath(rec.OriginalPath) || rec.DisplayName == "" || rec.DisplayName == "." || rec.DisplayName == ".." || path.Base(rec.DisplayName) != rec.DisplayName || strings.ContainsAny(rec.DisplayName, "\x00\r\n\\") || !validFilenameScope(rec.AuthScope) || !validFilenameScope(rec.RuleFingerprint) || rec.CiphertextSize < 0 {
		return FilenameRecord{}, errors.New("invalid filename reservation")
	}
	token := make([]byte, 16)
	if _, err := rand.Read(token); err != nil {
		return FilenameRecord{}, err
	}
	rec.Token = hex.EncodeToString(token)
	rec.Status = FilenamePending
	rec.CreatedAt = time.Now().UTC()
	rec.UpdatedAt = rec.CreatedAt
	raw, err := json.Marshal(rec)
	if err != nil {
		return FilenameRecord{}, err
	}
	err = s.update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(filenameReservations)
		if err != nil {
			return err
		}
		idx, err := tx.CreateBucketIfNotExists(filenameOriginalIndex)
		if err != nil {
			return err
		}
		k := filenameKey(rec.Origin, rec.EncryptedPath)
		if b.Get(k) != nil {
			return ErrFilenameReserved
		}
		reverse := filenameKey(rec.Origin, rec.OriginalPath, rec.AuthScope, rec.RuleFingerprint)
		if old := idx.Get(reverse); old != nil {
			return ErrFilenameReserved
		}
		if err = b.Put(k, raw); err != nil {
			return err
		}
		return idx.Put(reverse, k)
	})
	if err != nil {
		return FilenameRecord{}, err
	}
	return rec, nil
}
func (s *Store) GetFilenameReservation(origin, encryptedPath string) (FilenameRecord, bool, error) {
	return s.getFilenameReservation(origin, encryptedPath, "", "", false)
}
func (s *Store) GetFilenameReservationByOriginal(origin, originalPath, authScope, ruleFingerprint string) (FilenameRecord, bool, error) {
	return s.getFilenameReservation(origin, originalPath, authScope, ruleFingerprint, true)
}

// FindFilenameReservationForRead is a private routing hint, NOT authorization.
// It never changes the credential-scoped write index. Legacy stores have only
// hashed indexes, so bound the read-only scan and fail closed on budget overflow
// or ambiguous original paths (including records from different write scopes).
func (s *Store) FindFilenameReservationForRead(origin, original string) (FilenameRecord, bool, error) {
	var result FilenameRecord
	found := false
	if err := s.filenameReady(); err != nil {
		return result, false, err
	}
	if !validFilenameOrigin(origin) || !validFilenamePath(original) {
		return result, false, errors.New("invalid filename read lookup")
	}
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(filenameReservations)
		if b == nil {
			return nil
		}
		c := b.Cursor()
		deadline := time.Now().Add(250 * time.Millisecond)
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if time.Now().After(deadline) {
				return errors.New("filename read lookup budget exceeded")
			}
			var rec FilenameRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			if rec.Origin != origin || rec.OriginalPath != original {
				continue
			}
			if found {
				return errors.New("ambiguous filename read mapping")
			}
			result, found = rec, true
		}
		return nil
	})
	if err != nil {
		return FilenameRecord{}, false, err
	}
	return result, found, nil
}

func (s *Store) getFilenameReservation(origin, p, auth, rule string, reverse bool) (FilenameRecord, bool, error) {
	var rec FilenameRecord
	found := false
	if err := s.filenameReady(); err != nil {
		return rec, false, err
	}
	if !validFilenameOrigin(origin) || !validFilenamePath(p) || (reverse && (!validFilenameScope(auth) || !validFilenameScope(rule))) {
		return rec, false, errors.New("invalid reservation lookup")
	}
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(filenameReservations)
		if b == nil {
			return nil
		}
		k := filenameKey(origin, p)
		if reverse {
			idx := tx.Bucket(filenameOriginalIndex)
			if idx == nil {
				return nil
			}
			k = idx.Get(filenameKey(origin, p, auth, rule))
			if k == nil {
				return nil
			}
		}
		raw := b.Get(k)
		if raw == nil {
			return nil
		}
		if err := json.Unmarshal(raw, &rec); err != nil {
			return err
		}
		found = rec.Origin == origin && ((!reverse && rec.EncryptedPath == p) || (reverse && rec.OriginalPath == p && rec.AuthScope == auth && rec.RuleFingerprint == rule))
		return nil
	})
	return rec, found, err
}
func (s *Store) FinishFilenameReservation(origin, encryptedPath, token, status string) error {
	if err := s.filenameReady(); err != nil {
		return err
	}
	if !validFilenameOrigin(origin) || !validFilenamePath(encryptedPath) || (status != FilenameComplete && status != FilenameFailed) {
		return errors.New("invalid filename completion")
	}
	return s.update(func(tx *bolt.Tx) error {
		b := tx.Bucket(filenameReservations)
		if b == nil {
			return ErrFilenameTokenMismatch
		}
		k := filenameKey(origin, encryptedPath)
		raw := b.Get(k)
		if raw == nil {
			return ErrFilenameTokenMismatch
		}
		var rec FilenameRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			return err
		}
		if token == "" || subtle.ConstantTimeCompare([]byte(rec.Token), []byte(token)) != 1 {
			return ErrFilenameTokenMismatch
		}
		if rec.Status != FilenamePending {
			if rec.Status == status {
				return nil
			}
			return errors.New("filename reservation already finalized")
		}
		rec.Status = status
		rec.UpdatedAt = time.Now().UTC()
		raw, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		return b.Put(k, raw)
	})
}
func validMediaAlias(rec VerifiedMediaAlias) bool {
	if !validFilenameOrigin(rec.Origin) || !validFilenamePath(rec.EncryptedPath) || !validFilenamePath(rec.DisplayPath) || !validFilenameScope(rec.AuthScope) || !validFilenameScope(rec.RuleFingerprint) || rec.Provenance != VerifiedMediaAliasProvenance || rec.VerifiedAt.IsZero() || rec.VerifiedAt.After(time.Now().Add(time.Minute)) {
		return false
	}
	mime := map[string]string{".mp4": "video/mp4", ".mkv": "video/x-matroska", ".webm": "video/webm", ".avi": "video/x-msvideo", ".mov": "video/quicktime", ".mpeg": "video/mpeg", ".ts": "video/mp2t", ".flv": "video/x-flv"}
	if mime[rec.Ext] == "" || mime[rec.Ext] != rec.MIME || path.Ext(rec.DisplayPath) != rec.Ext {
		return false
	}
	m := encryption.ContentMeta{EncType: rec.EncType, Version: rec.ContentVersion, PlainSize: rec.PlainSize, CiphertextSize: rec.CiphertextSize, HeaderLen: rec.HeaderLen, NonceField: rec.NonceField, ChunkSize: rec.ChunkSize, KDFIterations: rec.KDFIterations}
	if m.PlainSize < 0 || m.CiphertextSize <= 0 {
		return false
	}
	switch m.Version {
	case encryption.ContentVersionV1:
		return encryption.IsRegistered(m.EncType) && m.PlainSize > 0 && m.CiphertextSize == m.PlainSize && m.HeaderLen == 0 && len(m.NonceField) == 0 && m.ChunkSize == 0 && m.KDFIterations == 0
	case encryption.ContentVersionV2:
		if m.HeaderLen != encryption.ContentHeaderSize() || len(m.NonceField) != 16 || m.ChunkSize != 0 || m.KDFIterations != 0 || m.PlainSize > math.MaxInt64-m.HeaderLen || m.CiphertextSize != m.PlainSize+m.HeaderLen {
			return false
		}
		_, err := encryption.BuildV2Header(m.EncType, m.PlainSize, m.NonceField)
		return err == nil
	case encryption.ContentVersionV3:
		if m.HeaderLen != encryption.V3HeaderSize || len(m.NonceField) != 16 || m.ChunkSize == 0 || m.ChunkSize > 1<<30 || m.KDFIterations == 0 || m.KDFIterations > 10000000 {
			return false
		}
		chunks := m.PlainSize / int64(m.ChunkSize)
		if m.PlainSize%int64(m.ChunkSize) != 0 {
			chunks++
		}
		stride := int64(m.ChunkSize) + 16
		if chunks > (math.MaxInt64-encryption.V3HeaderSize)/stride {
			return false
		}
		return m.CiphertextSize == encryption.V3HeaderSize+chunks*stride
	}
	return false
}
func (s *Store) PutVerifiedMediaAlias(rec VerifiedMediaAlias) error {
	if err := s.filenameReady(); err != nil {
		return err
	}
	if !validMediaAlias(rec) {
		return errors.New("invalid verified media alias")
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return s.update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(verifiedMediaAliases)
		if err != nil {
			return err
		}
		idx, err := tx.CreateBucketIfNotExists(verifiedMediaReverse)
		if err != nil {
			return err
		}
		k := filenameKey(rec.Origin, rec.EncryptedPath, rec.AuthScope, rec.RuleFingerprint)
		reverse := filenameKey(rec.Origin, rec.DisplayPath, rec.AuthScope, rec.RuleFingerprint)
		if old := idx.Get(reverse); old != nil && string(old) != string(k) {
			return ErrMediaAliasConflict
		}
		if previous := b.Get(k); previous != nil {
			var old VerifiedMediaAlias
			if err = json.Unmarshal(previous, &old); err != nil {
				return err
			}
			if old.VerifiedAt.After(rec.VerifiedAt) {
				return errors.New("stale verified media alias update")
			}
			if old.DisplayPath != rec.DisplayPath {
				oldReverse := filenameKey(old.Origin, old.DisplayPath, old.AuthScope, old.RuleFingerprint)
				if string(idx.Get(oldReverse)) == string(k) {
					if err = idx.Delete(oldReverse); err != nil {
						return err
					}
				}
			}
		}
		if err = b.Put(k, raw); err != nil {
			return err
		}
		return idx.Put(reverse, k)
	})
}
func (s *Store) GetVerifiedMediaAlias(origin, encryptedPath, authScope, ruleFingerprint string, ciphertextSize int64) (VerifiedMediaAlias, bool, error) {
	return s.getVerifiedMediaAlias(origin, encryptedPath, authScope, ruleFingerprint, ciphertextSize, false)
}
func (s *Store) GetVerifiedMediaAliasByDisplay(origin, displayPath, authScope, ruleFingerprint string, ciphertextSize int64) (VerifiedMediaAlias, bool, error) {
	return s.getVerifiedMediaAlias(origin, displayPath, authScope, ruleFingerprint, ciphertextSize, true)
}
func (s *Store) getVerifiedMediaAlias(origin, p, auth, rule string, size int64, reverse bool) (VerifiedMediaAlias, bool, error) {
	var rec VerifiedMediaAlias
	found := false
	if err := s.filenameReady(); err != nil {
		return rec, false, err
	}
	if !validFilenameOrigin(origin) || !validFilenamePath(p) || !validFilenameScope(auth) || !validFilenameScope(rule) {
		return rec, false, errors.New("invalid verified media lookup")
	}
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(verifiedMediaAliases)
		if b == nil {
			return nil
		}
		k := filenameKey(origin, p, auth, rule)
		if reverse {
			idx := tx.Bucket(verifiedMediaReverse)
			if idx == nil {
				return nil
			}
			k = idx.Get(k)
			if k == nil {
				return nil
			}
		}
		raw := b.Get(k)
		if raw == nil {
			return nil
		}
		if err := json.Unmarshal(raw, &rec); err != nil {
			return err
		}
		found = rec.Origin == origin && rec.AuthScope == auth && rec.RuleFingerprint == rule && ((reverse && rec.DisplayPath == p) || (!reverse && rec.EncryptedPath == p)) && validMediaAlias(rec) && time.Since(rec.VerifiedAt) < 24*time.Hour && (size <= 0 || size == rec.CiphertextSize)
		return nil
	})
	if !found {
		rec = VerifiedMediaAlias{}
	}
	return rec, found, err
}
