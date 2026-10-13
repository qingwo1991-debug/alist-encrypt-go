package encrypt

import (
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
)

const confirmedMetadataProvenanceInspection = "validated-inspection"

// Identity deliberately excludes ephemeral signed transport URLs. Its caller
// supplies the canonical origin/object path and hashes of authorization/rules.
type confirmedMetadataIdentity struct {
	ObjectID          string
	CredentialScope   string
	CryptoFingerprint string
}

func (id confirmedMetadataIdentity) valid() bool {
	return id.ObjectID != "" && id.CredentialScope != "" && id.CryptoFingerprint != ""
}

// Key uses length framing, not delimiter concatenation, to avoid ambiguity.
func (id confirmedMetadataIdentity) Key() string {
	h := sha256.New()
	for _, value := range []string{id.ObjectID, id.CredentialScope, id.CryptoFingerprint} {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		_, _ = h.Write(size[:])
		_, _ = h.Write([]byte(value))
	}
	return hex.EncodeToString(h.Sum(nil))
}

type confirmedMetadataRecord struct {
	Identity       confirmedMetadataIdentity
	Meta           ContentMeta
	Provenance     string
	ConfirmedAt    int64
	ValidatedAt    int64
	ETag           string
	LastModified   string
	ValidatorScope string
	Generation     uint64
	// Fingerprint is optional captured evidence, never synthesized from a size.
	Fingerprint string
}

func validConfirmedMetadataRecord(rec confirmedMetadataRecord) bool {
	if !rec.Identity.valid() || rec.Provenance != confirmedMetadataProvenanceInspection || rec.ConfirmedAt <= 0 || rec.ValidatedAt < rec.ConfirmedAt || rec.Generation > math.MaxInt64 {
		return false
	}
	m := rec.Meta
	switch m.Version {
	case ContentVersionV1:
		return m.HeaderLen == 0 && m.PlainSize > 0 && m.CiphertextSize == m.PlainSize && len(m.NonceField) == 0 && m.ChunkSize == 0 && m.KDFIterations == 0
	case ContentVersionV2:
		return m.HeaderLen == ContentHeaderSize() && len(m.NonceField) == 16 && m.PlainSize > 0 && m.PlainSize <= math.MaxInt64-m.HeaderLen && m.CiphertextSize == m.PlainSize+m.HeaderLen && m.ChunkSize == 0 && m.KDFIterations == 0
	case ContentVersionV3:
		return ValidateV3ContentMeta(m) == nil
	default:
		return false
	}
}

func initConfirmedMetadataSchema(db *sql.DB) error {
	if db == nil {
		return errors.New("confirmed metadata: database unavailable")
	}
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS confirmed_metadata (
 object_key TEXT PRIMARY KEY,
 object_id TEXT NOT NULL,
 credential_scope TEXT NOT NULL,
 crypto_fingerprint TEXT NOT NULL,
 metadata_fingerprint TEXT NOT NULL DEFAULT '',
 provenance TEXT NOT NULL,
 confirmed_at INTEGER NOT NULL,
 validated_at INTEGER NOT NULL,
 etag TEXT NOT NULL DEFAULT '',
 last_modified TEXT NOT NULL DEFAULT '',
 validator_scope TEXT NOT NULL DEFAULT '',
 generation INTEGER NOT NULL DEFAULT 0,
 enc_type TEXT NOT NULL,
 content_version INTEGER NOT NULL,
 header_len INTEGER NOT NULL,
 plain_size INTEGER NOT NULL,
 ciphertext_size INTEGER NOT NULL,
 nonce_field BLOB,
 chunk_size INTEGER NOT NULL,
 kdf_iterations INTEGER NOT NULL
 )`)
	return err
}

// Writes are synchronous single-statement operations: confirmation is durable
// before return, independent of the legacy buffered partial-observation queue.
// Do not take localStore.mu here: SQLite/sql.DB owns statement serialization.
func (s *localStore) PutConfirmedMetadata(rec confirmedMetadataRecord) error {
	if s == nil || s.db == nil {
		return errors.New("confirmed metadata: database unavailable")
	}
	if !validConfirmedMetadataRecord(rec) {
		return errors.New("confirmed metadata: invalid identity, provenance or geometry")
	}
	nonce := cloneNonceField(rec.Meta.NonceField)
	_, err := s.db.Exec(`INSERT INTO confirmed_metadata
 (object_key, object_id, credential_scope, crypto_fingerprint, metadata_fingerprint, provenance, confirmed_at, validated_at, etag, last_modified, validator_scope, generation, enc_type, content_version, header_len, plain_size, ciphertext_size, nonce_field, chunk_size, kdf_iterations)
 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
 ON CONFLICT(object_key) DO UPDATE SET
 object_id=excluded.object_id, credential_scope=excluded.credential_scope, crypto_fingerprint=excluded.crypto_fingerprint,
 metadata_fingerprint=excluded.metadata_fingerprint, provenance=excluded.provenance,
 confirmed_at=excluded.confirmed_at, validated_at=excluded.validated_at, etag=excluded.etag,
 last_modified=excluded.last_modified, validator_scope=excluded.validator_scope, generation=excluded.generation,
 enc_type=excluded.enc_type, content_version=excluded.content_version, header_len=excluded.header_len,
 plain_size=excluded.plain_size, ciphertext_size=excluded.ciphertext_size, nonce_field=excluded.nonce_field,
 chunk_size=excluded.chunk_size, kdf_iterations=excluded.kdf_iterations
 WHERE excluded.generation >= confirmed_metadata.generation AND excluded.validated_at >= confirmed_metadata.validated_at`,
		rec.Identity.Key(), rec.Identity.ObjectID, rec.Identity.CredentialScope, rec.Identity.CryptoFingerprint,
		rec.Fingerprint, rec.Provenance, rec.ConfirmedAt, rec.ValidatedAt, rec.ETag, rec.LastModified, rec.ValidatorScope, rec.Generation,
		string(rec.Meta.EncType), rec.Meta.Version, rec.Meta.HeaderLen, rec.Meta.PlainSize, rec.Meta.CiphertextSize, nonce, rec.Meta.ChunkSize, rec.Meta.KDFIterations)
	return err
}

func (s *localStore) GetConfirmedMetadata(id confirmedMetadataIdentity) (confirmedMetadataRecord, bool) {
	var rec confirmedMetadataRecord
	if s == nil || s.db == nil || !id.valid() {
		return rec, false
	}
	var encType string
	err := s.db.QueryRow(`SELECT object_id, credential_scope, crypto_fingerprint, metadata_fingerprint, provenance, confirmed_at, validated_at, etag, last_modified, validator_scope, generation, enc_type, content_version, header_len, plain_size, ciphertext_size, nonce_field, chunk_size, kdf_iterations FROM confirmed_metadata WHERE object_key=?`, id.Key()).Scan(
		&rec.Identity.ObjectID, &rec.Identity.CredentialScope, &rec.Identity.CryptoFingerprint, &rec.Fingerprint,
		&rec.Provenance, &rec.ConfirmedAt, &rec.ValidatedAt, &rec.ETag, &rec.LastModified, &rec.ValidatorScope, &rec.Generation,
		&encType, &rec.Meta.Version, &rec.Meta.HeaderLen, &rec.Meta.PlainSize, &rec.Meta.CiphertextSize, &rec.Meta.NonceField, &rec.Meta.ChunkSize, &rec.Meta.KDFIterations)
	rec.Meta.EncType = EncryptionType(encType)
	if err != nil || rec.Identity != id || !validConfirmedMetadataRecord(rec) {
		return confirmedMetadataRecord{}, false
	}
	rec.Meta.NonceField = cloneNonceField(rec.Meta.NonceField)
	return rec, true
}

// DeleteAllConfirmedMetadata conservatively invalidates confirmed evidence for
// explicit refresh and mutations whose affected subtree cannot be identified.
// Legacy size/import tables are untouched and never become confirmed evidence
// merely because a manual refresh cleared this table. The resolver must also
// fence all outstanding flights and clear its confirmed in-memory entries.
func (s *localStore) DeleteAllConfirmedMetadata() error {
	if s == nil || s.db == nil {
		return errors.New("confirmed metadata: database unavailable")
	}
	_, err := s.db.Exec(`DELETE FROM confirmed_metadata`)
	return err
}

// DeleteConfirmedMetadataObject invalidates every authorization/rule scope after
// a known object mutation. Response-validator failures use scoped deletion instead.
// The resolver still owns fencing in-flight writes against this deletion.
func (s *localStore) DeleteConfirmedMetadataObject(objectID string) error {
	if s == nil || s.db == nil {
		return errors.New("confirmed metadata: database unavailable")
	}
	if objectID == "" {
		return errors.New("confirmed metadata: invalid object identity")
	}
	_, err := s.db.Exec(`DELETE FROM confirmed_metadata WHERE object_id=?`, objectID)
	return err
}

func (s *localStore) DeleteConfirmedMetadata(id confirmedMetadataIdentity) error {
	if s == nil || s.db == nil {
		return errors.New("confirmed metadata: database unavailable")
	}
	if !id.valid() {
		return errors.New("confirmed metadata: invalid identity")
	}
	_, err := s.db.Exec(`DELETE FROM confirmed_metadata WHERE object_key=?`, id.Key())
	return err
}
