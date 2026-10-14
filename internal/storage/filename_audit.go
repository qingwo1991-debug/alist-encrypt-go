package storage

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Audit queries never return the reservation token or credential/rule digests.
// Names are separately opted into by the authenticated management layer.
type FilenameAuditRow struct {
	EncryptedPath  string    `json:"encrypted_path"`
	OriginalPath   string    `json:"original_path,omitempty"`
	DisplayName    string    `json:"display_name,omitempty"`
	Status         string    `json:"status"`
	CiphertextSize int64     `json:"ciphertext_size"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	LocalInvariant string    `json:"local_invariant"`
}
type FilenameAuditQuery struct {
	Origin, Prefix, After string
	From, Until           time.Time
	Limit                 int
	Names                 bool
}
type FilenameAuditPage struct {
	Records []FilenameAuditRow `json:"records"`
	After   string             `json:"-"`
	Scanned int                `json:"scanned"`
}

// FilenameAudit reads a single consistent Bolt view. Pagination is live, not a
// cross-request snapshot. Scan work as well as response size is bounded.
func (s *Store) FilenameAudit(q FilenameAuditQuery) (FilenameAuditPage, error) {
	out := FilenameAuditPage{Records: []FilenameAuditRow{}}
	if err := s.filenameReady(); err != nil {
		return out, err
	}
	if !validFilenameOrigin(q.Origin) || (q.Prefix != "/" && !validFilenamePath(q.Prefix)) || q.From.IsZero() || !q.Until.After(q.From) || q.Until.Sub(q.From) > 31*24*time.Hour || q.Limit < 1 || q.Limit > 100 || (q.After != "" && !validFilenameScope(q.After)) {
		return out, errors.New("invalid bounded audit query")
	}
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(filenameReservations)
		if b == nil {
			return nil
		}
		idx := tx.Bucket(filenameOriginalIndex)
		c := b.Cursor()
		k, v := c.First()
		if q.After != "" {
			k, v = c.Seek([]byte(q.After))
			if bytes.Equal(k, []byte(q.After)) {
				k, v = c.Next()
			}
		}
		for ; k != nil; k, v = c.Next() {
			out.Scanned++
			var r FilenameRecord
			if err := json.Unmarshal(v, &r); err != nil {
				return errors.New("invalid filename audit record")
			}
			if r.Origin == q.Origin && (q.Prefix == "/" || r.EncryptedPath == q.Prefix || strings.HasPrefix(r.EncryptedPath, q.Prefix+"/")) && !r.CreatedAt.Before(q.From) && r.CreatedAt.Before(q.Until) {
				invariant := "ok"
				reverse := filenameKey(r.Origin, r.OriginalPath, r.AuthScope, r.RuleFingerprint)
				if !bytes.Equal(k, filenameKey(r.Origin, r.EncryptedPath)) || idx == nil || !bytes.Equal(idx.Get(reverse), k) {
					invariant = "violation"
				}
				row := FilenameAuditRow{EncryptedPath: r.EncryptedPath, Status: r.Status, CiphertextSize: r.CiphertextSize, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, LocalInvariant: invariant}
				if q.Names {
					row.OriginalPath = r.OriginalPath
					row.DisplayName = r.DisplayName
				}
				out.Records = append(out.Records, row)
			}
			if len(out.Records) >= q.Limit || out.Scanned >= 1000 {
				last := string(k)
				next, _ := c.Next()
				if next != nil {
					out.After = last
				}
				break
			}
		}
		return nil
	})
	return out, err
}

var filenameChecks = []byte("filename_management_checks_v1")

// FilenameCheck is append-only local check evidence, not an upload operation or
// permission to retry/reuse a physical object, nonce, or reservation token.
type FilenameCheck struct {
	OpID         string    `json:"op_id"`
	At           time.Time `json:"at"`
	CallerDigest string    `json:"caller_digest"`
	QueryDigest  string    `json:"query_digest"`
	Checked      int       `json:"checked"`
	Violations   int       `json:"violations"`
	Remote       string    `json:"remote"`
}

func (s *Store) AppendFilenameCheck(check FilenameCheck) error {
	if err := s.filenameReady(); err != nil {
		return err
	}
	if len(check.OpID) != 32 || !validFilenameScope(check.CallerDigest) || !validFilenameScope(check.QueryDigest) || check.At.IsZero() || check.Remote != "unknown" {
		return errors.New("invalid check evidence")
	}
	raw, err := json.Marshal(check)
	if err != nil {
		return err
	}
	return s.update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(filenameChecks)
		if err != nil {
			return err
		}
		if b.Get([]byte(check.OpID)) != nil {
			return errors.New("check operation already exists")
		}
		return b.Put([]byte(check.OpID), raw)
	})
}
