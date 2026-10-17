package storage

import (
	"bytes"
	"encoding/json"
	"errors"
	bolt "go.etcd.io/bbolt"
	"time"
)

// invalidateRestoreTransport uses the actual dao.FileInfo JSON contract without
// importing dao (which imports storage). Raw geometry and timestamps remain their
// original JSON bytes; only reusable transport material is removed. Unknown
// schemas are refused, never blindly decoded/re-encoded into a lossy old struct.
func invalidateRestoreTransport(tx *bolt.Tx) error {
	b := tx.Bucket(BucketFileInfo)
	if b == nil {
		return errors.New("missing fileinfo bucket")
	}
	allowed := map[string]bool{}
	for _, k := range []string{"path", "encrypted_path", "name", "size", "ciphertext_size", "content_version", "header_len", "nonce_field", "chunk_size", "kdf_iterations", "is_dir", "modified", "raw_url", "raw_url_auth_scope", "sign", "upstream_fetched_at"} {
		allowed[k] = true
	}
	type entry struct{ k, v []byte }
	var changes []entry
	err := b.ForEach(func(k, v []byte) error {
		if v == nil {
			return errors.New("unknown fileinfo nested bucket")
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(v, &fields); err != nil || fields == nil {
			return errors.New("invalid fileinfo entity")
		}
		for key := range fields {
			if !allowed[key] {
				return errors.New("unknown fileinfo field")
			}
		}
		var path string
		if json.Unmarshal(fields["path"], &path) != nil || path == "" {
			return errors.New("invalid fileinfo path")
		}
		// Validate typed known fields, while retaining their raw representation.
		for _, key := range []string{"size", "ciphertext_size", "content_version", "header_len", "chunk_size", "kdf_iterations"} {
			if raw := fields[key]; raw != nil {
				var n uint64
				if json.Unmarshal(raw, &n) != nil {
					return errors.New("invalid fileinfo numeric field")
				}
			}
		}
		for _, key := range []string{"encrypted_path", "name", "nonce_field", "raw_url", "raw_url_auth_scope", "sign"} {
			if raw := fields[key]; raw != nil && !bytes.Equal(raw, []byte("null")) {
				var s string
				if json.Unmarshal(raw, &s) != nil {
					return errors.New("invalid fileinfo string field")
				}
			}
		}
		for _, key := range []string{"modified", "upstream_fetched_at"} {
			if raw := fields[key]; raw != nil {
				var stamp time.Time
				if json.Unmarshal(raw, &stamp) != nil {
					return errors.New("invalid fileinfo timestamp")
				}
			}
		}
		if raw := fields["is_dir"]; raw != nil {
			var flag bool
			if json.Unmarshal(raw, &flag) != nil {
				return errors.New("invalid fileinfo directory flag")
			}
		}
		for _, key := range []string{"raw_url", "raw_url_auth_scope", "sign"} {
			fields[key] = json.RawMessage(`""`)
		}
		raw, err := json.Marshal(fields)
		if err != nil {
			return err
		}
		changes = append(changes, entry{append([]byte(nil), k...), raw})
		return nil
	})
	if err != nil {
		return err
	}
	for _, e := range changes {
		if err := b.Put(e.k, e.v); err != nil {
			return err
		}
	}
	return nil
}
