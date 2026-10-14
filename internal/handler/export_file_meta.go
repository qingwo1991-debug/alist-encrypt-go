package handler

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/storage/mysqlstore"
)

type fileExportRequest struct {
	version, limit, offset int
	filter                 mysqlstore.FileMetaFilter
	scope                  string
}

type fileExportCursor struct {
	Version   int    `json:"v"`
	Timestamp string `json:"t"`
	Key       string `json:"k"`
	Backend   string `json:"b"`
	Scope     string `json:"s"`
}

func validExportKey(key string) bool {
	decoded, err := hex.DecodeString(key)
	return err == nil && len(decoded) == 16 && key == strings.ToLower(key)
}

func parseFileExport(r *http.Request, backend string) (fileExportRequest, error) {
	req := fileExportRequest{version: 1, limit: 1000}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return req, fmt.Errorf("invalid query encoding")
	}
	// Duplicate recognized parameters are ambiguous and must not be silently selected.
	for _, key := range []string{"version", "limit", "offset", "since", "updated_after", "cursor", "provider", "path", "path_prefix", "consistency", "mode", "snapshot", "strict", "include_deleted", "include_sensitive"} {
		if len(q[key]) > 1 {
			return req, fmt.Errorf("duplicate %s", key)
		}
	}
	for key, target := range map[string]*int{"version": &req.version, "limit": &req.limit, "offset": &req.offset} {
		if v, ok := q[key]; ok {
			n, err := strconv.Atoi(v[0])
			if err != nil || n < 0 {
				return req, fmt.Errorf("invalid %s", key)
			}
			*target = n
		}
	}
	if req.version != 1 && req.version != 2 {
		return req, fmt.Errorf("unsupported export version")
	}
	if req.limit < 1 {
		return req, fmt.Errorf("invalid limit")
	}
	if req.limit > 5000 {
		req.limit = 5000
	}
	if q.Get("cursor") != "" && q.Has("offset") {
		return req, fmt.Errorf("cursor and offset cannot be combined")
	}
	if c := q.Get("consistency"); c != "" && c != "live" {
		return req, fmt.Errorf("unsupported consistency: only weak live export is available")
	}
	if m := q.Get("mode"); m != "" && m != "live" {
		return req, fmt.Errorf("unsupported mode: strict incremental and snapshot are unavailable")
	}
	for _, key := range []string{"snapshot", "strict", "include_deleted", "include_sensitive"} {
		if v, ok := q[key]; ok && v[0] != "false" && v[0] != "0" {
			return req, fmt.Errorf("unsupported %s", key)
		}
	}
	if q.Get("since") != "" && q.Get("updated_after") != "" {
		return req, fmt.Errorf("since and updated_after cannot be combined")
	}
	f := mysqlstore.FileMetaFilter{ProviderHost: q.Get("provider"), OriginalPath: q.Get("path"), PathPrefix: q.Get("path_prefix"), Limit: req.limit + 1, Offset: req.offset, LegacySeconds: req.version == 1}
	if v, ok := q["since"]; ok {
		n, err := strconv.ParseInt(v[0], 10, 64)
		if err != nil || n < 0 {
			return req, fmt.Errorf("invalid since")
		}
		f.UpdatedAfter = time.Unix(n, 0).UTC()
	}
	if v, ok := q["updated_after"]; ok {
		t, err := time.Parse(time.RFC3339Nano, v[0])
		if err != nil {
			return req, fmt.Errorf("invalid updated_after")
		}
		f.UpdatedAfter = t.UTC()
	}
	if req.version == 1 && !f.UpdatedAfter.IsZero() {
		f.UpdatedAfter = f.UpdatedAfter.Truncate(time.Second)
	}
	scopeJSON, _ := json.Marshal([]string{f.ProviderHost, f.OriginalPath, f.PathPrefix, f.UpdatedAfter.Format(time.RFC3339Nano)})
	sum := sha256.Sum256(scopeJSON)
	req.scope = hex.EncodeToString(sum[:])
	if key := q.Get("cursor"); key != "" {
		if req.version == 1 {
			if !validExportKey(key) || f.UpdatedAfter.IsZero() {
				return req, fmt.Errorf("legacy cursor requires raw KeyHash and since/updated_after")
			}
			f.CursorKey = key
			f.CursorTime = f.UpdatedAfter
		} else {
			if len(key) > 2048 {
				return req, fmt.Errorf("invalid cursor")
			}
			raw, err := base64.RawURLEncoding.Strict().DecodeString(key)
			if err != nil {
				return req, fmt.Errorf("invalid cursor")
			}
			var c fileExportCursor
			d := json.NewDecoder(bytes.NewReader(raw))
			d.DisallowUnknownFields()
			if err = d.Decode(&c); err != nil {
				return req, fmt.Errorf("invalid cursor")
			}
			canonical, _ := json.Marshal(c)
			t, err := time.Parse(time.RFC3339Nano, c.Timestamp)
			if err != nil || t.IsZero() || c.Timestamp != t.UTC().Format(time.RFC3339Nano) || !bytes.Equal(raw, canonical) || c.Version != 2 || !validExportKey(c.Key) || c.Backend != backend || c.Scope != req.scope {
				return req, fmt.Errorf("invalid cursor or filter/backend scope")
			}
			f.CursorTime = t
			f.CursorKey = c.Key
		}
	}
	req.filter = f
	return req, nil
}

func boltFileExportRecord(info *dao.FileInfo) mysqlstore.FileMetaRecord {
	host := ""
	if u, err := url.Parse(info.RawURL); err == nil {
		host = u.Host
	}
	updated := info.Modified
	if updated.IsZero() {
		updated = info.UpstreamFetchedAt
	}
	if updated.IsZero() {
		updated = time.Unix(0, 0).UTC()
	}
	return mysqlstore.FileMetaRecord{
		KeyHash:           mysqlstore.KeyHash(host, info.Path),
		ProviderHost:      host,
		OriginalPath:      info.Path,
		EncryptedPath:     info.EncryptedPath,
		Name:              info.Name,
		Size:              info.Size,
		CiphertextSize:    info.CiphertextSize,
		ContentVersion:    info.ContentVersion,
		HeaderLen:         info.HeaderLen,
		NonceField:        append([]byte(nil), info.NonceField...),
		ChunkSize:         info.ChunkSize,
		KDFIterations:     info.KDFIterations,
		UpstreamFetchedAt: info.UpstreamFetchedAt,
		UpdatedAt:         updated,
		LastAccessed:      info.Modified,
		Active:            true,
	}
}

func selectBoltFileExport(all []*dao.FileInfo, req fileExportRequest) []mysqlstore.FileMetaRecord {
	f := req.filter
	records := make([]mysqlstore.FileMetaRecord, 0, len(all))
	for _, info := range all {
		record := boltFileExportRecord(info)
		if req.version == 1 {
			record.UpdatedAt = record.UpdatedAt.UTC().Truncate(time.Second)
		}
		if f.ProviderHost != "" && record.ProviderHost != f.ProviderHost || f.OriginalPath != "" && record.OriginalPath != f.OriginalPath || !strings.HasPrefix(record.OriginalPath, f.PathPrefix) {
			continue
		}
		if !f.UpdatedAfter.IsZero() && record.UpdatedAt.Before(f.UpdatedAfter) {
			continue
		}
		if f.CursorKey != "" && (record.UpdatedAt.Before(f.CursorTime) || record.UpdatedAt.Equal(f.CursorTime) && record.KeyHash <= f.CursorKey) {
			continue
		}
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].UpdatedAt.Equal(records[j].UpdatedAt) {
			return records[i].KeyHash < records[j].KeyHash
		}
		return records[i].UpdatedAt.Before(records[j].UpdatedAt)
	})
	if req.offset >= len(records) {
		return []mysqlstore.FileMetaRecord{}
	}
	records = records[req.offset:]
	if len(records) > req.limit+1 {
		records = records[:req.limit+1]
	}
	return records
}

// ExportFileMeta exports synchronization hints, never a database backup or a
// revision/deletion feed. Each page observes live state, not a cross-page snapshot.
func (h *APIHandler) ExportFileMeta(w http.ResponseWriter, r *http.Request) {
	backend := "boltdb"
	if h.mysqlStore != nil {
		backend = "mysql"
	}
	req, err := parseFileExport(r, backend)
	if err != nil {
		RespondJSON(w, http.StatusBadRequest, APIResponse{Code: 400, Msg: err.Error()})
		return
	}
	var records []mysqlstore.FileMetaRecord
	if h.mysqlStore != nil {
		records, err = h.svc.ExportFileMeta(r.Context(), req.filter)
	} else {
		var all []*dao.FileInfo
		all, err = h.fileDAO.ExportAll()
		if err == nil {
			records = selectBoltFileExport(all, req)
		}
	}
	if err != nil {
		RespondJSON(w, http.StatusInternalServerError, APIResponse{Code: 500, Msg: "metadata export failed"})
		return
	}
	hasMore := len(records) > req.limit
	if hasMore {
		records = records[:req.limit]
	}
	if records == nil {
		records = []mysqlstore.FileMetaRecord{}
	}
	nextCursor := ""
	nextSince := int64(0)
	nextTime := ""
	for i := range records {
		records[i].RawURL = ""
		records[i].RawURLAuthScope = ""
		records[i].Sign = ""
		if req.version == 1 {
			records[i].UpdatedAt = records[i].UpdatedAt.UTC().Truncate(time.Second)
		}
	}
	if len(records) > 0 {
		last := records[len(records)-1]
		nextSince = last.UpdatedAt.Unix()
		nextTime = last.UpdatedAt.UTC().Format(time.RFC3339Nano)
		nextCursor = last.KeyHash
		if req.version == 2 {
			raw, _ := json.Marshal(fileExportCursor{Version: 2, Timestamp: nextTime, Key: last.KeyHash, Backend: backend, Scope: req.scope})
			nextCursor = base64.RawURLEncoding.EncodeToString(raw)
		}
	}
	RespondSuccess(w, map[string]interface{}{"items": records, "version": req.version, "backend": backend, "consistency": "weak_live", "incremental": "best_effort", "snapshot_supported": false, "strict_incremental_supported": false, "limit": req.limit, "offset": req.offset, "has_more": hasMore, "next_since": nextSince, "next_since_rfc3339": nextTime, "next_cursor": nextCursor})
}
