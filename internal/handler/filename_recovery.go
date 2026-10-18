package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/proxy"
	"github.com/alist-encrypt-go/internal/storage"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

// This proof is private to one authorized request. Recovery must not revive
// pre-admission global geometry or signed locators for this legacy path.
type filenameRecoveryProofKey struct{}
type filenameRecoveryProof struct {
	display, raw    string
	prefixSHA256    string
	ruleFingerprint string
	revision        uint64
	meta            encryption.ContentMeta
}

func recoveredFilenameProof(r *http.Request, display string) (filenameRecoveryProof, bool) {
	proof, ok := r.Context().Value(filenameRecoveryProofKey{}).(filenameRecoveryProof)
	return proof, ok && proof.display == display
}

type filenameRecoveryRepository interface {
	GetFilenameRecovery(storage.FilenameRecord) (storage.FilenameRecovery, bool, error)
	PutFilenameRecovery(storage.FilenameRecord, storage.FilenameRecovery) error
}

func (h *WebDAVHandler) freshFilenameRecoveryRule(rec storage.FilenameRecord, revision uint64) (*config.PasswdInfo, bool) {
	if h.cfg == nil || h.passwdDAO == nil || h.cfg.RuntimeRevision() != revision || h.cfg.GetAlistURL() != rec.Origin {
		return nil, false
	}
	lookup := h.passwdDAO.FindByPath
	if fresh, ok := h.passwdDAO.(interface {
		FindByPathFresh(string) (*config.PasswdInfo, bool)
	}); ok {
		lookup = fresh.FindByPathFresh
	}
	ep, ok := lookup(rec.OriginalPath)
	if !ok || ep == nil || !ep.Enable || !ep.EncName || filenameRuleScope(ep) != rec.RuleFingerprint {
		return nil, false
	}
	rawRule, ok := lookup(rec.EncryptedPath)
	if !ok || rawRule == nil || !rawRule.Enable || !rawRule.EncName || filenameRuleScope(rawRule) != rec.RuleFingerprint {
		return nil, false
	}
	if h.cfg.RuntimeRevision() != revision {
		return nil, false
	}
	return ep, true
}

// Both the physical basename's CRC-checked decoding and its directory must bind
// the requested original. Lossy names additionally require exact recomputation.
func (h *WebDAVHandler) recoveryFilenameMatches(rec storage.FilenameRecord, ep *config.PasswdInfo) bool {
	if path.Dir(rec.EncryptedPath) != path.Dir(rec.OriginalPath) {
		return false
	}
	base := path.Base(rec.EncryptedPath)
	decoded := encryption.ConvertShowNameWithSuffixOptions(ep.Password, ep.EncType, base, ep.EncSuffix, false)
	if decoded == path.Base(rec.OriginalPath) {
		return true
	}
	limit := protectedFilenameLimit(h.cfg, rec.OriginalPath)
	suffix := ep.EncSuffix
	if suffix == "" {
		suffix = path.Ext(rec.OriginalPath)
	}
	encoded, short, err := encryption.BoundEncryptedFilename(ep.Password, ep.EncType, path.Base(rec.OriginalPath), suffix, limit)
	return err == nil && encoded == base && short == decoded && short == rec.DisplayName
}

func recoveryMetaMatches(e storage.VerifiedMediaAlias, out proxy.MediaIdentityResult) bool {
	m := out.Meta
	return out.Reusable && out.Ext == e.Ext && out.MIME == e.MIME && m.Version == e.ContentVersion && m.EncType == e.EncType && m.CiphertextSize == e.CiphertextSize && m.PlainSize == e.PlainSize && m.HeaderLen == e.HeaderLen && bytes.Equal(m.NonceField, e.NonceField) && uint32(m.ChunkSize) == e.ChunkSize && m.KDFIterations == e.KDFIterations
}

// Every recovered read proves current caller access and the same bounded object
// identity, even under trusted-local. Administrative proof is never read auth.
func (h *WebDAVHandler) verifyFilenameRecovery(r *http.Request, rec storage.FilenameRecord, recovery storage.FilenameRecovery, ep *config.PasswdInfo) bool {
	inspector, ok := h.streamProxy.(mediaPrefixInspector)
	if !ok || !h.recoveryFilenameMatches(rec, ep) {
		return false
	}
	size, err := filenameRemotePropfind(r, rec.Origin, rec.EncryptedPath, h.getShortClient())
	if err != nil || size != rec.CiphertextSize {
		return false
	}
	target := rec.Origin + (&url.URL{Path: "/dav" + rec.EncryptedPath}).EscapedPath()
	out, err := inspector.InspectDecryptedMediaPrefix(r.Context(), target, r.Header, ep, size)
	return err == nil && out.PrefixSHA256 == recovery.PrefixSHA256 && recoveryMetaMatches(recovery.Evidence, out)
}

func (h *WebDAVHandler) bindRecoveredFilename(r *http.Request, rec storage.FilenameRecord, revision uint64) bool {
	repo, ok := h.fileDAO.(filenameRecoveryRepository)
	if !ok || rec.Status != storage.FilenameFailed {
		return false
	}
	recovery, found, err := repo.GetFilenameRecovery(rec)
	if err != nil || !found {
		return false
	}
	ep, ok := h.freshFilenameRecoveryRule(rec, revision)
	if !ok || !h.verifyFilenameRecovery(r, rec, recovery, ep) {
		return false
	}
	if _, ok := h.freshFilenameRecoveryRule(rec, revision); !ok {
		return false
	}
	e := recovery.Evidence
	meta := encryption.ContentMeta{Version: e.ContentVersion, EncType: e.EncType, PlainSize: e.PlainSize, CiphertextSize: e.CiphertextSize, HeaderLen: e.HeaderLen, NonceField: append([]byte(nil), e.NonceField...), ChunkSize: e.ChunkSize, KDFIterations: e.KDFIterations}
	*r = *r.WithContext(context.WithValue(r.Context(), filenameRecoveryProofKey{}, filenameRecoveryProof{display: rec.OriginalPath, raw: rec.EncryptedPath, prefixSHA256: recovery.PrefixSHA256, ruleFingerprint: rec.RuleFingerprint, revision: revision, meta: meta}))
	rememberFilenamePath(r, rec.OriginalPath, rec.EncryptedPath, true)
	return true
}

// HandleRecoverFilename MUST be registered only inside the management JWT
// group, like saveWebdavConfig. Authorizetoken carries that JWT; Authorization
// carries explicitly supplied upstream DAV owner credentials. No configured
// service credentials, arbitrary target URLs, cloud mutations or global mappings.
func (h *WebDAVHandler) HandleRecoverFilename(w http.ResponseWriter, r *http.Request) {
	fail := func(status int) { http.Error(w, "Filename recovery unavailable", status) }
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		fail(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		OriginalPath string `json:"original_path"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 8193))
	dec.DisallowUnknownFields()
	if dec.Decode(&req) != nil || dec.Decode(new(interface{})) != io.EOF || len(req.OriginalPath) > 4096 || path.Clean(req.OriginalPath) != req.OriginalPath || !strings.HasPrefix(req.OriginalPath, "/") {
		fail(http.StatusBadRequest)
		return
	}
	repo, ok := h.fileDAO.(filenameRecoveryRepository)
	getter, hasGetter := h.fileDAO.(interface {
		FindFilenameReservationForRead(string, string) (storage.FilenameRecord, bool, error)
	})
	inspector, hasInspector := h.streamProxy.(mediaPrefixInspector)
	if !ok || !hasGetter || !hasInspector || h.cfg == nil {
		fail(http.StatusServiceUnavailable)
		return
	}
	revision, origin := h.cfg.RuntimeRevision(), h.cfg.GetAlistURL()
	rec, found, err := getter.FindFilenameReservationForRead(origin, req.OriginalPath)
	if err != nil || !found || rec.Status != storage.FilenameFailed {
		fail(http.StatusConflict)
		return
	}
	ep, ok := h.freshFilenameRecoveryRule(rec, revision)
	if !ok || !h.recoveryFilenameMatches(rec, ep) {
		fail(http.StatusConflict)
		return
	}
	size, err := filenameRemotePropfind(r, origin, rec.EncryptedPath, h.getShortClient())
	if err != nil || size != rec.CiphertextSize {
		fail(http.StatusConflict)
		return
	}
	target := origin + (&url.URL{Path: "/dav" + rec.EncryptedPath}).EscapedPath()
	out, err := inspector.InspectDecryptedMediaPrefix(r.Context(), target, r.Header, ep, size)
	if err != nil || !out.Reusable || out.Meta.CiphertextSize != size || out.Ext != strings.ToLower(path.Ext(rec.OriginalPath)) || !strings.HasPrefix(out.MIME, "video/") || out.PrefixSHA256 == "" {
		fail(http.StatusConflict)
		return
	}
	m := out.Meta
	recovery := storage.FilenameRecovery{AuditDigest: storage.FilenameAuditDigest(rec), PrefixSHA256: out.PrefixSHA256, Evidence: storage.VerifiedMediaAlias{Origin: origin, EncryptedPath: rec.EncryptedPath, DisplayPath: rec.OriginalPath, AuthScope: filenameRequestScope(r), RuleFingerprint: rec.RuleFingerprint, CiphertextSize: m.CiphertextSize, PlainSize: m.PlainSize, ContentVersion: m.Version, HeaderLen: m.HeaderLen, NonceField: append([]byte(nil), m.NonceField...), ChunkSize: uint32(m.ChunkSize), KDFIterations: m.KDFIterations, EncType: m.EncType, ETag: out.ETag, LastModified: out.LastModified, ValidatorScope: out.ValidatorScope, VerifiedAt: time.Now().UTC(), MIME: out.MIME, Ext: out.Ext, Provenance: storage.VerifiedMediaAliasProvenance}}
	if _, ok := h.freshFilenameRecoveryRule(rec, revision); !ok || r.Context().Err() != nil {
		fail(http.StatusConflict)
		return
	}
	published, err := h.cfg.PublishIfRevision(revision, func() error { return repo.PutFilenameRecovery(rec, recovery) })
	if err != nil || !published {
		fail(http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, `{"recovered":true,"audit_status":"failed","cloud_modified":false}`)
}
