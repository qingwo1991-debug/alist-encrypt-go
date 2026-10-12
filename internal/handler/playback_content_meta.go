package handler

import (
	"github.com/alist-encrypt-go/internal/dao"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

// cachedPlaybackMeta accepts only complete metadata. Older persisted V3 entries
// did not store record geometry or KDF parameters and must be probed again;
// assuming current defaults would silently change the container's meaning.
func cachedPlaybackMeta(info *dao.FileInfo, encType string) (encryption.ContentMeta, bool) {
	if info == nil || info.IsDir || info.Size < 0 || (info.Size == 0 && info.ContentVersion != encryption.ContentVersionV3) {
		return encryption.ContentMeta{}, false
	}
	meta := encryption.ContentMeta{
		EncType:        encryption.EncType(encType),
		Version:        info.ContentVersion,
		HeaderLen:      info.HeaderLen,
		PlainSize:      info.Size,
		CiphertextSize: info.CiphertextSize,
		NonceField:     append([]byte(nil), info.NonceField...),
		ChunkSize:      info.ChunkSize,
		KDFIterations:  info.KDFIterations,
	}
	switch meta.Version {
	case encryption.ContentVersionV1:
		return meta, meta.HeaderLen == 0
	case encryption.ContentVersionV2:
		return meta, meta.HeaderLen == encryption.ContentHeaderSize() && len(meta.NonceField) == 16
	case encryption.ContentVersionV3:
		if meta.PlainSize == 0 && !emptyPlaybackV3Meta(meta) {
			return encryption.ContentMeta{}, false
		}
		return meta, meta.HeaderLen == encryption.V3HeaderSize && int64(len(meta.NonceField)) == encryption.V3NonceFieldLen() && meta.ChunkSize > 0 && meta.ChunkSize <= 1<<30 && meta.KDFIterations > 0 && meta.CiphertextSize > 0
	default:
		return encryption.ContentMeta{}, false
	}
}

func emptyPlaybackV3Meta(meta encryption.ContentMeta) bool {
	return meta.IsV3() && meta.PlainSize == 0 && meta.HeaderLen == encryption.V3HeaderSize &&
		int64(len(meta.NonceField)) == encryption.V3NonceFieldLen() && meta.ChunkSize > 0 && meta.ChunkSize <= 1<<30 &&
		(meta.CiphertextSize == meta.HeaderLen || meta.CiphertextSize == meta.HeaderLen+16)
}
