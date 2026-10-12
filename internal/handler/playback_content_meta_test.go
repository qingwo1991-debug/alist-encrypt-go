package handler

import (
	"bytes"
	"testing"

	"github.com/alist-encrypt-go/internal/dao"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

func TestCachedPlaybackMetaPreservesV3Parameters(t *testing.T) {
	info := &dao.FileInfo{Size: 12345, CiphertextSize: 16448, ContentVersion: encryption.ContentVersionV3, HeaderLen: encryption.V3HeaderSize, NonceField: bytes.Repeat([]byte{7}, 16), ChunkSize: 4096, KDFIterations: 1234}
	meta, ok := cachedPlaybackMeta(info, "aesctr")
	if !ok || meta.ChunkSize != 4096 || meta.KDFIterations != 1234 || meta.PlainSize != info.Size {
		t.Fatalf("complete V3 metadata lost: %+v, ok=%v", meta, ok)
	}
	meta.NonceField[0] = 0
	if info.NonceField[0] != 7 {
		t.Fatal("returned nonce aliases cached metadata")
	}
}

func TestCachedPlaybackMetaRejectsIncompleteV3(t *testing.T) {
	base := dao.FileInfo{Size: 100, CiphertextSize: 4160, ContentVersion: encryption.ContentVersionV3, HeaderLen: encryption.V3HeaderSize, NonceField: bytes.Repeat([]byte{7}, 16), ChunkSize: 4096, KDFIterations: 600000}
	cases := []struct {
		name   string
		mutate func(*dao.FileInfo)
	}{
		{"old-cache", func(i *dao.FileInfo) { i.ChunkSize = 0; i.KDFIterations = 0 }},
		{"missing-kdf", func(i *dao.FileInfo) { i.KDFIterations = 0 }},
		{"missing-nonce", func(i *dao.FileInfo) { i.NonceField = nil }},
		{"bad-header", func(i *dao.FileInfo) { i.HeaderLen = 32 }},
		{"oversized-chunk", func(i *dao.FileInfo) { i.ChunkSize = 1<<30 + 1 }},
		{"missing-cipher-size", func(i *dao.FileInfo) { i.CiphertextSize = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info := base
			tc.mutate(&info)
			if _, ok := cachedPlaybackMeta(&info, "aesctr"); ok {
				t.Fatal("incomplete V3 must trigger reprobe")
			}
		})
	}
}

func TestCachedPlaybackMetaLegacyCompatibility(t *testing.T) {
	for _, info := range []*dao.FileInfo{
		{Size: 100, ContentVersion: encryption.ContentVersionV1},
		{Size: 100, CiphertextSize: 132, ContentVersion: encryption.ContentVersionV2, HeaderLen: encryption.ContentHeaderSize(), NonceField: make([]byte, 16)},
	} {
		if _, ok := cachedPlaybackMeta(info, "aesctr"); !ok {
			t.Fatalf("valid legacy metadata rejected: %+v", info)
		}
	}
}
