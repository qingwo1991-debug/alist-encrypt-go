package handler

import (
	"context"
	"time"
)

type FileMeta struct {
	ProviderKey  string
	OriginalPath string
	Size         int64
	ETag         string
	ContentType  string
	StatusCode   int
	UpdatedAt    time.Time
	LastAccessed time.Time
}

type FileMetaStore interface {
	Get(ctx context.Context, providerKey, originalPath string) (FileMeta, bool, error)
	Upsert(ctx context.Context, meta FileMeta) error
	Cleanup(ctx context.Context, cutoff time.Time) error
}
