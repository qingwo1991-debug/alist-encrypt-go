package mega

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
)

// do others that not defined in Driver interface
// openObject represents a download in progress
type downloadSession interface {
	Chunks() int
	ChunkLocation(int) (int64, int, error)
	DownloadChunkContext(context.Context, int) ([]byte, error)
	Finish() error
}

type openObject struct {
	ctx       context.Context
	mu        sync.Mutex
	d         downloadSession
	cancel    context.CancelFunc
	closeOnce sync.Once
	closeErr  error
	id        int
	skip      int64
	chunk     []byte
	closed    bool
}

// get the next chunk
func (oo *openObject) getChunk(ctx context.Context) (err error) {
	if oo.id >= oo.d.Chunks() {
		return io.EOF
	}
	var chunk []byte
	err = utils.RetryContext(ctx, 3, time.Second, func() (err error) {
		chunk, err = oo.d.DownloadChunkContext(ctx, oo.id)
		return err
	})
	if err != nil {
		return err
	}
	oo.id++
	oo.chunk = chunk
	return nil
}

// Read reads up to len(p) bytes into p.
func (oo *openObject) Read(p []byte) (n int, err error) {
	oo.mu.Lock()
	defer oo.mu.Unlock()
	if oo.closed {
		return 0, fmt.Errorf("read on closed file")
	}
	if err := oo.ctx.Err(); err != nil {
		return 0, err
	}
	if len(p) == 0 {
		return 0, nil
	}
	// Skip data at the start if requested
	for oo.skip > 0 {
		_, size, err := oo.d.ChunkLocation(oo.id)
		if err != nil {
			return 0, err
		}
		if oo.skip < int64(size) {
			break
		}
		oo.id++
		oo.skip -= int64(size)
	}
	if len(oo.chunk) == 0 {
		err = oo.getChunk(oo.ctx)
		if err != nil {
			return 0, err
		}
		if oo.skip > 0 {
			oo.chunk = oo.chunk[oo.skip:]
			oo.skip = 0
		}
	}
	n = copy(p, oo.chunk)
	oo.chunk = oo.chunk[n:]
	return n, nil
}

// Close closed the file - MAC errors are reported here
func (oo *openObject) Close() error {
	// Signal the actual HTTP operation before waiting for Read's lock.
	if oo.cancel != nil {
		oo.cancel()
	}
	oo.closeOnce.Do(func() {
		oo.mu.Lock()
		defer oo.mu.Unlock()
		oo.closed = true
		// Finish is local MAC verification, not a retryable network operation.
		// Retrying it mutates the CBC accumulator and can corrupt verification.
		if err := oo.d.Finish(); err != nil {
			oo.closeErr = fmt.Errorf("failed to finish download: %w", err)
		}
		oo.chunk = nil
	})
	return oo.closeErr
}
