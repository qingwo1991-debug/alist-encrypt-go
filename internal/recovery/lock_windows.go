//go:build windows

package recovery

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Lock struct {
	file       *os.File
	overlapped windows.Overlapped
	once       sync.Once
	err        error
}

func Acquire(ctx context.Context, dir string) (*Lock, error) {
	p := filepath.Join(dir, ".store-maint.lock")
	if st, err := os.Lstat(p); err == nil && !st.Mode().IsRegular() {
		return nil, errors.New("invalid store lock file")
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	l := &Lock{file: f}
	for {
		if err = ctx.Err(); err != nil {
			f.Close()
			return nil, err
		}
		err = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &l.overlapped)
		if err == nil {
			return l, nil
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) && !errors.Is(err, windows.ERROR_IO_PENDING) {
			f.Close()
			return nil, err
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			f.Close()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}
func (l *Lock) Close() error {
	if l == nil {
		return nil
	}
	l.once.Do(func() {
		l.err = errors.Join(windows.UnlockFileEx(windows.Handle(l.file.Fd()), 0, 1, 0, &l.overlapped), l.file.Close())
	})
	return l.err
}
