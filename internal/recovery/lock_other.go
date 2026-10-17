//go:build !unix && !windows

package recovery

import (
	"context"
	"errors"
)

type Lock struct{}

func Acquire(context.Context, string) (*Lock, error) {
	return nil, errors.New("store lifetime lock unsupported on this platform")
}
func (*Lock) Close() error { return nil }
