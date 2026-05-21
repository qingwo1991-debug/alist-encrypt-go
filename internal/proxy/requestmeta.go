package proxy

import (
	"context"
	"strings"
)

type requestMetaKey string

const displayNameContextKey requestMetaKey = "display_name"

func WithDisplayName(ctx context.Context, displayName string) context.Context {
	displayName = strings.TrimSpace(displayName)
	if ctx == nil || displayName == "" {
		return ctx
	}
	return context.WithValue(ctx, displayNameContextKey, displayName)
}

func displayNameFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	value, _ := ctx.Value(displayNameContextKey).(string)
	return strings.TrimSpace(value)
}
