package mega

import (
	"context"
	"errors"
	"testing"

	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/t3rm1n4l/go-mega"
)

func TestCanceledInitPreservesClient(t *testing.T) {
	old := mega.New()
	d := &Mega{c: old}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := d.Init(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled before login, got %v", err)
	}
	if d.c != old {
		t.Fatal("canceled init replaced client")
	}
}

func TestCanceledListDoesNotReadClient(t *testing.T) {
	d := &Mega{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.List(ctx, &MegaNode{}, model.ListArgs{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled before filesystem read, got %v", err)
	}
}
