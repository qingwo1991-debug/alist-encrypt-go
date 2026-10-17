package cmd

import (
	internalnet "github.com/OpenListTeam/OpenList/v4/internal/net"
	"testing"
	"time"
)

func TestCLIEntrypointsCannotMutateEmbeddedOwner(t *testing.T) {
	owner, err := internalnet.AcquireEmbeddedLease()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = owner.BeginStop(); _ = owner.Release() }()
	if err := Init(); err == nil {
		t.Fatal("CLI Init bypassed embedded owner")
	}
	if err := Release(); err == nil {
		t.Fatal("CLI Release bypassed embedded owner")
	}
	// Must fail before setup and before blocking for OS signal.
	done := make(chan struct{})
	go func() { OutOpenListInit(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("CLI waited for signal after overlap reject")
	}
	if err := owner.Publish(nil); err != nil {
		t.Fatalf("CLI cleared owner: %v", err)
	}
}
