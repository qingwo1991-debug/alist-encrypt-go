package openlistlib

import (
	internalnet "github.com/OpenListTeam/OpenList/v4/internal/net"
	"testing"
)

func TestEmbeddedInitFailureReleasesOnlyOwner(t *testing.T) {
	if err := Init(nil, nil); err == nil {
		t.Fatal("invalid callbacks accepted")
	}
	lease, err := internalnet.AcquireEmbeddedLease()
	if err != nil {
		t.Fatalf("failed Init retained lease: %v", err)
	}
	if err := Init(nil, nil); err == nil {
		t.Fatal("second Init accepted")
	}
	if err := lease.Publish(nil); err != nil {
		t.Fatalf("failed contender cleared owner: %v", err)
	}
	_ = lease.BeginStop()
	if err := lease.Release(); err != nil {
		t.Fatal(err)
	}
}
func TestEmbeddedStartRequiresInit(t *testing.T) {
	if err := StartEmbedded(); err == nil {
		t.Fatal("Start before Init accepted")
	}
}
