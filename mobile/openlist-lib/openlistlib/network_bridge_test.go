package openlistlib

import (
	"github.com/OpenListTeam/OpenList/v4/openlistlib/encrypt"
	"testing"
)

type facadeNativeBridge struct{}

func (*facadeNativeBridge) BindSocket(int64, string) int64               { return 0 }
func (*facadeNativeBridge) StartDNS(string, string, string, int64) int64 { return 0 }
func (*facadeNativeBridge) PollDNS(string) string                        { return `{"status":"pending"}` }
func (*facadeNativeBridge) CancelDNS(string)                             {}

func TestNetworkBridgeFacadePrimitiveContract(t *testing.T) {
	before := encrypt.SnapshotNativeRoutes()
	bridge := &facadeNativeBridge{}
	SetNetworkBridge(bridge)
	t.Cleanup(func() {
		SetNetworkBridge(before.Bridge)
		SetNativeNetworkRoutes(before.DefaultToken, before.PhysicalToken, encrypt.SnapshotNativeRoutes().Generation+1)
	})
	generation := before.Generation + 1
	SetNativeNetworkRoutes("default-facade", "physical-facade", generation)
	snapshot := encrypt.SnapshotNativeRoutes()
	if snapshot.Bridge != bridge || snapshot.Generation != generation || snapshot.DefaultToken != "default-facade" || snapshot.PhysicalToken != "physical-facade" {
		t.Fatalf("snapshot %+v", snapshot)
	}
	SetNativeNetworkRoutes("changed", "changed", generation)
	SetNativeNetworkRoutes("old", "old", generation-1)
	snapshot = encrypt.SnapshotNativeRoutes()
	if snapshot.DefaultToken != "default-facade" || snapshot.PhysicalToken != "physical-facade" {
		t.Fatal("generation was reassigned")
	}
	// Cleanup restores the bridge first, then republishes tokens with a new
	// generation because bridge replacement invalidates all prior tokens.
}
