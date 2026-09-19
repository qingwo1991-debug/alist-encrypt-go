package ports

import (
	"testing"

	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/proxy"
)

// Compile-time conformance: the adapter layer implements the ports. Any
// breaking change in an adapter's surface that removes a port method fails
// here instead of at some downstream handler call site.
var (
	_ FileRepository = (*dao.FileDAO)(nil)
	_ KeyRepository  = (*dao.PasswdDAO)(nil)
	_ Streamer       = (*proxy.StreamProxy)(nil)
)

func TestPortsAdaptersSatisfyInterfaces(t *testing.T) {
	// No runtime behavior; the blank var declarations above already enforce
	// the contract at compile time. This test exists so the package-level
	// check is exercised under `go test ./internal/...`.
	if false {
		t.Fatal("unreachable")
	}
}
