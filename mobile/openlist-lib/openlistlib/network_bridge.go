package openlistlib

import "github.com/OpenListTeam/OpenList/v4/openlistlib/encrypt"

// NetworkBridge binds an existing socket and resolves names on the same opaque
// Android network token. Methods use only gomobile-supported primitive types.
// Return zero for success or a positive Unix errno. PollDNS returns bounded JSON
// with status pending, ok (addresses), or error (code); terminal polls consume it.
type NetworkBridge interface {
	BindSocket(fd int64, token string) int64
	StartDNS(id string, token string, host string, timeoutMillis int64) int64
	PollDNS(id string) string
	CancelDNS(id string)
}

func SetNetworkBridge(bridge NetworkBridge) { encrypt.SetNativeNetworkBridge(bridge) }

// SetNativeNetworkRoutes publishes immutable generation-scoped opaque tokens.
// Tokens are native registry identifiers, not Android handles or Linux fwmarks.
func SetNativeNetworkRoutes(defaultToken, physicalToken string, generation int64) {
	encrypt.SetNativeNetworkRoutes(defaultToken, physicalToken, generation)
}
