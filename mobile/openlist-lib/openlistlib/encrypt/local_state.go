package encrypt

import "sync/atomic"

type NetworkState string

const (
	NetworkStateWiFi    NetworkState = "wifi"
	NetworkState4G      NetworkState = "4g"
	NetworkState5G      NetworkState = "5g"
	NetworkStateCellular NetworkState = "cellular"
	NetworkStateOffline NetworkState = "offline"
)

var currentNetworkState atomic.Value

func init() {
	currentNetworkState.Store(NetworkStateWiFi)
}

func normalizeNetworkState(state string) NetworkState {
	switch NetworkState(state) {
	case NetworkStateWiFi, NetworkState4G, NetworkState5G, NetworkStateCellular, NetworkStateOffline:
		return NetworkState(state)
	default:
		return NetworkStateWiFi
	}
}

func SetNetworkState(state string) {
	currentNetworkState.Store(normalizeNetworkState(state))
}

func GetNetworkState() NetworkState {
	if v := currentNetworkState.Load(); v != nil {
		if s, ok := v.(NetworkState); ok {
			return s
		}
	}
	return NetworkStateWiFi
}
