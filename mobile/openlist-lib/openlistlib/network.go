package openlistlib

import "github.com/OpenListTeam/OpenList/v4/openlistlib/encrypt"

func SetNetworkState(state string) {
	encrypt.SetNetworkState(state)
}
