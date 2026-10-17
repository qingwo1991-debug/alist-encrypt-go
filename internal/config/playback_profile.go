package config

import "fmt"

const (
	// PlaybackProfileStandard preserves the conservative, general-purpose playback path.
	PlaybackProfileStandard = "standard"
	// PlaybackProfileTrustedLocal opts into playback optimizations for trusted local upstreams.
	PlaybackProfileTrustedLocal = "trusted_local"
)

// normalizePlaybackProfile treats an absent legacy value as standard. Explicit
// values must match exactly: a typo must never opt a deployment into local trust.
func normalizePlaybackProfile(profile string) string {
	if profile == "" {
		return PlaybackProfileStandard
	}
	return profile
}

func validatePlaybackProfile(profile string) error {
	switch normalizePlaybackProfile(profile) {
	case PlaybackProfileStandard, PlaybackProfileTrustedLocal:
		return nil
	default:
		return fmt.Errorf("playbackProfile must be %q or %q", PlaybackProfileStandard, PlaybackProfileTrustedLocal)
	}
}
