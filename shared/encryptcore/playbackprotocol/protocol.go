// Package playbackprotocol defines the transport contract shared by adapters.
// A launch intent is not proof of actual player start, frame, or exit.
package playbackprotocol

const Version = 2

// Request only accepts canonical logical paths, never transport URLs or auth scope.
// Clear advances the generation and retains a tombstone until session TTL expiry.
type Request struct {
	Session          string   `json:"session"`
	Generation       uint64   `json:"generation"`
	Path             string   `json:"path,omitempty"`
	SpeculativePaths []string `json:"speculativePaths,omitempty"`
	Clear            bool     `json:"clear,omitempty"`
}

type Capability struct {
	Version            int    `json:"version"`
	Available          bool   `json:"available"`
	Clear              bool   `json:"clear"`
	CanonicalPathsOnly bool   `json:"canonicalPathsOnly"`
	SignedCDN          bool   `json:"signedCDN"`
	Events             string `json:"events"`
}
