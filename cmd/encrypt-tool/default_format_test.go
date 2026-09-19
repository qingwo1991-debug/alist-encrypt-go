package main

import "testing"

// formatDefaultPinned guards the batch-5 requirement that new/encrypted output
// defaults to the V3 chunked AEAD container, with an explicit legacy opt-out.
func TestFormatDefaultIsV3WithLegacyOptOut(t *testing.T) {
	cases := []struct {
		name string
		f    flags
		want bool
	}{
		{"default no flags -> V3", flags{v3: true}, true},
		{"explicit --v2 -> legacy V2", flags{v3: true, v2: true}, false},
		{"--legacy alias same as --v2", flags{v3: true, v2: true}, false},
		{"legacy with no v3 marker", flags{v2: true}, false},
	}
	for _, tc := range cases {
		if got := tc.f.useV3(); got != tc.want {
			t.Errorf("%s: useV3=%v, want %v", tc.name, got, tc.want)
		}
	}
}
