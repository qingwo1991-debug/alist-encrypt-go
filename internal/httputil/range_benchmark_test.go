package httputil

import "testing"

var rangeBenchmarkResult *RangeRequest

// BenchmarkPlaybackRangeParse covers the Range shapes emitted by common
// media players during first-frame reads and random seeks.
func BenchmarkPlaybackRangeParse(b *testing.B) {
	const fileSize = int64(4 * 1024 * 1024 * 1024)
	for _, tc := range []struct {
		name   string
		header string
	}{
		{name: "first_frame", header: "bytes=0-2097151"},
		{name: "bounded_seek", header: "bytes=3221225472-3222274047"},
		{name: "open_ended_seek", header: "bytes=3221225472-"},
		{name: "suffix_probe", header: "bytes=-1048576"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				parsed, err := ParseRange(tc.header, fileSize)
				if err != nil {
					b.Fatal(err)
				}
				rangeBenchmarkResult = parsed
			}
		})
	}
}
