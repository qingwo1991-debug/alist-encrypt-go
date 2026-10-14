package encryption

import (
	"encoding/binary"
	"testing"
)

func TestDetectVideoFormatFiniteSignatures(t *testing.T) {
	bmff := func(brand string) []byte {
		b := make([]byte, 20)
		binary.BigEndian.PutUint32(b, 20)
		copy(b[4:], "ftyp")
		copy(b[8:], brand)
		copy(b[16:], "isom")
		return b
	}
	ebml := func(doc string) []byte {
		b := []byte{0x1a, 0x45, 0xdf, 0xa3, byte(0x80 + 3 + len(doc)), 0x42, 0x82, byte(0x80 + len(doc))}
		return append(b, doc...)
	}
	avi := []byte{'R', 'I', 'F', 'F', 4, 0, 0, 0, 'A', 'V', 'I', ' '}
	flv := []byte{'F', 'L', 'V', 1, 1, 0, 0, 0, 9}
	ts := make([]byte, 380)
	for _, i := range []int{0, 188, 376} {
		ts[i] = 0x47
		ts[i+3] = 0x10
	}
	cases := []struct {
		name string
		b    []byte
		ext  string
	}{{"mp4", bmff("mp42"), ".mp4"}, {"mov", bmff("qt  "), ".mov"}, {"m4a-video-compatible-brand", bmff("M4A "), ""}, {"avif-video-compatible-brand", bmff("avif"), ""}, {"heic", bmff("heic"), ""}, {"mkv", ebml("matroska"), ".mkv"}, {"webm", ebml("webm"), ".webm"}, {"arbitrary-ebml-doc-string", []byte("\x1a\x45\xdf\xa3some-matroska"), ""}, {"avi", avi, ".avi"}, {"flv-video", flv, ".flv"}, {"ts", ts, ".ts"}, {"text", []byte("video/mp4 ftypisom"), ""}, {"short", []byte{0x47}, ""}}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ext, mime, ok := DetectVideoFormat(c.b)
			if ext != c.ext || ok != (c.ext != "") || (ok && mime == "") {
				t.Fatalf("got (%q,%q,%v) want ext %q", ext, mime, ok, c.ext)
			}
		})
	}
	bad := bmff("mp42")
	binary.BigEndian.PutUint32(bad, 4096)
	if _, _, ok := DetectVideoFormat(bad); ok {
		t.Fatal("unavailable box accepted")
	}
	flv[4] = 4
	if _, _, ok := DetectVideoFormat(flv); ok {
		t.Fatal("audio-only FLV accepted")
	}
	ts[376] = 0
	if _, _, ok := DetectVideoFormat(ts); ok {
		t.Fatal("single/two TS syncs accepted")
	}
	for n := 0; n < 20; n++ {
		DetectVideoFormat(make([]byte, n))
	}
}
