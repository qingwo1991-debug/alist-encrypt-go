package encryption

import (
	"bytes"
	"encoding/binary"
)

// DetectVideoFormat identifies a finite set of video container signatures, not
// the integrity, decodability or video tracks of the entire file. Unknown input
// is never promoted using generic HTTP MIME sniffing. ext includes its dot.
func DetectVideoFormat(prefix []byte) (ext, mime string, ok bool) {
	if len(prefix) >= 16 && string(prefix[4:8]) == "ftyp" {
		size := uint64(binary.BigEndian.Uint32(prefix[:4]))
		if size < 16 || size > uint64(len(prefix)) || (size-16)%4 != 0 {
			return "", "", false
		}
		brands := [][]byte{prefix[8:12]}
		for i := 16; i < int(size); i += 4 {
			brands = append(brands, prefix[i:i+4])
		}
		video, quick := false, false
		for _, b := range brands {
			switch string(b) {
			case "avif", "avis", "heic", "heix", "hevc", "hevx", "mif1", "msf1", "M4A ", "M4B ", "M4P ", "F4A ", "F4B ":
				return "", "", false
			case "qt  ":
				quick = true
			case "isom", "iso2", "mp41", "mp42", "avc1", "dash", "M4V ", "M4VH", "M4VP", "3gp4", "3gp5", "3gp6", "3ge6", "3gg6":
				video = true
			}
		}
		if quick {
			return ".mov", "video/quicktime", true
		}
		if video {
			return ".mp4", "video/mp4", true
		}
	}
	if len(prefix) >= 12 && string(prefix[:4]) == "RIFF" && string(prefix[8:12]) == "AVI " && binary.LittleEndian.Uint32(prefix[4:8]) >= 4 {
		return ".avi", "video/x-msvideo", true
	}
	if len(prefix) >= 9 && string(prefix[:3]) == "FLV" && prefix[3] == 1 && prefix[4]&1 != 0 && prefix[4]&^byte(5) == 0 && binary.BigEndian.Uint32(prefix[5:9]) >= 9 && uint64(binary.BigEndian.Uint32(prefix[5:9])) <= uint64(len(prefix)) {
		return ".flv", "video/x-flv", true
	}
	if len(prefix) >= 377 && prefix[0] == 0x47 && prefix[188] == 0x47 && prefix[376] == 0x47 {
		good := true
		for _, i := range []int{0, 188, 376} {
			if i+3 < len(prefix) && (prefix[i+1]&0x80 != 0 || prefix[i+3]&0x30 == 0) {
				good = false
			}
		}
		if good {
			return ".ts", "video/mp2t", true
		}
	}
	if len(prefix) >= 5 && bytes.Equal(prefix[:4], []byte{0x1a, 0x45, 0xdf, 0xa3}) {
		size, n, valid := mediaEBMLVInt(prefix[4:], true)
		if !valid || size > 4096 || size > uint64(len(prefix)-4-n) {
			return "", "", false
		}
		body := prefix[4+n : 4+n+int(size)]
		doc := ""
		for len(body) > 0 {
			id, k, valid := mediaEBMLVInt(body, false)
			if !valid {
				return "", "", false
			}
			body = body[k:]
			sz, k, valid := mediaEBMLVInt(body, true)
			if !valid || sz > uint64(len(body)-k) {
				return "", "", false
			}
			body = body[k:]
			if id == 0x4282 {
				if doc != "" || sz > 16 {
					return "", "", false
				}
				doc = string(body[:int(sz)])
			}
			body = body[int(sz):]
		}
		if doc == "matroska" {
			return ".mkv", "video/x-matroska", true
		}
		if doc == "webm" {
			return ".webm", "video/webm", true
		}
	}
	return "", "", false
}

// EBML element IDs retain their marker; sizes strip it and reject unknown size.
func mediaEBMLVInt(b []byte, size bool) (uint64, int, bool) {
	if len(b) == 0 || b[0] == 0 {
		return 0, 0, false
	}
	mask := byte(0x80)
	n := 1
	for b[0]&mask == 0 {
		mask >>= 1
		n++
	}
	if n > 8 || (!size && n > 4) || len(b) < n {
		return 0, 0, false
	}
	v := uint64(b[0])
	if size {
		v = uint64(b[0] &^ mask)
	}
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	if size && v == (uint64(1)<<uint(7*n))-1 {
		return 0, 0, false
	}
	return v, n, true
}
