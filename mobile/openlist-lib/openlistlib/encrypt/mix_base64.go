package encrypt

import (
	"bytes"
	"crypto/sha256"
	"strings"
)

const base64Source = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~+"

type MixBase64 struct {
	chars    []string
	mapChars map[string]int
}

func initKSA(passwd string) string {
	var key []byte
	if len(passwd) > 0 { // effectively matches 'string' check? JS code: if (typeof passwd === 'string')
		hash := sha256.New()
		hash.Write([]byte(passwd))
		key = hash.Sum(nil)
	} else {
		key = []byte(passwd) // unreachable if type is string in Go usually
	}

	// S-box init
	sbox := make([]int, len(base64Source))
	for i := range sbox {
		sbox[i] = i
	}

	// Fill K
	K := make([]int, len(base64Source))
	keyLen := len(key)
	for i := range K {
		K[i] = int(key[i%keyLen])
	}

	// Swap S-box
	j := 0
	sourceLen := len(base64Source)
	for i := 0; i < sourceLen; i++ {
		j = (j + sbox[i] + K[i]) % sourceLen
		sbox[i], sbox[j] = sbox[j], sbox[i]
	}

	var secret bytes.Buffer
	sourceKey := []rune(base64Source)
	for _, idx := range sbox {
		secret.WriteRune(sourceKey[idx])
	}
	return secret.String()
}

func NewMixBase64(passwd string) *MixBase64 {
	salt := "mix64"
	var secret string
	if len(passwd) == 64 {
		secret = passwd
	} else {
		secret = initKSA(passwd + salt)
	}

	chars := make([]string, len(secret))
	mapChars := make(map[string]int)

	for i, r := range secret {
		s := string(r)
		chars[i] = s
		mapChars[s] = i
	}

	return &MixBase64{
		chars:    chars,
		mapChars: mapChars,
	}
}

func (m *MixBase64) Encode(input string) string {
	buffer := []byte(input) // utf-8 by default
	var result bytes.Buffer
	length := len(buffer)

	chars := m.chars

	for i := 0; i < length; i += 3 {
		// subarray
		remain := length - i
		if remain >= 3 {
			bt0 := int(buffer[i])
			bt1 := int(buffer[i+1])
			bt2 := int(buffer[i+2])

			result.WriteString(chars[bt0>>2])
			result.WriteString(chars[((bt0&3)<<4)|(bt1>>4)])
			result.WriteString(chars[((bt1&15)<<2)|(bt2>>6)])
			result.WriteString(chars[bt2&63])
		} else {
			// padding logic
			arr := buffer[i:]
			if len(arr) == 1 {
				v0 := int(arr[0])
				result.WriteString(chars[v0>>2])
				result.WriteString(chars[(v0&3)<<4])
				result.WriteString(chars[64]) // 64 is index out of bounds?
				// source length is 64 + 1? No.
				// source length is 64.  indices 0-63.
				// JS Code: chars[64] + chars[64]
				// Wait, source = '...-~+' length is 26+26+10+3 = 65?
				// A-Z (26) + a-z (26) + 0-9 (10) + -~+ (3) = 65 chars.
				// Base64 uses 64 chars.
				// mixBase64Source has 65 chars?
				// JS: `const source = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~+'`
				// Length: 26+26+10+3 = 65.
				// standard base64: A-Z, a-z, 0-9, +, / (64 chars) + = (pad)
				// This custom base64 uses 65 chars?
				// JS: chars indexes go up to 63 in main loop (bt2 & 63).
				// Padding used chars[64].
				// So yes, it uses the 65th char as padding?
				result.WriteString(chars[64])
			} else if len(arr) == 2 {
				v0 := int(arr[0])
				v1 := int(arr[1])
				result.WriteString(chars[v0>>2])
				result.WriteString(chars[((v0&3)<<4)|(v1>>4)])
				result.WriteString(chars[(v1&15)<<2])
				result.WriteString(chars[64])
			}
		}
	}
	return result.String()
}

func (m *MixBase64) Decode(base64Str string) ([]byte, error) {
	chars := m.chars

	// 注意：移除了严格的字符预验证，与 Node.js alist-encrypt 行为一致
	// Node.js 版本在解码失败时用 try-catch 处理，不预验证字符
	// 这样可以兼容包含外部后缀（空格、括号等）的文件名
	// 无效字符会在实际解码时通过 mapChars 查找失败来处理

	// JS logic to calculate size
	// let size = (base64Str.length / 4) * 3
	size := (len(base64Str) / 4) * 3

	padChar := chars[64]
	if strings.Contains(base64Str, padChar+padChar) {
		size -= 2
	} else if strings.Contains(base64Str, padChar) {
		size -= 1
	}

	// buffer allocation
	buffer := make([]byte, size)
	j := 0
	i := 0

	runes := []rune(base64Str)
	length := len(runes)

	for i < length {
		enc1 := m.mapChars[string(runes[i])]
		i++
		// check bounds for subsequent chars
		if i >= length {
			break
		}
		enc2 := m.mapChars[string(runes[i])]
		i++
		if i >= length {
			break
		}
		enc3 := m.mapChars[string(runes[i])]
		i++
		if i >= length {
			break
		}
		enc4 := m.mapChars[string(runes[i])]
		i++

		// buffer.writeUInt8((enc1 << 2) | (enc2 >> 4), j++)
		if j < size {
			buffer[j] = byte((enc1 << 2) | (enc2 >> 4))
			j++
		}

		if enc3 != 64 {
			if j < size {
				buffer[j] = byte(((enc2 & 15) << 4) | (enc3 >> 2))
				j++
			}
		}
		if enc4 != 64 {
			if j < size {
				buffer[j] = byte(((enc3 & 3) << 6) | enc4)
				j++
			}
		}
	}
	return buffer, nil
}

func MixBase64GetSourceChar(index int) byte {
	return base64Source[index]
}
