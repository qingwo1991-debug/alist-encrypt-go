package encryption

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"net/url"
	"path"
	"regexp"
	"strings"
)

const (
	// OrigPrefix marks files that failed decryption
	OrigPrefix = "orig_"
	// Base64 source characters (URL-safe, no padding '=')
	sourceChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~+"
)

// MixBase64 implements password-based Base64 encoding with KSA-shuffled alphabet
// This is a 1:1 port of the Node.js implementation
type MixBase64 struct {
	chars     [65]byte          // 64 chars + padding char at index 64
	decodeMap map[byte]int
}

// NewMixBase64 creates a new MixBase64 encoder with password-derived alphabet
func NewMixBase64(passwd string) *MixBase64 {
	m := &MixBase64{
		decodeMap: make(map[byte]int),
	}

	var secret string
	if len(passwd) == 64 {
		secret = passwd
	} else {
		secret = initKSA(passwd + "mix64")
	}

	// Build encode map
	for i := 0; i < 64; i++ {
		m.chars[i] = secret[i]
	}
	// Padding character is the 65th char (index 64)
	if len(secret) > 64 {
		m.chars[64] = secret[64]
	} else {
		m.chars[64] = '+'
	}

	// Build decode map
	for i := 0; i < 65; i++ {
		m.decodeMap[m.chars[i]] = i
	}

	return m
}

// initKSA implements the Key Scheduling Algorithm for shuffling the alphabet
// This is identical to the Node.js implementation
func initKSA(passwd string) string {
	// Generate SHA256 hash of password
	key := sha256.Sum256([]byte(passwd))

	// Initialize S-box
	sbox := make([]int, len(sourceChars))
	for i := range sbox {
		sbox[i] = i
	}

	// Fill K array with key bytes
	K := make([]byte, len(sourceChars))
	for i := 0; i < len(sourceChars); i++ {
		K[i] = key[i%len(key)]
	}

	// Shuffle S-box using KSA
	j := 0
	for i := 0; i < len(sourceChars); i++ {
		j = (j + sbox[i] + int(K[i])) % len(sourceChars)
		sbox[i], sbox[j] = sbox[j], sbox[i]
	}

	// Build shuffled secret string
	sourceBytes := []byte(sourceChars)
	var secret bytes.Buffer
	for _, idx := range sbox {
		secret.WriteByte(sourceBytes[idx])
	}

	return secret.String()
}

// Encode encodes data to MixBase64 string
func (m *MixBase64) Encode(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	var result bytes.Buffer

	// Process 3 bytes at a time
	i := 0
	for ; i+3 <= len(data); i += 3 {
		b0, b1, b2 := data[i], data[i+1], data[i+2]
		result.WriteByte(m.chars[b0>>2])
		result.WriteByte(m.chars[((b0&3)<<4)|(b1>>4)])
		result.WriteByte(m.chars[((b1&15)<<2)|(b2>>6)])
		result.WriteByte(m.chars[b2&63])
	}

	// Handle remaining bytes
	remaining := len(data) - i
	if remaining == 1 {
		b0 := data[i]
		result.WriteByte(m.chars[b0>>2])
		result.WriteByte(m.chars[(b0&3)<<4])
		result.WriteByte(m.chars[64]) // padding
		result.WriteByte(m.chars[64]) // padding
	} else if remaining == 2 {
		b0, b1 := data[i], data[i+1]
		result.WriteByte(m.chars[b0>>2])
		result.WriteByte(m.chars[((b0&3)<<4)|(b1>>4)])
		result.WriteByte(m.chars[(b1&15)<<2])
		result.WriteByte(m.chars[64]) // padding
	}

	return result.String()
}

// EncodeString encodes a UTF-8 string
func (m *MixBase64) EncodeString(s string) string {
	return m.Encode([]byte(s))
}

// Decode decodes MixBase64 string to bytes
func (m *MixBase64) Decode(base64Str string) ([]byte, error) {
	if len(base64Str) == 0 {
		return nil, nil
	}

	// Calculate output size
	size := (len(base64Str) / 4) * 3
	paddingChar := string(m.chars[64])
	if strings.HasSuffix(base64Str, paddingChar+paddingChar) {
		size -= 2
	} else if strings.HasSuffix(base64Str, paddingChar) {
		size -= 1
	}

	buffer := make([]byte, size)
	j := 0

	for i := 0; i < len(base64Str); i += 4 {
		enc1, ok1 := m.decodeMap[base64Str[i]]
		enc2, ok2 := m.decodeMap[base64Str[i+1]]
		enc3, ok3 := m.decodeMap[base64Str[i+2]]
		enc4, ok4 := m.decodeMap[base64Str[i+3]]

		if !ok1 || !ok2 || !ok3 || !ok4 {
			return nil, errors.New("invalid character in base64 string")
		}

		buffer[j] = byte((enc1 << 2) | (enc2 >> 4))
		j++

		if enc3 != 64 && j < size {
			buffer[j] = byte(((enc2 & 15) << 4) | (enc3 >> 2))
			j++
		}
		if enc4 != 64 && j < size {
			buffer[j] = byte(((enc3 & 3) << 6) | enc4)
			j++
		}
	}

	return buffer[:j], nil
}

// DecodeString decodes MixBase64 string to UTF-8 string
func (m *MixBase64) DecodeString(base64Str string) (string, error) {
	data, err := m.Decode(base64Str)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// GetSourceChar returns the character at given index in source charset
func GetSourceChar(index int) byte {
	if index < 0 || index >= len(sourceChars) {
		return sourceChars[0]
	}
	return sourceChars[index]
}

// GetCheckBit calculates a check bit from text (sum of bytes mod 64)
func GetCheckBit(text string) byte {
	sum := 0
	for _, b := range []byte(text) {
		sum += int(b)
	}
	return sourceChars[sum%64]
}

// CRC6 calculates 6-bit CRC checksum using the same algorithm as Node.js version
type CRC6 struct {
	table [256]byte
}

// NewCRC6 creates a new CRC6 calculator
func NewCRC6() *CRC6 {
	c := &CRC6{}
	c.generateTable6()
	return c
}

// generateTable6 generates CRC6 lookup table
// Polynomial: x^6 + x + 1 (0x03), with input/output reflection built-in
func (c *CRC6) generateTable6() {
	for i := 0; i < 256; i++ {
		curr := byte(i)
		for j := 0; j < 8; j++ {
			if (curr & 0x01) != 0 {
				// 0x30 = (reverse 0x03) >> (8-6) = 00110000
				curr = ((curr >> 1) ^ 0x30)
			} else {
				curr = curr >> 1
			}
		}
		c.table[i] = curr
	}
}

// Checksum calculates CRC6 checksum of data
func (c *CRC6) Checksum(data []byte) int {
	crc := byte(0)
	for _, b := range data {
		crc = c.table[crc^b]
	}
	return int(crc)
}

// Global CRC6 instance
var crc6 = NewCRC6()

// EncodeName encrypts a filename using password and encryption type
func EncodeName(password, encType, plainName string) string {
	passwdOutward := GetPasswdOutward(password, encType)
	mix64 := NewMixBase64(passwdOutward)

	encodedName := mix64.EncodeString(plainName)

	// Calculate CRC6 checksum
	checkData := encodedName + passwdOutward
	crc6Bit := crc6.Checksum([]byte(checkData))
	crc6Check := GetSourceChar(crc6Bit)

	return encodedName + string(crc6Check)
}

// DecodeName decrypts a filename, returns empty string if decryption fails
func DecodeName(password, encType, encodedName string) string {
	if len(encodedName) < 2 {
		return ""
	}

	crc6Check := encodedName[len(encodedName)-1]
	passwdOutward := GetPasswdOutward(password, encType)
	mix64 := NewMixBase64(passwdOutward)

	subEncName := encodedName[:len(encodedName)-1]

	// Verify CRC6
	checkData := subEncName + passwdOutward
	crc6Bit := crc6.Checksum([]byte(checkData))
	if GetSourceChar(crc6Bit) != crc6Check {
		return ""
	}

	// Decode
	decoded, err := mix64.DecodeString(subEncName)
	if err != nil {
		return ""
	}

	return decoded
}

// ConvertShowName converts encrypted filename to display name
func ConvertShowName(password, encType, pathText string) string {
	// URL decode the path
	decoded, err := url.QueryUnescape(pathText)
	if err != nil {
		decoded = pathText
	}

	fileName := path.Base(decoded)
	ext := path.Ext(fileName)
	encName := strings.TrimSuffix(fileName, ext)

	showName := DecodeName(password, encType, encName)
	if showName == "" {
		return OrigPrefix + fileName
	}
	return showName
}

// ConvertRealName converts display filename to encrypted name
func ConvertRealName(password, encType, pathText string) string {
	fileName := path.Base(pathText)

	// Check if it's an original (unencrypted) file
	if strings.HasPrefix(fileName, OrigPrefix) {
		return strings.TrimPrefix(fileName, OrigPrefix)
	}

	// URL decode the filename
	decoded, err := url.QueryUnescape(fileName)
	if err != nil {
		decoded = fileName
	}

	ext := path.Ext(decoded)
	baseName := strings.TrimSuffix(decoded, ext)

	// Encrypt the filename
	encName := EncodeName(password, encType, baseName)

	return encName + ext
}

// ConvertRealNameWithSuffix converts display filename to encrypted name with custom suffix
func ConvertRealNameWithSuffix(password, encType, pathText, encSuffix string) string {
	fileName := path.Base(pathText)

	// Check if it's an original (unencrypted) file
	if strings.HasPrefix(fileName, OrigPrefix) {
		return strings.TrimPrefix(fileName, OrigPrefix)
	}

	// URL decode the filename
	decoded, err := url.QueryUnescape(fileName)
	if err != nil {
		decoded = fileName
	}

	ext := path.Ext(decoded)
	if encSuffix != "" {
		ext = encSuffix
	}

	baseName := strings.TrimSuffix(decoded, path.Ext(decoded))

	// Encrypt the filename
	encName := EncodeName(password, encType, baseName)

	return encName + ext
}

// EncodeFolderName encodes folder password info
func EncodeFolderName(password, encType, folderPasswd, folderEncType string) string {
	passwdInfo := folderEncType + "_" + folderPasswd
	return EncodeName(password, encType, passwdInfo)
}

// DecodeFolderName decodes folder password info
func DecodeFolderName(password, encType, encodedName string) (folderEncType, folderPasswd string, ok bool) {
	arr := strings.Split(encodedName, "_")
	if len(arr) < 2 {
		return "", "", false
	}

	folderEncName := arr[len(arr)-1]
	decoded := DecodeName(password, encType, folderEncName)
	if decoded == "" {
		return "", "", false
	}

	idx := strings.Index(decoded, "_")
	if idx < 0 {
		return "", "", false
	}

	return decoded[:idx], decoded[idx+1:], true
}

// PathMatcher checks if a path matches encryption patterns
type PathMatcher struct {
	patterns []*regexp.Regexp
}

// NewPathMatcher creates a new path matcher from pattern strings
func NewPathMatcher(patterns []string) *PathMatcher {
	pm := &PathMatcher{
		patterns: make([]*regexp.Regexp, 0, len(patterns)),
	}

	for _, p := range patterns {
		if re, err := regexp.Compile(p); err == nil {
			pm.patterns = append(pm.patterns, re)
		}
	}

	return pm
}

// Match checks if path matches any pattern
func (pm *PathMatcher) Match(urlPath string) bool {
	for _, re := range pm.patterns {
		if re.MatchString(urlPath) {
			return true
		}
	}
	return false
}

// PathExec checks if URL matches any encryption path pattern
func PathExec(encPaths []string, urlPath string) bool {
	for _, pattern := range encPaths {
		if re, err := regexp.Compile(pattern); err == nil {
			if re.MatchString(urlPath) {
				return true
			}
		}
	}
	return false
}
