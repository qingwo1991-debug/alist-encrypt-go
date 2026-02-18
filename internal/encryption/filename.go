package encryption

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
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
	chars     [65]byte // 64 chars + padding char at index 64
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
	if len(base64Str)%4 != 0 {
		return nil, errors.New("invalid base64 string length")
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
// Uses cached PBKDF2 key and MixBase64 instance for performance
func EncodeName(password, encType, plainName string) string {
	passwdOutward := GetPasswdOutward(password, encType)
	mix64 := GetCachedMixBase64(passwdOutward)

	encodedName := mix64.EncodeString(plainName)

	// Calculate CRC6 checksum
	checkData := encodedName + passwdOutward
	crc6Bit := crc6.Checksum([]byte(checkData))
	crc6Check := GetSourceChar(crc6Bit)

	return encodedName + string(crc6Check)
}

// DecodeName decrypts a filename, returns empty string if decryption fails
// Uses cached PBKDF2 key and MixBase64 instance for performance
func DecodeName(password, encType, encodedName string) string {
	if len(encodedName) < 2 {
		return ""
	}

	crc6Check := encodedName[len(encodedName)-1]
	passwdOutward := GetPasswdOutward(password, encType)
	mix64 := GetCachedMixBase64(passwdOutward)

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

// DecodeNameLoose attempts decode without CRC verification and applies heuristics.
// Returns empty string if the result looks invalid.
func DecodeNameLoose(password, encType, encodedName string) string {
	if len(encodedName) < 2 {
		return ""
	}

	passwdOutward := GetPasswdOutward(password, encType)
	mix64 := GetCachedMixBase64(passwdOutward)

	subEncName := encodedName[:len(encodedName)-1]
	decoded, err := mix64.DecodeString(subEncName)
	if err != nil {
		return ""
	}
	if !isMostlyPrintable(decoded) {
		return ""
	}
	return decoded
}

// ConvertShowName converts encrypted filename to display name
func ConvertShowName(password, encType, pathText string) string {
	return ConvertShowNameWithSuffixOptions(password, encType, pathText, "", false)
}

// ConvertShowNameWithOptions converts encrypted filename to display name with optional loose decode.
func ConvertShowNameWithOptions(password, encType, pathText string, allowLoose bool) string {
	return ConvertShowNameWithSuffixOptions(password, encType, pathText, "", allowLoose)
}

// ConvertShowNameWithSuffixOptions converts encrypted filename to display name with
// optional configured encrypted suffix and loose decode fallback.
func ConvertShowNameWithSuffixOptions(password, encType, pathText, encSuffix string, allowLoose bool) string {
	// URL decode the path using PathUnescape (NOT QueryUnescape!)
	// QueryUnescape converts '+' to space, but '+' is valid in MixBase64
	decoded, err := url.PathUnescape(pathText)
	if err != nil {
		decoded = pathText
	}

	fileName := path.Base(decoded)
	ext := path.Ext(fileName)
	encName := strings.TrimSuffix(fileName, ext)
	normSuffix := NormalizeEncSuffix(encSuffix)

	// Keep legacy (faster) behavior when encrypted suffix is not in use.
	// Hidden extension flow is enabled only when the configured suffix matches.
	useHiddenSuffixFlow := normSuffix != "" && ext == normSuffix

	showName := ""
	dupSuffix := ""
	if !useHiddenSuffixFlow {
		showName = DecodeName(password, encType, encName)
		if showName == "" && allowLoose {
			showName = DecodeNameLoose(password, encType, encName)
		}
	} else {
		showName = DecodeName(password, encType, encName)
		if showName == "" {
			trimmed, suffix, ok := splitTrailingDuplicateSuffix(encName)
			if ok {
				showName = DecodeName(password, encType, trimmed)
				if showName != "" {
					dupSuffix = suffix
				}
			}
		}
		if showName == "" && allowLoose {
			showName = DecodeNameLoose(password, encType, encName)
			if showName == "" {
				trimmed, suffix, ok := splitTrailingDuplicateSuffix(encName)
				if ok {
					showName = DecodeNameLoose(password, encType, trimmed)
					if showName != "" {
						dupSuffix = suffix
					}
				}
			}
		}
	}
	if showName == "" {
		return OrigPrefix + fileName
	}
	if dupSuffix != "" {
		showName = appendDuplicateSuffix(showName, dupSuffix)
	}
	// Node.js logic: encrypted name includes extension; decrypted name does not append extension
	return showName
}

func splitTrailingDuplicateSuffix(name string) (trimmed, suffix string, ok bool) {
	if !strings.HasSuffix(name, ")") {
		return "", "", false
	}
	left := strings.LastIndex(name, "(")
	if left <= 0 || left >= len(name)-2 {
		return "", "", false
	}
	numText := name[left+1 : len(name)-1]
	n, err := strconv.Atoi(numText)
	if err != nil || n <= 0 {
		return "", "", false
	}
	return name[:left], name[left:], true
}

func appendDuplicateSuffix(fileName, suffix string) string {
	ext := path.Ext(fileName)
	if ext == "" {
		return fileName + suffix
	}
	base := strings.TrimSuffix(fileName, ext)
	return base + suffix + ext
}

// ConvertRealName converts display filename to encrypted name
func ConvertRealName(password, encType, pathText string) string {
	fileName := path.Base(pathText)

	// Check if it's an original (unencrypted) file
	if strings.HasPrefix(fileName, OrigPrefix) {
		return strings.TrimPrefix(fileName, OrigPrefix)
	}

	// URL decode the filename using PathUnescape (NOT QueryUnescape!)
	// QueryUnescape converts '+' to space, but '+' is valid in MixBase64
	decoded, err := url.PathUnescape(fileName)
	if err != nil {
		decoded = fileName
	}

	ext := path.Ext(decoded)

	// 与 OpenList-Encrypt 一致：加密完整文件名（含扩展名），然后再加扩展名
	// Encrypt the complete filename (including extension), then add extension again
	encName := EncodeName(password, encType, decoded)

	return encName + ext
}

// ConvertRealNameWithSuffix converts display filename to encrypted name with custom suffix
func ConvertRealNameWithSuffix(password, encType, pathText, encSuffix string) string {
	fileName := path.Base(pathText)

	// Check if it's an original (unencrypted) file
	if strings.HasPrefix(fileName, OrigPrefix) {
		return strings.TrimPrefix(fileName, OrigPrefix)
	}

	// URL decode the filename using PathUnescape (NOT QueryUnescape!)
	// QueryUnescape converts '+' to space, but '+' is valid in MixBase64
	decoded, err := url.PathUnescape(fileName)
	if err != nil {
		decoded = fileName
	}

	ext := path.Ext(decoded)
	encSuffix = NormalizeEncSuffix(encSuffix)
	if encSuffix != "" {
		ext = encSuffix
	}

	// Keep behavior consistent with upload/display flow:
	// encrypt full filename (including original extension), then append output suffix.
	encName := EncodeName(password, encType, decoded)

	return encName + ext
}

// NormalizeEncSuffix normalizes configured encrypted suffix:
// empty stays empty; non-empty always starts with dot.
func NormalizeEncSuffix(encSuffix string) string {
	encSuffix = strings.TrimSpace(encSuffix)
	if encSuffix == "" {
		return ""
	}
	if strings.HasPrefix(encSuffix, ".") {
		return encSuffix
	}
	return "." + encSuffix
}

// EncodeFolderName encodes folder password info
func EncodeFolderName(password, encType, folderPasswd, folderEncType string) string {
	passwdInfo := folderEncType + "_" + folderPasswd
	return EncodeName(password, encType, passwdInfo)
}

// DecodeFolderName decodes folder password info
func DecodeFolderName(password, encType, encodedName string) (folderEncType, folderPasswd string, ok bool) {
	encodedName = strings.TrimSpace(encodedName)
	if encodedName == "" {
		return "", "", false
	}

	// Primary path: encodedName is the direct output of EncodeFolderName.
	decoded := DecodeName(password, encType, encodedName)
	if decoded == "" {
		// Backward-compatibility: allow legacy "prefix_<encoded>" format.
		if idx := strings.LastIndex(encodedName, "_"); idx >= 0 && idx+1 < len(encodedName) {
			decoded = DecodeName(password, encType, encodedName[idx+1:])
		}
	}
	if decoded == "" {
		return "", "", false
	}

	sep := strings.Index(decoded, "_")
	if sep < 0 {
		return "", "", false
	}

	return decoded[:sep], decoded[sep+1:], true
}

func isMostlyPrintable(s string) bool {
	if s == "" || !utf8.ValidString(s) {
		return false
	}
	total := 0
	printable := 0
	for _, r := range s {
		total++
		if r == 0 {
			return false
		}
		if unicode.IsPrint(r) {
			printable++
		}
	}
	if total == 0 {
		return false
	}
	return printable*100/total >= 85
}

// PathMatcher checks if a path matches encryption patterns
type PathMatcher struct {
	patterns []string
}

// NewPathMatcher creates a new path matcher from pattern strings
func NewPathMatcher(patterns []string) *PathMatcher {
	return &PathMatcher{patterns: patterns}
}

// Match checks if path matches any pattern
func (pm *PathMatcher) Match(urlPath string) bool {
	for _, pattern := range pm.patterns {
		if pathMatchOne(pattern, urlPath) {
			return true
		}
	}
	return false
}

// PathExec checks if URL matches any encryption path pattern
func PathExec(encPaths []string, urlPath string) bool {
	for _, pattern := range encPaths {
		if pathMatchOne(pattern, urlPath) {
			return true
		}
	}
	return false
}

func pathMatchOne(pattern, urlPath string) bool {
	pattern = strings.TrimSpace(pattern)
	urlPath = strings.TrimSpace(urlPath)
	if pattern == "" || urlPath == "" {
		return false
	}
	if !strings.HasPrefix(pattern, "/") && !looksLikeRegexPattern(pattern) {
		pattern = "/" + pattern
	}
	if !strings.HasPrefix(urlPath, "/") {
		urlPath = "/" + urlPath
	}

	for _, expanded := range expandRuntimePathPatterns(pattern) {
		if matchPattern(expanded, urlPath) {
			return true
		}
	}
	return false
}

func expandRuntimePathPatterns(base string) []string {
	if looksLikeRegexPattern(base) {
		return []string{base}
	}

	out := make([]string, 0, 4)
	seen := make(map[string]struct{}, 4)
	appendUnique := func(v string) {
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}

	appendUnique(base)
	appendUnique("/d" + base)
	appendUnique("/p" + base)
	appendUnique("/dav" + base)

	return out
}

func matchPattern(pattern, urlPath string) bool {
	// For common "dir/*" rules, include direct directory path.
	if strings.HasSuffix(pattern, "/*") {
		dir := strings.TrimSuffix(pattern, "/*")
		if urlPath == dir || urlPath == dir+"/" {
			return true
		}
	}

	regexPattern := wildcardToRegex(pattern)
	re, err := regexp.Compile(regexPattern)
	if err != nil {
		return false
	}
	if re.MatchString(urlPath) {
		return true
	}

	// Compatibility fallback: old config treated patterns as regular expressions.
	if legacyRe, err := regexp.Compile(pattern); err == nil {
		return legacyRe.MatchString(urlPath)
	}
	return false
}

func wildcardToRegex(pattern string) string {
	var b strings.Builder
	b.WriteString("^")
	for _, r := range pattern {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			if strings.ContainsRune(`.+()[]{}|^$\\`, r) {
				b.WriteByte('\\')
			}
			b.WriteRune(r)
		}
	}
	b.WriteString("$")
	return b.String()
}

func looksLikeRegexPattern(pattern string) bool {
	return strings.ContainsAny(pattern, "^$()[]{}|\\.+")
}
