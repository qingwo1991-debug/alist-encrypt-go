package encryption

import (
	"net/url"
	"path"
	"strings"
)

// FileNameConverter handles filename encryption/decryption operations
type FileNameConverter struct {
	Password  string
	EncType   string
	EncSuffix string
}

// NewFileNameConverter creates a new filename converter
func NewFileNameConverter(password, encType, encSuffix string) *FileNameConverter {
	return &FileNameConverter{
		Password:  password,
		EncType:   encType,
		EncSuffix: encSuffix,
	}
}

// EncryptFileName encrypts a plain filename
func (c *FileNameConverter) EncryptFileName(plainName string) string {
	return EncodeName(c.Password, c.EncType, plainName)
}

// DecryptFileName decrypts an encrypted filename
func (c *FileNameConverter) DecryptFileName(encryptedName string) string {
	return DecodeName(c.Password, c.EncType, encryptedName)
}

// EncryptPath encrypts the filename portion of a path
func (c *FileNameConverter) EncryptPath(displayPath string) string {
	fileName := path.Base(displayPath)

	// Check if it's an original (unencrypted) file
	if strings.HasPrefix(fileName, OrigPrefix) {
		realName := strings.TrimPrefix(fileName, OrigPrefix)
		return path.Dir(displayPath) + "/" + realName
	}

	// URL decode the filename
	decoded, err := url.PathUnescape(fileName)
	if err != nil {
		decoded = fileName
	}

	ext := path.Ext(decoded)
	if c.EncSuffix != "" {
		ext = c.EncSuffix
	}

	baseName := strings.TrimSuffix(decoded, path.Ext(decoded))
	encName := c.EncryptFileName(baseName)

	return path.Dir(displayPath) + "/" + encName + ext
}

// DecryptPath decrypts the filename portion of a path
func (c *FileNameConverter) DecryptPath(encryptedPath string) string {
	// URL decode the path
	decoded, err := url.PathUnescape(encryptedPath)
	if err != nil {
		decoded = encryptedPath
	}

	fileName := path.Base(decoded)
	ext := path.Ext(fileName)
	encName := strings.TrimSuffix(fileName, ext)

	showName := c.DecryptFileName(encName)
	if showName == "" {
		return path.Dir(encryptedPath) + "/" + OrigPrefix + fileName
	}

	return path.Dir(encryptedPath) + "/" + showName
}

// ToDisplayName converts an encrypted filename to display name
func (c *FileNameConverter) ToDisplayName(pathText string) string {
	return ConvertShowName(c.Password, c.EncType, pathText)
}

// ToRealName converts a display filename to encrypted name
func (c *FileNameConverter) ToRealName(pathText string) string {
	return ConvertRealNameWithSuffix(c.Password, c.EncType, pathText, c.EncSuffix)
}

// IsOriginalFile checks if a filename is marked as original (failed decryption)
func IsOriginalFile(fileName string) bool {
	return strings.HasPrefix(fileName, OrigPrefix)
}

// StripOriginalPrefix removes the orig_ prefix from a filename
func StripOriginalPrefix(fileName string) string {
	return strings.TrimPrefix(fileName, OrigPrefix)
}
