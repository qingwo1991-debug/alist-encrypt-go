package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"

	"golang.org/x/crypto/pbkdf2"
)

// AESCTR implements AES-128-CTR encryption with position seeking support
type AESCTR struct {
	password string
	fileSize int64
	key      []byte
	iv       []byte
	block    cipher.Block
	stream   cipher.Stream
	position int64
}

// NewAESCTR creates a new AES-CTR cipher instance
func NewAESCTR(password string, fileSize int64) (*AESCTR, error) {
	a := &AESCTR{
		password: password,
		fileSize: fileSize,
	}

	// Key derivation using PBKDF2
	passwdOutward := pbkdf2.Key([]byte(password), []byte("AES-CTR"), 1000, 16, sha256.New)
	passwdSalt := hex.EncodeToString(passwdOutward) + strconv.FormatInt(fileSize, 10)

	// Generate key and IV using MD5
	keyHash := md5.Sum([]byte(passwdSalt))
	a.key = keyHash[:]

	ivHash := md5.Sum([]byte(strconv.FormatInt(fileSize, 10)))
	a.iv = make([]byte, 16)
	copy(a.iv, ivHash[:])

	// Create AES block cipher
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	a.block = block
	a.stream = cipher.NewCTR(block, a.iv)

	return a, nil
}

// SetPosition sets the stream position for seeking (video scrubbing support)
func (a *AESCTR) SetPosition(position int64) error {
	if position < 0 {
		return fmt.Errorf("position cannot be negative")
	}

	// Reset IV to original
	ivHash := md5.Sum([]byte(strconv.FormatInt(a.fileSize, 10)))
	a.iv = make([]byte, 16)
	copy(a.iv, ivHash[:])

	// Calculate how many 16-byte blocks to skip
	blockCount := position / 16

	// Increment IV counter by blockCount
	a.incrementIV(blockCount)

	// Create new CTR stream with updated IV
	a.stream = cipher.NewCTR(a.block, a.iv)

	// Discard partial block bytes
	offset := position % 16
	if offset > 0 {
		discard := make([]byte, offset)
		a.stream.XORKeyStream(discard, discard)
	}

	a.position = position
	return nil
}

// incrementIV increments the 128-bit IV counter by the given amount
func (a *AESCTR) incrementIV(count int64) {
	carry := uint64(count)
	lower := binary.BigEndian.Uint64(a.iv[8:16])
	newLower := lower + carry
	binary.BigEndian.PutUint64(a.iv[8:16], newLower)

	if newLower < lower {
		upper := binary.BigEndian.Uint64(a.iv[0:8])
		binary.BigEndian.PutUint64(a.iv[0:8], upper+1)
	}
}

// Position returns the current stream position
func (a *AESCTR) Position() int64 {
	return a.position
}

// Algorithm returns the cipher algorithm name
func (a *AESCTR) Algorithm() string {
	return "AES-128-CTR"
}

// BlockSize returns the cipher block size
func (a *AESCTR) BlockSize() int {
	return 16
}

// Encrypt encrypts data in place
func (a *AESCTR) Encrypt(data []byte) {
	a.stream.XORKeyStream(data, data)
	a.position += int64(len(data))
}

// Decrypt decrypts data in place (same as encrypt for CTR mode)
func (a *AESCTR) Decrypt(data []byte) {
	a.Encrypt(data)
}

// EncryptReader wraps a reader with encryption using base implementation
func (a *AESCTR) EncryptReader(r io.Reader) io.Reader {
	return WrapReaderFunc(r, a.Encrypt)
}

// DecryptReader wraps a reader with decryption
func (a *AESCTR) DecryptReader(r io.Reader) io.Reader {
	return a.EncryptReader(r) // CTR mode: encrypt == decrypt
}

// EncryptWriter wraps a writer with encryption using base implementation
func (a *AESCTR) EncryptWriter(w io.Writer) io.Writer {
	return WrapWriterFunc(w, a.Encrypt)
}
