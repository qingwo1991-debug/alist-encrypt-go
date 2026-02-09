package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha256"
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
	sourceIv []byte // Original IV for position seeking
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

	// Match Node.js logic: if password is already 32 chars (hex), skip PBKDF2
	passwdOutward := password
	if len(password) != 32 {
		key := pbkdf2.Key([]byte(password), []byte("AES-CTR"), 1000, 16, sha256.New)
		passwdOutward = hex.EncodeToString(key)
	}
	passwdSalt := passwdOutward + strconv.FormatInt(fileSize, 10)

	// Generate key and IV using MD5
	keyHash := md5.Sum([]byte(passwdSalt))
	a.key = keyHash[:]

	ivHash := md5.Sum([]byte(strconv.FormatInt(fileSize, 10)))
	a.iv = make([]byte, 16)
	copy(a.iv, ivHash[:])

	// Save original IV for position seeking
	a.sourceIv = make([]byte, 16)
	copy(a.sourceIv, a.iv)

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

	// Restore IV from sourceIv (matches OpenList-Encrypt behavior)
	a.iv = make([]byte, len(a.sourceIv))
	copy(a.iv, a.sourceIv)

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
// Must match Node.js alist-encrypt's aesCTR.js implementation exactly
func (a *AESCTR) incrementIV(increment int64) {
	// Match Node.js aesCTR.js incrementIV implementation
	const maxUint32 = uint64(0xffffffff)
	inc := uint64(increment)
	incrementBig := int64(inc / maxUint32)
	incrementLittle := int64(inc%maxUint32) - incrementBig

	overflow := int64(0)
	for idx := 0; idx < 4; idx++ {
		offset := 12 - idx*4
		num := int64(uint32(a.iv[offset])<<24 | uint32(a.iv[offset+1])<<16 |
			uint32(a.iv[offset+2])<<8 | uint32(a.iv[offset+3]))
		incPart := overflow
		if idx == 0 {
			incPart += incrementLittle
		}
		if idx == 1 {
			incPart += incrementBig
		}
		num += incPart
		numBig := num / int64(maxUint32)
		numLittle := num%int64(maxUint32) - numBig
		overflow = numBig
		v := uint32(numLittle)
		a.iv[offset] = byte(v >> 24)
		a.iv[offset+1] = byte(v >> 16)
		a.iv[offset+2] = byte(v >> 8)
		a.iv[offset+3] = byte(v)
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
