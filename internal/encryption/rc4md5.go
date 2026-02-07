package encryption

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"

	"golang.org/x/crypto/pbkdf2"
)

const segmentPosition = 1000000 // 1MB segments for RC4-MD5

// RC4MD5 implements RC4-MD5 encryption with segmentation
type RC4MD5 struct {
	password   string
	fileSize   int64
	fileHexKey string    // Store hex key for segment resets
	key        []byte
	position   int64
	i, j       int       // RC4 state indices
	sbox       [256]byte // RC4 S-box
}

// NewRC4MD5 creates a new RC4-MD5 cipher instance
func NewRC4MD5(password string, fileSize int64) (*RC4MD5, error) {
	r := &RC4MD5{
		password: password,
		fileSize: fileSize,
	}

	// Step 1: PBKDF2 derivation (matching Node.js)
	passwdOutward := password
	if len(password) != 32 {
		key := pbkdf2.Key([]byte(password), []byte("RC4"), 1000, 16, sha256.New)
		passwdOutward = hex.EncodeToString(key)
	}

	// Step 2: Combine with file size (as string)
	passwdSalt := passwdOutward + strconv.FormatInt(fileSize, 10)

	// Step 3: MD5 hash to get hex key
	hash := md5.Sum([]byte(passwdSalt))
	r.fileHexKey = hex.EncodeToString(hash[:])

	// Step 4: Convert hex to binary key
	r.key, _ = hex.DecodeString(r.fileHexKey)

	// Initialize KSA with original key
	if err := r.resetKSA(); err != nil {
		return nil, err
	}

	return r, nil
}

// resetKSA resets the RC4 KSA (Key Scheduling Algorithm) for current segment
func (r *RC4MD5) resetKSA() error {
	// Calculate segment offset (0, 1000000, 2000000, ...)
	offset := (r.position / segmentPosition) * segmentPosition

	// Convert offset to 4-byte big-endian
	offsetBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(offsetBuf, uint32(offset))

	// Decode hex key to binary
	rc4Key, _ := hex.DecodeString(r.fileHexKey)

	// XOR offset into last 4 bytes of key
	j := len(rc4Key) - 4
	for i := 0; i < 4; i++ {
		rc4Key[j+i] ^= offsetBuf[i]
	}

	// Initialize KSA with modified key
	return r.initKSA(rc4Key)
}

// initKSA initializes the RC4 S-box using KSA algorithm
func (r *RC4MD5) initKSA(key []byte) error {
	// Standard RC4 KSA
	K := make([]byte, 256)
	for i := 0; i < 256; i++ {
		r.sbox[i] = byte(i)
		K[i] = key[i%len(key)]
	}

	j := 0
	for i := 0; i < 256; i++ {
		j = (j + int(r.sbox[i]) + int(K[i])) % 256
		r.sbox[i], r.sbox[j] = r.sbox[j], r.sbox[i]
	}

	r.i = 0
	r.j = 0
	return nil
}

// SetPosition sets the stream position for range requests
func (r *RC4MD5) SetPosition(position int64) error {
	if position < 0 {
		return fmt.Errorf("position cannot be negative")
	}

	r.position = position

	// Reset to current segment's key
	if err := r.resetKSA(); err != nil {
		return err
	}

	// Advance within segment
	offset := position % segmentPosition
	if offset > 0 {
		r.prgaAdvance(int(offset))
	}

	return nil
}

// prgaAdvance advances the PRGA without producing output
func (r *RC4MD5) prgaAdvance(count int) {
	for k := 0; k < count; k++ {
		r.i = (r.i + 1) % 256
		r.j = (r.j + int(r.sbox[r.i])) % 256
		r.sbox[r.i], r.sbox[r.j] = r.sbox[r.j], r.sbox[r.i]
	}
}

// Position returns the current stream position
func (r *RC4MD5) Position() int64 {
	return r.position
}

// Algorithm returns the cipher algorithm name
func (r *RC4MD5) Algorithm() string {
	return "RC4-MD5"
}

// BlockSize returns the cipher block size (RC4 is a stream cipher, returns 1)
func (r *RC4MD5) BlockSize() int {
	return 1
}

// Encrypt encrypts data in place with segmentation
func (r *RC4MD5) Encrypt(data []byte) {
	for k := 0; k < len(data); k++ {
		r.i = (r.i + 1) % 256
		r.j = (r.j + int(r.sbox[r.i])) % 256

		// Swap
		r.sbox[r.i], r.sbox[r.j] = r.sbox[r.j], r.sbox[r.i]

		// XOR with keystream
		data[k] ^= r.sbox[(int(r.sbox[r.i])+int(r.sbox[r.j]))%256]

		r.position++

		// Reset every 1MB
		if r.position%segmentPosition == 0 {
			r.resetKSA()
		}
	}
}

// Decrypt decrypts data in place (same as encrypt for RC4)
func (r *RC4MD5) Decrypt(data []byte) {
	r.Encrypt(data)
}

// EncryptReader wraps a reader with encryption using base implementation
func (r *RC4MD5) EncryptReader(reader io.Reader) io.Reader {
	return WrapReaderFunc(reader, r.Encrypt)
}

// DecryptReader wraps a reader with decryption
func (r *RC4MD5) DecryptReader(reader io.Reader) io.Reader {
	return r.EncryptReader(reader)
}

// EncryptWriter wraps a writer with encryption using base implementation
func (r *RC4MD5) EncryptWriter(writer io.Writer) io.Writer {
	return WrapWriterFunc(writer, r.Encrypt)
}

// KeyHex returns the hex-encoded key for debugging
func (r *RC4MD5) KeyHex() string {
	return r.fileHexKey
}
