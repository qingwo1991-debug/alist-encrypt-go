package encryption

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"sync"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/pbkdf2"
)

// Buffer pool for ChaCha20 encryption
var chacha20BufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 64*1024)
		return &buf
	},
}

// ChaCha20 implements ChaCha20 encryption with position seeking support
// ChaCha20 is ideal for CPUs without AES-NI (like J4125) - 3-5x faster than software AES
type ChaCha20Cipher struct {
	password string
	fileSize int64
	key      []byte
	nonce    []byte
	cipher   *chacha20.Cipher
	position int64
}

// NewChaCha20 creates a new ChaCha20 cipher instance
func NewChaCha20(password string, fileSize int64) (*ChaCha20Cipher, error) {
	c := &ChaCha20Cipher{
		password: password,
		fileSize: fileSize,
	}

	// Key derivation using PBKDF2 - 32 bytes for ChaCha20
	passwdOutward := pbkdf2.Key([]byte(password), []byte("ChaCha20"), 1000, 32, sha256.New)
	passwdSalt := hex.EncodeToString(passwdOutward) + strconv.FormatInt(fileSize, 10)

	// Generate 32-byte key using SHA256
	keyHash := sha256.Sum256([]byte(passwdSalt))
	c.key = keyHash[:]

	// Generate 12-byte nonce (ChaCha20 standard nonce size)
	nonceHash := md5.Sum([]byte(strconv.FormatInt(fileSize, 10)))
	c.nonce = nonceHash[:12]

	// Create ChaCha20 cipher
	cipher, err := chacha20.NewUnauthenticatedCipher(c.key, c.nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to create ChaCha20 cipher: %w", err)
	}
	c.cipher = cipher

	return c, nil
}

// SetPosition sets the stream position for seeking (video scrubbing support)
// ChaCha20 supports O(1) random access like AES-CTR
func (c *ChaCha20Cipher) SetPosition(position int64) error {
	if position < 0 {
		return fmt.Errorf("position cannot be negative")
	}

	// ChaCha20 uses 64-byte blocks, calculate block number
	blockCount := uint32(position / 64)

	// Recreate cipher and set counter
	cipher, err := chacha20.NewUnauthenticatedCipher(c.key, c.nonce)
	if err != nil {
		return fmt.Errorf("failed to create ChaCha20 cipher: %w", err)
	}
	cipher.SetCounter(blockCount)
	c.cipher = cipher

	// Discard partial block bytes
	offset := position % 64
	if offset > 0 {
		discard := make([]byte, offset)
		c.cipher.XORKeyStream(discard, discard)
	}

	c.position = position
	return nil
}

// Encrypt encrypts data in place
func (c *ChaCha20Cipher) Encrypt(data []byte) {
	c.cipher.XORKeyStream(data, data)
	c.position += int64(len(data))
}

// Decrypt decrypts data in place (same as encrypt for stream ciphers)
func (c *ChaCha20Cipher) Decrypt(data []byte) {
	c.Encrypt(data)
}

// EncryptReader wraps a reader with encryption
func (c *ChaCha20Cipher) EncryptReader(r io.Reader) io.Reader {
	return &chacha20Reader{
		reader: r,
		cipher: c,
	}
}

// DecryptReader wraps a reader with decryption
func (c *ChaCha20Cipher) DecryptReader(r io.Reader) io.Reader {
	return c.EncryptReader(r) // Stream cipher: encrypt == decrypt
}

type chacha20Reader struct {
	reader io.Reader
	cipher *ChaCha20Cipher
}

func (r *chacha20Reader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		r.cipher.Decrypt(p[:n])
	}
	return n, err
}

// EncryptWriter wraps a writer with encryption
func (c *ChaCha20Cipher) EncryptWriter(w io.Writer) io.Writer {
	return &chacha20Writer{
		writer: w,
		cipher: c,
	}
}

type chacha20Writer struct {
	writer io.Writer
	cipher *ChaCha20Cipher
}

func (w *chacha20Writer) Write(p []byte) (int, error) {
	// Use buffer pool for small writes
	var encrypted []byte
	if len(p) <= 64*1024 {
		bufPtr := chacha20BufferPool.Get().(*[]byte)
		defer chacha20BufferPool.Put(bufPtr)
		encrypted = (*bufPtr)[:len(p)]
	} else {
		encrypted = make([]byte, len(p))
	}
	copy(encrypted, p)
	w.cipher.Encrypt(encrypted)
	return w.writer.Write(encrypted)
}

// GetPasswdOutwardChaCha20 generates the outward password key for filename encryption
func GetPasswdOutwardChaCha20(password string) string {
	key := pbkdf2.Key([]byte(password), []byte("ChaCha20"), 1000, 16, sha256.New)
	return hex.EncodeToString(key)
}

// BenchmarkInfo returns info about ChaCha20 advantages
func (c *ChaCha20Cipher) BenchmarkInfo() string {
	return "ChaCha20: Optimal for CPUs without AES-NI (J4125, ARM). O(1) seek support. 3-5x faster than software AES."
}

// SupportsHardwareAcceleration returns false as ChaCha20 is pure software
// but designed to be fast in software (unlike AES which needs AES-NI)
func (c *ChaCha20Cipher) SupportsHardwareAcceleration() bool {
	return false
}

// BlockSize returns the ChaCha20 block size
func (c *ChaCha20Cipher) BlockSize() int {
	return 64
}

// NonceSize returns the nonce size used
func (c *ChaCha20Cipher) NonceSize() int {
	return 12
}

// Counter returns the current block counter based on position
func (c *ChaCha20Cipher) Counter() uint32 {
	return uint32(c.position / 64)
}

// GetPosition returns the current stream position
func (c *ChaCha20Cipher) GetPosition() int64 {
	return c.position
}

// incrementCounter is used internally for counter manipulation
func incrementCounter(counter []byte, count int64) {
	carry := uint64(count)
	lower := binary.LittleEndian.Uint64(counter[0:8])
	newLower := lower + carry
	binary.LittleEndian.PutUint64(counter[0:8], newLower)

	if newLower < lower && len(counter) >= 16 {
		upper := binary.LittleEndian.Uint64(counter[8:16])
		binary.LittleEndian.PutUint64(counter[8:16], upper+1)
	}
}
