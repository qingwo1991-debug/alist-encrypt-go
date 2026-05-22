package encrypt

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/pbkdf2"
)

// ChaCha20Encryptor ChaCha20 流加密器（与 alist-encrypt-go 密钥派生对齐）
//
// 密钥派生：pbkdf2(password, "ChaCha20", 1000, 32, sha256) → hex → passwdOutward
//           sha256(passwdOutward + strconv.FormatInt(fileSize, 10)) → 32-byte key
//           md5(strconv.FormatInt(fileSize, 10))[:12] → 12-byte nonce
//
// 此版本与旧版（双 md5 拼接）不兼容。
type ChaCha20Encryptor struct {
	key      []byte
	nonce    []byte
	cipher   *chacha20.Cipher
	position int64
}

// GetPasswdOutwardChaCha20 生成 ChaCha20 的 passwdOutward（与 alist-encrypt-go 一致）
func GetPasswdOutwardChaCha20(password string) string {
	key := pbkdf2.Key([]byte(password), []byte("ChaCha20"), 1000, 32, sha256.New)
	return hex.EncodeToString(key)
}

// NewChaCha20Encryptor 创建 ChaCha20 加密器（与 alist-encrypt-go 兼容）
func NewChaCha20Encryptor(password, passwdOutward string, fileSize int64) (*ChaCha20Encryptor, error) {
	sizeSalt := strconv.FormatInt(fileSize, 10)
	passwdSalt := passwdOutward + sizeSalt

	// 与 alist-encrypt-go 一致：sha256(passwdSalt) 作为 key
	keyHash := sha256.Sum256([]byte(passwdSalt))
	key := keyHash[:]

	// 与 alist-encrypt-go 一致：md5(sizeSalt)[:12] 作为 nonce
	nonceHash := md5.Sum([]byte(sizeSalt))
	nonce := nonceHash[:12]

	c, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to create ChaCha20 cipher: %w", err)
	}

	return &ChaCha20Encryptor{
		key:      key,
		nonce:    nonce,
		cipher:   c,
		position: 0,
	}, nil
}

// SetPosition 设置流位置（O(1) 随机访问）
func (c *ChaCha20Encryptor) SetPosition(position int64) error {
	if position < 0 {
		return fmt.Errorf("position cannot be negative")
	}

	blockCount := uint32(position / 64)

	newCipher, err := chacha20.NewUnauthenticatedCipher(c.key, c.nonce)
	if err != nil {
		return fmt.Errorf("failed to recreate ChaCha20 cipher: %w", err)
	}
	newCipher.SetCounter(blockCount)
	c.cipher = newCipher

	// 丢弃块内偏移字节
	offset := int(position % 64)
	if offset > 0 {
		discard := make([]byte, offset)
		c.cipher.XORKeyStream(discard, discard)
	}

	c.position = position
	return nil
}

// GetPosition 获取当前位置
func (c *ChaCha20Encryptor) GetPosition() int64 {
	return c.position
}

// Encrypt 加密数据（返回新切片，兼容 FlowEncryptor 接口）
func (c *ChaCha20Encryptor) Encrypt(data []byte) ([]byte, error) {
	result := make([]byte, len(data))
	c.cipher.XORKeyStream(result, data)
	c.position += int64(len(data))
	return result, nil
}

// Decrypt 解密数据（ChaCha20 是对称的）
func (c *ChaCha20Encryptor) Decrypt(data []byte) ([]byte, error) {
	return c.Encrypt(data)
}

// EncryptInplace 原地加密（减少内存分配）
func (c *ChaCha20Encryptor) EncryptInplace(data []byte) error {
	c.cipher.XORKeyStream(data, data)
	c.position += int64(len(data))
	return nil
}

// DecryptInplace 原地解密（ChaCha20 对称）
func (c *ChaCha20Encryptor) DecryptInplace(data []byte) error {
	return c.EncryptInplace(data)
}

// EncryptReader 返回加密 io.Reader（适配 proxy.go 使用）
func (c *ChaCha20Encryptor) EncryptReader(r io.Reader) io.Reader {
	return &chacha20Reader{r: r, enc: c}
}

type chacha20Reader struct {
	r   io.Reader
	enc *ChaCha20Encryptor
}

func (cr *chacha20Reader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	if n > 0 {
		_ = cr.enc.EncryptInplace(p[:n])
	}
	return n, err
}
