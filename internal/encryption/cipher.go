package encryption

import "io"

// StreamCipher provides basic XOR key stream encryption
type StreamCipher interface {
	// XORKeyStream XORs data with the key stream in place
	XORKeyStream(data []byte)
}

// SeekableCipher extends StreamCipher with position seeking
type SeekableCipher interface {
	StreamCipher
	// SetPosition sets the stream position for seeking
	SetPosition(position int64) error
	// Position returns the current stream position
	Position() int64
}

// CipherInfo provides metadata about a cipher
type CipherInfo interface {
	// Algorithm returns the cipher algorithm name
	Algorithm() string
	// BlockSize returns the cipher block size
	BlockSize() int
}

// CipherReader wraps a reader with encryption/decryption
type CipherReader interface {
	io.Reader
}

// CipherWriter wraps a writer with encryption/decryption
type CipherWriter interface {
	io.Writer
}

// FullCipher combines all cipher capabilities
type FullCipher interface {
	SeekableCipher
	CipherInfo
	// Encrypt encrypts data in place
	Encrypt(data []byte)
	// Decrypt decrypts data in place
	Decrypt(data []byte)
	// EncryptReader wraps a reader with encryption
	EncryptReader(r io.Reader) io.Reader
	// DecryptReader wraps a reader with decryption
	DecryptReader(r io.Reader) io.Reader
}
