package encryption

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"
)

func TestLatestContentEncryptorRoundtripAllAlgorithms(t *testing.T) {
	plain := bytes.Repeat([]byte("content-v2-roundtrip-"), 128)
	for _, encType := range []string{"aesctr", "chacha20", "rc4md5"} {
		t.Run(encType, func(t *testing.T) {
			enc, err := NewLatestContentEncryptor("test-password", encType, int64(len(plain)))
			if err != nil {
				t.Fatalf("new latest encryptor: %v", err)
			}
			reader, err := enc.EncryptReader(bytes.NewReader(plain), 0)
			if err != nil {
				t.Fatalf("encrypt reader: %v", err)
			}
			ciphertext, err := io.ReadAll(reader)
			if err != nil {
				t.Fatalf("read ciphertext: %v", err)
			}
			meta, ok, err := ParseContentHeader(EncType(encType), ciphertext, int64(len(ciphertext)))
			if err != nil || !ok {
				t.Fatalf("parse header ok=%v err=%v", ok, err)
			}
			if meta.PlainSize != int64(len(plain)) {
				t.Fatalf("plainSize=%d want=%d", meta.PlainSize, len(plain))
			}
			decReader, decMeta, err := AutoDecryptReader("test-password", EncType(encType), bytes.NewReader(ciphertext), int64(len(ciphertext)))
			if err != nil {
				t.Fatalf("auto decrypt reader: %v", err)
			}
			if !decMeta.IsV2() {
				t.Fatal("expected v2 meta")
			}
			decrypted, err := io.ReadAll(decReader)
			if err != nil {
				t.Fatalf("read decrypted: %v", err)
			}
			if !bytes.Equal(decrypted, plain) {
				t.Fatalf("decrypted mismatch")
			}
		})
	}
}

func TestLatestContentEncryptorUsesRandomNonceField(t *testing.T) {
	plain := []byte("same-size-same-password")
	first, err := NewLatestContentEncryptor("test-password", "aesctr", int64(len(plain)))
	if err != nil {
		t.Fatalf("first encryptor: %v", err)
	}
	second, err := NewLatestContentEncryptor("test-password", "aesctr", int64(len(plain)))
	if err != nil {
		t.Fatalf("second encryptor: %v", err)
	}
	if bytes.Equal(first.Header, second.Header) {
		t.Fatal("expected random v2 headers to differ")
	}
}

func TestAutoDecryptReaderMaintainsLegacyCompatibility(t *testing.T) {
	password := "legacy-password"
	fileSize := int64(4096)
	plain := bytes.Repeat([]byte("legacy-plain-"), 256)
	legacy, err := NewFlowEnc(password, "aesctr", fileSize)
	if err != nil {
		t.Fatalf("legacy flow: %v", err)
	}
	reader := legacy.EncryptReader(bytes.NewReader(plain))
	ciphertext, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read ciphertext: %v", err)
	}
	decReader, meta, err := AutoDecryptReader(password, EncTypeAESCTR, bytes.NewReader(ciphertext), fileSize)
	if err != nil {
		t.Fatalf("auto decrypt reader: %v", err)
	}
	if meta.IsV2() {
		t.Fatal("legacy ciphertext should not be detected as v2")
	}
	decrypted, err := io.ReadAll(decReader)
	if err != nil {
		t.Fatalf("read decrypted: %v", err)
	}
	if !bytes.Equal(decrypted, plain) {
		t.Fatalf("legacy decrypt mismatch")
	}
}

func TestV2PBKDF2CacheDoesNotSplitByNonce(t *testing.T) {
	v2KeyCacheMu.Lock()
	v2KeyCache = make(map[string]*cacheEntry[[]byte])
	v2KeyCacheMu.Unlock()
	SetV2KeyCacheTTL(24 * time.Hour)

	nonceA := bytes.Repeat([]byte{0x01}, 16)
	nonceB := bytes.Repeat([]byte{0x02}, 16)
	if _, err := NewAESCTRV2("same-password", 1024, nonceA); err != nil {
		t.Fatalf("first cipher: %v", err)
	}
	if _, err := NewAESCTRV2("same-password", 1024, nonceB); err != nil {
		t.Fatalf("second cipher: %v", err)
	}

	v2KeyCacheMu.RLock()
	defer v2KeyCacheMu.RUnlock()
	if got := len(v2KeyCache); got != 1 {
		t.Fatalf("v2 key cache entries=%d, want 1", got)
	}
	for key := range v2KeyCache {
		if strings.Contains(key, "same-password") {
			t.Fatalf("v2 key cache key contains plaintext password: %q", key)
		}
	}
}

func TestV2PBKDF2CacheHitExtendsTTL(t *testing.T) {
	v2KeyCacheMu.Lock()
	v2KeyCache = make(map[string]*cacheEntry[[]byte])
	v2KeyCacheMu.Unlock()
	SetV2KeyCacheTTL(time.Hour)

	nonce := bytes.Repeat([]byte{0x03}, 16)
	if _, err := NewAESCTRV2("sliding-password", 1024, nonce); err != nil {
		t.Fatalf("first cipher: %v", err)
	}

	var oldExpire time.Time
	v2KeyCacheMu.Lock()
	for _, entry := range v2KeyCache {
		entry.expireAt = time.Now().Add(time.Millisecond)
		oldExpire = entry.expireAt
	}
	v2KeyCacheMu.Unlock()

	if _, err := NewAESCTRV2("sliding-password", 1024, nonce); err != nil {
		t.Fatalf("second cipher: %v", err)
	}

	v2KeyCacheMu.RLock()
	defer v2KeyCacheMu.RUnlock()
	for _, entry := range v2KeyCache {
		if !entry.expireAt.After(oldExpire.Add(30 * time.Minute)) {
			t.Fatalf("cache hit did not extend ttl enough: old=%s new=%s", oldExpire, entry.expireAt)
		}
	}
}
