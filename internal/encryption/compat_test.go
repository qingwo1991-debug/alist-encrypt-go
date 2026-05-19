package encryption

import (
	"bytes"
	"io"
	"testing"
)

func TestAESCTRRoundtrip(t *testing.T) {
	password := "test-password-123"
	fileSize := int64(1024 * 1024) // 1MB

	plaintext := make([]byte, 10000)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	enc, err := NewAESCTR(password, fileSize)
	if err != nil {
		t.Fatalf("NewAESCTR: %v", err)
	}

	encrypted := make([]byte, len(plaintext))
	copy(encrypted, plaintext)
	enc.Encrypt(encrypted)

	if bytes.Equal(encrypted, plaintext) {
		t.Fatal("encryption should change data")
	}

	dec, err := NewAESCTR(password, fileSize)
	if err != nil {
		t.Fatalf("NewAESCTR (dec): %v", err)
	}
	dec.Decrypt(encrypted)

	if !bytes.Equal(encrypted, plaintext) {
		t.Fatal("decryption should restore original data")
	}
}

func TestAESCTRPositionSeek(t *testing.T) {
	password := "seek-test"
	fileSize := int64(5000000)

	plaintext := make([]byte, 10000)
	for i := range plaintext {
		plaintext[i] = byte((i * 7) % 256)
	}

	// Encrypt from position 0
	enc, _ := NewAESCTR(password, fileSize)
	fullEncrypted := make([]byte, len(plaintext))
	copy(fullEncrypted, plaintext)
	enc.Encrypt(fullEncrypted)

	// Encrypt from position 5000
	enc2, _ := NewAESCTR(password, fileSize)
	enc2.SetPosition(5000)
	partialPlain := plaintext[5000:]
	partialEncrypted := make([]byte, len(partialPlain))
	copy(partialEncrypted, partialPlain)
	enc2.Encrypt(partialEncrypted)

	if !bytes.Equal(partialEncrypted, fullEncrypted[5000:]) {
		t.Fatal("partial encryption from offset should match full encryption")
	}

	// Decrypt from position 5000
	dec, _ := NewAESCTR(password, fileSize)
	dec.SetPosition(5000)
	dec.Decrypt(partialEncrypted)

	if !bytes.Equal(partialEncrypted, plaintext[5000:]) {
		t.Fatal("partial decryption should match original")
	}
}

func TestAESCTRStreamRoundtrip(t *testing.T) {
	password := "stream-test"
	fileSize := int64(50000)

	plaintext := bytes.Repeat([]byte("Hello, encrypted World! 你好加密世界 "), 100)

	enc, _ := NewAESCTR(password, fileSize)
	encryptedReader := enc.EncryptReader(bytes.NewReader(plaintext))
	encrypted, _ := io.ReadAll(encryptedReader)

	dec, _ := NewAESCTR(password, fileSize)
	decryptedReader := dec.DecryptReader(bytes.NewReader(encrypted))
	decrypted, _ := io.ReadAll(decryptedReader)

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("stream roundtrip failed: len(orig)=%d len(dec)=%d", len(plaintext), len(decrypted))
	}
}

func TestRC4MD5Roundtrip(t *testing.T) {
	password := "rc4-test-pass"
	fileSize := int64(2000000)

	plaintext := make([]byte, 50000)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	enc, err := NewRC4MD5(password, fileSize)
	if err != nil {
		t.Fatalf("NewRC4MD5: %v", err)
	}

	encrypted := make([]byte, len(plaintext))
	copy(encrypted, plaintext)
	enc.Encrypt(encrypted)

	if bytes.Equal(encrypted, plaintext) {
		t.Fatal("encryption should change data")
	}

	dec, _ := NewRC4MD5(password, fileSize)
	dec.Decrypt(encrypted)

	if !bytes.Equal(encrypted, plaintext) {
		t.Fatal("RC4 decryption should restore original data")
	}
}

func TestRC4MD5CrossSegment(t *testing.T) {
	password := "cross-seg-test"
	// File > segmentPosition (1M) to trigger segment resets
	fileSize := int64(2500000)

	// Data spanning across the 1M segment boundary
	plaintext := make([]byte, 1500000) // 1.5M
	for i := range plaintext {
		plaintext[i] = byte((i * 13) % 256)
	}

	enc, _ := NewRC4MD5(password, fileSize)
	encrypted := make([]byte, len(plaintext))
	copy(encrypted, plaintext)
	enc.Encrypt(encrypted)

	dec, _ := NewRC4MD5(password, fileSize)
	decrypted := make([]byte, len(encrypted))
	copy(decrypted, encrypted)
	dec.Decrypt(decrypted)

	if !bytes.Equal(decrypted, plaintext) {
		// Find first mismatch
		for i := range plaintext {
			if decrypted[i] != plaintext[i] {
				t.Fatalf("cross-segment mismatch at byte %d (segment boundary at %d): got %d want %d",
					i, segmentPosition, decrypted[i], plaintext[i])
			}
		}
	}
}

func TestFilenameEncodeDecode(t *testing.T) {
	names := []string{
		"oceans.mp4",
		"hello world 你好.mkv",
		"test-file-123.avi",
		"a",
		"very-long-filename-with-many-characters-1234567890.mp4",
	}

	for _, encType := range []string{"aesctr", "rc4md5"} {
		for _, name := range names {
			encoded := EncodeName("test-pass", encType, name)
			if encoded == "" {
				t.Errorf("encType=%s name=%q: encode returned empty", encType, name)
				continue
			}
			decoded := DecodeName("test-pass", encType, encoded)
			if decoded != name {
				t.Errorf("encType=%s name=%q: decoded=%q", encType, name, decoded)
			}
		}
	}
}

func TestFilenameDecodeWrongPassword(t *testing.T) {
	encoded := EncodeName("correct-pass", "aesctr", "test.mp4")
	decoded := DecodeName("wrong-pass", "aesctr", encoded)
	if decoded != "" {
		t.Errorf("wrong password should return empty, got %q", decoded)
	}
}

func TestFilenameCRC6Detection(t *testing.T) {
	encoded := EncodeName("pass123", "aesctr", "video.mp4")
	// Corrupt last char (CRC6)
	corrupted := encoded[:len(encoded)-1] + "X"
	decoded := DecodeName("pass123", "aesctr", corrupted)
	if decoded != "" {
		t.Errorf("corrupted CRC should return empty, got %q", decoded)
	}
}

func TestPasswdOutwardRC4Salt(t *testing.T) {
	// Verify that RC4 uses "RC4" PBKDF2 salt (compatibility with old Node.js)
	outward := GetPasswdOutward("test-password", "rc4md5")
	if outward == "" {
		t.Fatal("GetPasswdOutward returned empty")
	}
	// The outward should be different from AES-CTR since they use different salts
	outwardAES := GetPasswdOutward("test-password", "aesctr")
	if outward == outwardAES {
		t.Error("RC4 and AES-CTR passwdOutward should differ due to different PBKDF2 salts")
	}
}
