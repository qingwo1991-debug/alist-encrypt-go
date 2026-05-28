package encryption

import (
	"bytes"
	"io"
	"testing"
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
