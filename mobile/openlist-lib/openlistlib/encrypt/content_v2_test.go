package encrypt

import (
	"bytes"
	"io"
	"testing"
)

func TestAutoDecryptReaderSupportsV2AndLegacy(t *testing.T) {
	password := "test-password"
	plain := []byte("hello v2 content compatibility")

	for _, encType := range []EncryptionType{EncTypeAESCTR, EncTypeRC4, EncTypeChaCha20} {
		enc, err := NewLatestContentEncryptor(password, string(encType), int64(len(plain)))
		if err != nil {
			t.Fatalf("new latest encryptor %s: %v", encType, err)
		}
		reader, err := enc.EncryptReader(bytes.NewReader(plain), 0)
		if err != nil {
			t.Fatalf("encrypt reader %s: %v", encType, err)
		}
		ciphertext, err := io.ReadAll(reader)
		if err != nil {
			t.Fatalf("read ciphertext %s: %v", encType, err)
		}
		decReader, meta, err := AutoDecryptReader(password, encType, bytes.NewReader(ciphertext), int64(len(ciphertext)))
		if err != nil {
			t.Fatalf("auto decrypt %s: %v", encType, err)
		}
		got, err := io.ReadAll(decReader)
		if err != nil {
			t.Fatalf("read decrypted %s: %v", encType, err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("plaintext mismatch %s: got=%q want=%q", encType, got, plain)
		}
		if !meta.IsV2() {
			t.Fatalf("expected v2 meta for %s", encType)
		}
	}

	legacy, err := NewFlowEncryptor(password, EncTypeAESCTR, int64(len(plain)))
	if err != nil {
		t.Fatalf("new legacy encryptor: %v", err)
	}
	legacyReader := NewEncryptReader(bytes.NewReader(plain), legacy)
	legacyCiphertext, err := io.ReadAll(legacyReader)
	if err != nil {
		t.Fatalf("read legacy ciphertext: %v", err)
	}
	decReader, meta, err := AutoDecryptReader(password, EncTypeAESCTR, bytes.NewReader(legacyCiphertext), int64(len(legacyCiphertext)))
	if err != nil {
		t.Fatalf("auto decrypt legacy: %v", err)
	}
	got, err := io.ReadAll(decReader)
	if err != nil {
		t.Fatalf("read legacy plaintext: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("legacy plaintext mismatch: got=%q want=%q", got, plain)
	}
	if meta.IsV2() {
		t.Fatalf("expected legacy meta")
	}
}
