package encrypt

import (
	"fmt"
	"testing"
)

func TestCollectV2KeyPrewarmSpecsDeduplicatesAndMapsCipher(t *testing.T) {
	config := &ProxyConfig{
		EncryptPaths: []*EncryptPath{
			{Password: "shared", EncType: EncTypeAESCTR, Enable: true},
			{Password: "shared", EncType: EncTypeAESCTR, Enable: true},
			{Password: "shared", EncType: EncTypeChaCha20, Enable: true},
			{Password: "rc4", EncType: EncTypeRC4, Enable: true},
			{Password: "disabled", EncType: EncTypeAESCTR, Enable: false},
			nil,
		},
	}

	got := collectV2KeyPrewarmSpecs(config)
	if len(got) != 3 {
		t.Fatalf("prewarm specs=%d, want 3: %#v", len(got), got)
	}
	if got[0].salt != "AES-CTR-v2" || got[0].keyLen != 16 {
		t.Fatalf("AES spec=%#v", got[0])
	}
	if got[1].salt != "ChaCha20-v2" || got[1].keyLen != 32 {
		t.Fatalf("ChaCha20 spec=%#v", got[1])
	}
	if got[2].salt != "RC4-v2" || got[2].keyLen != 16 {
		t.Fatalf("RC4 spec=%#v", got[2])
	}
}

func TestCollectV2KeyPrewarmSpecsIsBounded(t *testing.T) {
	config := &ProxyConfig{}
	for i := 0; i < v2KeyPrewarmMaxEntries+4; i++ {
		config.EncryptPaths = append(config.EncryptPaths, &EncryptPath{
			Password: fmt.Sprintf("password-%d", i),
			EncType:  EncTypeAESCTR,
			Enable:   true,
		})
	}

	got := collectV2KeyPrewarmSpecs(config)
	if len(got) != v2KeyPrewarmMaxEntries {
		t.Fatalf("prewarm specs=%d, want cap %d", len(got), v2KeyPrewarmMaxEntries)
	}
}
