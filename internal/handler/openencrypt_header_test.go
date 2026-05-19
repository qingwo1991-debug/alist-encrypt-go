package handler

import (
	"net/http"
	"testing"
)

func TestPasswdInfoFromOpenEncryptHeaders(t *testing.T) {
	t.Run("valid headers", func(t *testing.T) {
		r, _ := http.NewRequest("GET", "/d/test/path", nil)
		r.Header.Set("X-OpenEncrypt-Rule-Matched", "true")
		r.Header.Set("X-OpenEncrypt-Rule-Password", "test-password")
		r.Header.Set("X-OpenEncrypt-Rule-Enc-Type", "aesctr")
		r.Header.Set("X-OpenEncrypt-Rule-Enc-Name", "true")

		info := PasswdInfoFromOpenEncryptHeaders(r)
		if info == nil {
			t.Fatal("should parse valid headers")
		}
		if info.Password != "test-password" {
			t.Errorf("password = %q, want %q", info.Password, "test-password")
		}
		if info.EncType != "aesctr" {
			t.Errorf("encType = %q, want %q", info.EncType, "aesctr")
		}
		if !info.EncName {
			t.Error("encName should be true")
		}
		if !info.Enable {
			t.Error("enable should be true")
		}
	})

	t.Run("missing matched header", func(t *testing.T) {
		r, _ := http.NewRequest("GET", "/d/test/path", nil)
		r.Header.Set("X-OpenEncrypt-Rule-Password", "test")
		if info := PasswdInfoFromOpenEncryptHeaders(r); info != nil {
			t.Fatal("should return nil when Matched header missing")
		}
	})

	t.Run("matched false", func(t *testing.T) {
		r, _ := http.NewRequest("GET", "/d/test/path", nil)
		r.Header.Set("X-OpenEncrypt-Rule-Matched", "false")
		r.Header.Set("X-OpenEncrypt-Rule-Password", "test")
		if info := PasswdInfoFromOpenEncryptHeaders(r); info != nil {
			t.Fatal("should return nil when Matched is false")
		}
	})

	t.Run("missing password", func(t *testing.T) {
		r, _ := http.NewRequest("GET", "/d/test/path", nil)
		r.Header.Set("X-OpenEncrypt-Rule-Matched", "true")
		if info := PasswdInfoFromOpenEncryptHeaders(r); info != nil {
			t.Fatal("should return nil when password missing")
		}
	})

	t.Run("nil request", func(t *testing.T) {
		if info := PasswdInfoFromOpenEncryptHeaders(nil); info != nil {
			t.Fatal("should return nil for nil request")
		}
	})

	t.Run("default encType", func(t *testing.T) {
		r, _ := http.NewRequest("GET", "/d/test/path", nil)
		r.Header.Set("X-OpenEncrypt-Rule-Matched", "true")
		r.Header.Set("X-OpenEncrypt-Rule-Password", "test")
		// encType not set

		info := PasswdInfoFromOpenEncryptHeaders(r)
		if info == nil {
			t.Fatal("should parse with default encType")
		}
		if info.EncType != "aesctr" {
			t.Errorf("default encType = %q, want aesctr", info.EncType)
		}
	})

	t.Run("encrypt operation skips", func(t *testing.T) {
		r, _ := http.NewRequest("PUT", "/d/test/path", nil)
		r.Header.Set("X-OpenEncrypt-Rule-Matched", "true")
		r.Header.Set("X-OpenEncrypt-Rule-Password", "test")
		r.Header.Set("X-OpenEncrypt-Operation", "encrypt")

		info := PasswdInfoFromOpenEncryptHeaders(r)
		if info != nil {
			t.Fatal("should skip when operation is encrypt (not decrypt)")
		}
	})
}
