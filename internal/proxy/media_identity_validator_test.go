package proxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

func TestMediaIdentityV3RequiresSingleStrongETag(t *testing.T) {
	pw := &config.PasswdInfo{Password: "etag-fixture", EncType: "aesctr", Enable: true}
	nonce := bytes.Repeat([]byte{91}, 16)
	header, err := encryption.NewV3Header(100, nonce, 128, 1)
	if err != nil {
		t.Fatal(err)
	}
	key, err := encryption.DeriveV3KeyContext(context.Background(), pw.Password, nonce, 1, encryption.V3KDFSpeculative)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := encryption.NewV3ChunkCipher(key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]byte, 128)
	binary.BigEndian.PutUint32(plain, 20)
	copy(plain[4:], "ftypmp42")
	copy(plain[16:], "isom")
	record, err := cipher.Seal(0, plain)
	if err != nil {
		t.Fatal(err)
	}
	blob := append(header, record...)
	for _, tc := range []struct {
		name     string
		values   []string
		reusable bool
	}{
		{"strong", []string{`"revision"`}, true},
		{"empty-opaque", []string{`""`}, true},
		{"ows", []string{" \t\"revision\"\t "}, true},
		{"absent", nil, false},
		{"weak", []string{`W/"revision"`}, false},
		{"unquoted", []string{"revision"}, false},
		{"whitespace", []string{" \t "}, false},
		{"combined", []string{`"one", "two"`}, false},
		{"multiple", []string{`"one"`, `"two"`}, false},
		{"duplicates", []string{`"one"`, `"one"`}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				for _, value := range tc.values {
					w.Header().Add("ETag", value)
				}
				http.ServeContent(w, r, "encrypted", time.Time{}, bytes.NewReader(blob))
			}))
			defer origin.Close()
			sp := NewStreamProxy(config.DefaultConfig())
			defer sp.StopMediaRecognition()
			sp.client = &Client{Client: origin.Client()}
			out, err := sp.InspectDecryptedMediaPrefix(context.Background(), origin.URL, nil, pw, int64(len(blob)))
			if err != nil || !out.RecordAuthenticated || out.Ext != ".mp4" || out.Reusable != tc.reusable {
				t.Fatalf("result=%+v err=%v wantReusable=%v", out, err, tc.reusable)
			}
			if calls.Load() != 2 || out.BytesRead != 48+int64(len(blob)) || out.RecordBytes != 144 {
				t.Fatalf("operation budget calls=%d result=%+v", calls.Load(), out)
			}
			if !tc.reusable && out.ETag != "" {
				t.Fatalf("invalid freshness evidence retained: %q", out.ETag)
			}
		})
	}
}
