package handler

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/encryption"
)

func TestHandleFsLinkUsesEncryptedPathAndWrapsRawURL(t *testing.T) {
	passwd := &config.PasswdInfo{
		Password:  "testpass",
		EncType:   "aesctr",
		Enable:    true,
		EncName:   true,
		EncSuffix: ".bin",
		EncPath:   []string{"/enc/*"},
	}
	converter := encryption.NewFileNameConverter(passwd.Password, passwd.EncType, passwd.EncSuffix)
	displayPath := "/enc/demo.mp4"
	encryptedName := converter.ToRealName("demo.mp4")
	encryptedPath := "/enc/" + encryptedName

	var seenPath string
	upstreamBase := "http://proxy.local"
	transport := rtFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/api/fs/link" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		var req map[string]interface{}
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		seenPath, _ = req["path"].(string)
		return jsonResponse(200, map[string]interface{}{
			"code":    200,
			"message": "success",
			"data": map[string]interface{}{
				"name":     encryptedName,
				"raw_url":  upstreamBase + "/d/" + encryptedName,
				"size":     float64(123),
				"provider": "AliyundriveOpen",
				"is_dir":   false,
			},
		}), nil
	})

	handler, fileDAO := newTestAlistHandler(t, "http://proxy.local:80", passwd)
	handler.httpClient = &http.Client{Transport: transport}
	fileDAO.SetEncPathMapping(displayPath, encryptedPath)

	reqBody, _ := json.Marshal(map[string]interface{}{"path": displayPath})
	req := httptest.NewRequest(http.MethodPost, "http://proxy.local/api/fs/link", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.HandleFsLink(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	if seenPath != encryptedPath {
		t.Fatalf("expected encrypted path %q, got %q", encryptedPath, seenPath)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	data, _ := resp["data"].(map[string]interface{})
	if got, _ := data["name"].(string); got != "demo.mp4" {
		t.Fatalf("expected decrypted name, got %q", got)
	}
	if got, _ := data["provider"].(string); got != "Local" {
		t.Fatalf("expected provider to be rewritten to Local, got %q", got)
	}
	rawURL, _ := data["raw_url"].(string)
	if rawURL == "" || rawURL == upstreamBase+"/d/"+encryptedName {
		t.Fatalf("expected raw_url to be wrapped by redirect, got %q", rawURL)
	}
}

func jsonResponse(status int, payload map[string]interface{}) *http.Response {
	body, _ := json.Marshal(payload)
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
	}
}
