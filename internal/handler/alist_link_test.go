package handler

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
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

func TestHandleFsGetRewritesV2CiphertextSizeToPlaintextSize(t *testing.T) {
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

	plain := bytes.Repeat([]byte("v2-plain-"), 128)
	contentEnc, err := encryption.NewLatestContentEncryptor(passwd.Password, passwd.EncType, int64(len(plain)))
	if err != nil {
		t.Fatalf("new latest encryptor: %v", err)
	}
	cipherReader, err := contentEnc.EncryptReader(bytes.NewReader(plain), 0)
	if err != nil {
		t.Fatalf("encrypt reader: %v", err)
	}
	ciphertext, err := io.ReadAll(cipherReader)
	if err != nil {
		t.Fatalf("read ciphertext: %v", err)
	}

	var seenPath string
	var backendURL string
	backend := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/fs/get":
			body, _ := io.ReadAll(r.Body)
			var req map[string]interface{}
			if err := json.Unmarshal(body, &req); err != nil {
				t.Fatalf("decode request: %v", err)
			}
			seenPath, _ = req["path"].(string)
			resp := map[string]interface{}{
				"code":    200,
				"message": "success",
				"data": map[string]interface{}{
					"name":     encryptedName,
					"raw_url":  backendURL + "/raw/" + encryptedName,
					"size":     float64(len(ciphertext)),
					"provider": "AliyundriveOpen",
					"is_dir":   false,
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		case "/raw/" + encryptedName:
			rangeHeader := r.Header.Get("Range")
			start := 0
			end := len(ciphertext) - 1
			if rangeHeader != "" {
				if rangeHeader != "bytes=0-31" {
					t.Fatalf("unexpected range: %q", rangeHeader)
				}
				end = 31
			}
			body := ciphertext[start : end+1]
			headers := http.Header{"Content-Type": []string{"application/octet-stream"}}
			if rangeHeader != "" {
				headers.Set("Content-Range", "bytes 0-31/"+strconv.Itoa(len(ciphertext)))
			}
			headers.Set("Content-Length", strconv.Itoa(len(body)))
			w.Header().Set("Content-Type", "application/octet-stream")
			for key, values := range headers {
				for _, value := range values {
					w.Header().Add(key, value)
				}
			}
			if rangeHeader != "" {
				w.WriteHeader(http.StatusPartialContent)
			} else {
				w.WriteHeader(http.StatusOK)
			}
			_, _ = w.Write(body)
			return
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
			return
		}
	}))
	defer backend.Close()
	backendURL = backend.URL

	handler, fileDAO := newTestAlistHandler(t, backend.URL, passwd)
	fileDAO.SetEncPathMapping(displayPath, encryptedPath)

	reqBody, _ := json.Marshal(map[string]interface{}{"path": displayPath})
	req := httptest.NewRequest(http.MethodPost, "http://proxy.local/api/fs/get", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.HandleFsGet(rec, req)

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
	if got := int64(data["size"].(float64)); got != int64(len(plain)) {
		t.Fatalf("size=%d want=%d", got, len(plain))
	}
	info, ok := fileDAO.Get(displayPath)
	if !ok || info == nil {
		t.Fatal("expected cached file info")
	}
	if info.Size != int64(len(plain)) {
		t.Fatalf("cached size=%d want=%d", info.Size, len(plain))
	}
	if info.CiphertextSize != int64(len(ciphertext)) {
		t.Fatalf("ciphertext size=%d want=%d", info.CiphertextSize, len(ciphertext))
	}
	if info.ContentVersion != encryption.ContentVersionV2 {
		t.Fatalf("content version=%d", info.ContentVersion)
	}
	if len(info.NonceField) != 16 {
		t.Fatalf("nonce length=%d want=16", len(info.NonceField))
	}
}

func TestHandleFsGetRewritesV2CiphertextSizeViaLocalFallbackProbe(t *testing.T) {
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

	plain := bytes.Repeat([]byte("v2-fallback-"), 128)
	contentEnc, err := encryption.NewLatestContentEncryptor(passwd.Password, passwd.EncType, int64(len(plain)))
	if err != nil {
		t.Fatalf("new latest encryptor: %v", err)
	}
	cipherReader, err := contentEnc.EncryptReader(bytes.NewReader(plain), 0)
	if err != nil {
		t.Fatalf("encrypt reader: %v", err)
	}
	ciphertext, err := io.ReadAll(cipherReader)
	if err != nil {
		t.Fatalf("read ciphertext: %v", err)
	}

	var backendURL string
	backend := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/fs/get":
			resp := map[string]interface{}{
				"code":    200,
				"message": "success",
				"data": map[string]interface{}{
					"name":     encryptedName,
					"raw_url":  backendURL + "/raw/" + encryptedName,
					"size":     float64(len(ciphertext)),
					"provider": "AliyundriveOpen",
					"is_dir":   false,
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		case "/raw/" + encryptedName:
			// Simulate CDN probe not supporting precise header inspection.
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", "1")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte{ciphertext[0]})
			return
		case "/d" + encryptedPath, "/dav" + encryptedPath:
			if got := r.Header.Get("Range"); got != "bytes=0-31" {
				t.Fatalf("unexpected fallback range: %q", got)
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Range", "bytes 0-31/"+strconv.Itoa(len(ciphertext)))
			w.Header().Set("Content-Length", "32")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(ciphertext[:32])
			return
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
			return
		}
	}))
	defer backend.Close()
	backendURL = backend.URL

	handler, fileDAO := newTestAlistHandler(t, backend.URL, passwd)
	fileDAO.SetEncPathMapping(displayPath, encryptedPath)

	reqBody, _ := json.Marshal(map[string]interface{}{"path": displayPath})
	req := httptest.NewRequest(http.MethodPost, "http://proxy.local/api/fs/get", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.HandleFsGet(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	data, _ := resp["data"].(map[string]interface{})
	if got := int64(data["size"].(float64)); got != int64(len(plain)) {
		t.Fatalf("size=%d want=%d", got, len(plain))
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
