package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
)

func TestHandleFsPutCachesEncryptedMappingOnlyAfterUpstreamSuccess(t *testing.T) {
	upstreamStatus := http.StatusBadRequest
	upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/fs/put" {
			t.Fatalf("unexpected upstream path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(upstreamStatus)
		_, _ = w.Write([]byte(`{"code":` + strconv.Itoa(upstreamStatus) + `}`))
	}))
	defer upstream.Close()

	passwd := &config.PasswdInfo{
		Password: "123456",
		EncType:  "aesctr",
		Enable:   true,
		EncName:  true,
		EncPath:  []string{"/encrypt/*"},
	}
	handler, fileDAO := newTestAlistHandler(t, upstream.URL, passwd)
	t.Cleanup(handler.Stop)

	displayPath := "/encrypt/movie.mp4"
	upload := func() *httptest.ResponseRecorder {
		t.Helper()
		body := "plain upload body"
		req := httptest.NewRequest(http.MethodPut, "/api/fs/put", strings.NewReader(body))
		req.Header.Set("File-Path", url.QueryEscape(displayPath))
		req.Header.Set("Content-Length", strconv.Itoa(len(body)))
		rec := httptest.NewRecorder()
		handler.HandleFsPut(rec, req)
		return rec
	}

	failed := upload()
	if failed.Code != http.StatusBadGateway {
		t.Fatalf("failed upload status=%d, want %d; body=%s", failed.Code, http.StatusBadGateway, failed.Body.String())
	}
	if encryptedPath, ok := fileDAO.GetEncPath(displayPath); ok {
		t.Fatalf("failed upload cached encrypted mapping %q", encryptedPath)
	}

	upstreamStatus = http.StatusOK
	succeeded := upload()
	if succeeded.Code != http.StatusOK {
		t.Fatalf("successful upload status=%d, want %d; body=%s", succeeded.Code, http.StatusOK, succeeded.Body.String())
	}
	if encryptedPath, ok := fileDAO.GetEncPath(displayPath); !ok || encryptedPath == "" {
		t.Fatalf("successful upload mapping=%q, ok=%v", encryptedPath, ok)
	}
}
