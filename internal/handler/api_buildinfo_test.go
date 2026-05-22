package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
)

func TestGetBuildInfo(t *testing.T) {
	h := NewAPIHandler(config.DefaultConfig(), nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/enc-api/getBuildInfo", nil)
	rr := httptest.NewRecorder()
	h.GetBuildInfo(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want %d", rr.Code, http.StatusOK)
	}

	var resp struct {
		Code int                    `json:"code"`
		Data map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	if resp.Code != 0 {
		t.Fatalf("code=%d, want 0", resp.Code)
	}
	if got := resp.Data["management_mode"]; got == "" || got == nil {
		t.Fatalf("management_mode missing: %#v", resp.Data)
	}
	if got := resp.Data["default_head_img"]; got != "/public/logo.png" {
		t.Fatalf("default_head_img=%v, want %q", got, "/public/logo.png")
	}
}
