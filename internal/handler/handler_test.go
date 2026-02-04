package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alist-encrypt-go/internal/errors"
)

// TestRespondError tests error response helper
func TestRespondError(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   int
	}{
		{
			name:       "bad request",
			err:        errors.NewBadRequest("invalid input"),
			wantStatus: http.StatusBadRequest,
			wantCode:   400,
		},
		{
			name:       "not found",
			err:        errors.NewNotFound("resource not found"),
			wantStatus: http.StatusNotFound,
			wantCode:   404,
		},
		{
			name:       "proxy error",
			err:        errors.NewProxyError("upstream failed"),
			wantStatus: http.StatusBadGateway,
			wantCode:   502,
		},
		{
			name:       "internal error",
			err:        errors.NewInternal("something broke"),
			wantStatus: http.StatusInternalServerError,
			wantCode:   500,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			RespondError(w, tt.err)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}

			var resp APIResponse
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to parse response: %v", err)
			}

			if resp.Code != tt.wantCode {
				t.Errorf("code = %d, want %d", resp.Code, tt.wantCode)
			}
		})
	}
}

// TestRespondSuccess tests success response helper
func TestRespondSuccess(t *testing.T) {
	w := httptest.NewRecorder()
	data := map[string]string{"key": "value"}
	RespondSuccess(w, data)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp APIResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp.Code != 0 {
		t.Errorf("code = %d, want 0", resp.Code)
	}

	if resp.Data == nil {
		t.Error("data should not be nil")
	}
}

// TestRespondAPIError tests API-style error response
func TestRespondAPIError(t *testing.T) {
	w := httptest.NewRecorder()
	RespondAPIError(w, 500, "password error")

	// Should always return HTTP 200 for API errors
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp APIResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp.Code != 500 {
		t.Errorf("code = %d, want 500", resp.Code)
	}

	if resp.Msg != "password error" {
		t.Errorf("msg = %q, want %q", resp.Msg, "password error")
	}
}

// TestRespondJSON tests JSON response
func TestRespondJSON(t *testing.T) {
	w := httptest.NewRecorder()
	data := map[string]interface{}{
		"code": 200,
		"data": map[string]string{"name": "test"},
	}
	RespondJSON(w, http.StatusOK, data)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	contentType := w.Header().Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", contentType)
	}
}

// TestRespondHTTPError tests plain HTTP error
func TestRespondHTTPError(t *testing.T) {
	w := httptest.NewRecorder()
	err := errors.NewBadRequest("bad input")
	RespondHTTPError(w, err)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	body := w.Body.String()
	if !strings.Contains(body, "bad input") {
		t.Errorf("body = %q, should contain 'bad input'", body)
	}
}

// TestRespondSuccessMsg tests success with message
func TestRespondSuccessMsg(t *testing.T) {
	w := httptest.NewRecorder()
	RespondSuccessMsg(w, "operation successful")

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp APIResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp.Code != 0 {
		t.Errorf("code = %d, want 0", resp.Code)
	}

	if resp.Msg != "operation successful" {
		t.Errorf("msg = %q, want %q", resp.Msg, "operation successful")
	}
}
