package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/rs/zerolog/log"

	"github.com/alist-encrypt-go/internal/errors"
)

// maxProxyResponseBody is the default maximum size (10 MB) for buffering upstream responses.
var maxProxyResponseBody int64 = 10 * 1024 * 1024

// SetMaxProxyResponseBody allows runtime configuration of the response body limit.
func SetMaxProxyResponseBody(bytes int64) {
	if bytes > 0 {
		maxProxyResponseBody = bytes
	}
}

// maxAPIRequestBody is the maximum size (1 MB) for JSON API request bodies.
// File upload bodies are streamed, not buffered, so this only applies to metadata APIs.
const maxAPIRequestBody = 1 * 1024 * 1024

// readLimitedRequestBody reads r.Body up to maxAPIRequestBody bytes.
// Returns an error if the body exceeds the limit.
func readLimitedRequestBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	return readLimitedBodyFromReader(r.Body, maxAPIRequestBody)
}

// readLimitedBodyFromReader reads from an io.Reader up to maxBytes.
func readLimitedBodyFromReader(r io.Reader, maxBytes int64) ([]byte, error) {
	limited := io.LimitReader(r, maxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("request body exceeds %d bytes limit", maxBytes)
	}
	return data, nil
}

// readLimitedBody reads resp.Body up to maxBytes. If the body exceeds the limit,
// an error is returned instead of consuming unbounded memory.
func readLimitedBody(resp *http.Response, maxBytes int64) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, nil
	}
	limited := io.LimitReader(resp.Body, maxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("upstream response body exceeds %d bytes limit (read %d bytes)", maxBytes, len(data))
	}
	return data, nil
}

// APIResponse represents a standard API response
type APIResponse struct {
	Code int         `json:"code"`
	Msg  string      `json:"msg,omitempty"`
	Data interface{} `json:"data,omitempty"`
}

// RespondError writes a JSON error response with logging
func RespondError(w http.ResponseWriter, err error) {
	var appErr *errors.AppError
	var ok bool
	if appErr, ok = err.(*errors.AppError); !ok {
		appErr = errors.NewInternalWithCause("Internal server error", err)
	}

	// Log the error with context
	if appErr.Cause != nil {
		log.Error().Err(appErr.Cause).Msg(appErr.Message)
	} else {
		log.Error().Msg(appErr.Message)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(appErr.HTTPStatus)
	json.NewEncoder(w).Encode(APIResponse{
		Code: int(appErr.Code),
		Msg:  appErr.Message,
	})
}

// RespondAPIError writes an API-style error response (code in body, HTTP 200)
// This matches the Alist API convention where errors return HTTP 200 with error code in body
func RespondAPIError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(APIResponse{
		Code: code,
		Msg:  message,
	})
}

// RespondSuccess writes a JSON success response
func RespondSuccess(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(APIResponse{
		Code: 0,
		Data: data,
	})
}

// RespondSuccessMsg writes a JSON success response with a message
func RespondSuccessMsg(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(APIResponse{
		Code: 0,
		Msg:  message,
	})
}

// RespondHTTPError writes a plain HTTP error for non-API endpoints
func RespondHTTPError(w http.ResponseWriter, err error) {
	status := errors.ToHTTPStatus(err)
	http.Error(w, err.Error(), status)
}

// RespondHTTPErrorWithStatus writes a plain HTTP error with explicit status code
func RespondHTTPErrorWithStatus(w http.ResponseWriter, message string, status int) {
	http.Error(w, message, status)
}

// RespondJSON writes a raw JSON response
func RespondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// RespondJSONBytes writes raw JSON bytes to the response
func RespondJSONBytes(w http.ResponseWriter, status int, data []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(data)
}

// RespondRaw writes raw bytes with custom content type
func RespondRaw(w http.ResponseWriter, status int, contentType string, data []byte) {
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(status)
	w.Write(data)
}
