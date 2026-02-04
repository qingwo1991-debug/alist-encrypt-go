package errors

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// ErrorCode represents application error codes
type ErrorCode int

const (
	// Client errors (4xx)
	ErrCodeBadRequest   ErrorCode = 400
	ErrCodeUnauthorized ErrorCode = 401
	ErrCodeForbidden    ErrorCode = 403
	ErrCodeNotFound     ErrorCode = 404

	// Server errors (5xx)
	ErrCodeInternal   ErrorCode = 500
	ErrCodeProxy      ErrorCode = 502
	ErrCodeEncryption ErrorCode = 510
	ErrCodeDecryption ErrorCode = 511
)

// AppError represents a structured application error
type AppError struct {
	Code       ErrorCode `json:"code"`
	Message    string    `json:"message"`
	HTTPStatus int       `json:"-"`
	Cause      error     `json:"-"`
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

// Unwrap returns the underlying error
func (e *AppError) Unwrap() error {
	return e.Cause
}

// NewBadRequest creates a bad request error
func NewBadRequest(message string) *AppError {
	return &AppError{
		Code:       ErrCodeBadRequest,
		Message:    message,
		HTTPStatus: http.StatusBadRequest,
	}
}

// NewBadRequestWithCause creates a bad request error with cause
func NewBadRequestWithCause(message string, cause error) *AppError {
	return &AppError{
		Code:       ErrCodeBadRequest,
		Message:    message,
		HTTPStatus: http.StatusBadRequest,
		Cause:      cause,
	}
}

// NewUnauthorized creates an unauthorized error
func NewUnauthorized(message string) *AppError {
	return &AppError{
		Code:       ErrCodeUnauthorized,
		Message:    message,
		HTTPStatus: http.StatusUnauthorized,
	}
}

// NewForbidden creates a forbidden error
func NewForbidden(message string) *AppError {
	return &AppError{
		Code:       ErrCodeForbidden,
		Message:    message,
		HTTPStatus: http.StatusForbidden,
	}
}

// NewNotFound creates a not found error
func NewNotFound(message string) *AppError {
	return &AppError{
		Code:       ErrCodeNotFound,
		Message:    message,
		HTTPStatus: http.StatusNotFound,
	}
}

// NewInternal creates an internal server error
func NewInternal(message string) *AppError {
	return &AppError{
		Code:       ErrCodeInternal,
		Message:    message,
		HTTPStatus: http.StatusInternalServerError,
	}
}

// NewInternalWithCause creates an internal server error with cause
func NewInternalWithCause(message string, cause error) *AppError {
	return &AppError{
		Code:       ErrCodeInternal,
		Message:    message,
		HTTPStatus: http.StatusInternalServerError,
		Cause:      cause,
	}
}

// NewProxyError creates a proxy error
func NewProxyError(message string) *AppError {
	return &AppError{
		Code:       ErrCodeProxy,
		Message:    message,
		HTTPStatus: http.StatusBadGateway,
	}
}

// NewProxyErrorWithCause creates a proxy error with cause
func NewProxyErrorWithCause(message string, cause error) *AppError {
	return &AppError{
		Code:       ErrCodeProxy,
		Message:    message,
		HTTPStatus: http.StatusBadGateway,
		Cause:      cause,
	}
}

// NewEncryptionError creates an encryption error
func NewEncryptionError(message string) *AppError {
	return &AppError{
		Code:       ErrCodeEncryption,
		Message:    message,
		HTTPStatus: http.StatusBadGateway,
	}
}

// NewEncryptionErrorWithCause creates an encryption error with cause
func NewEncryptionErrorWithCause(message string, cause error) *AppError {
	return &AppError{
		Code:       ErrCodeEncryption,
		Message:    message,
		HTTPStatus: http.StatusBadGateway,
		Cause:      cause,
	}
}

// NewDecryptionError creates a decryption error
func NewDecryptionError(message string) *AppError {
	return &AppError{
		Code:       ErrCodeDecryption,
		Message:    message,
		HTTPStatus: http.StatusBadGateway,
	}
}

// NewDecryptionErrorWithCause creates a decryption error with cause
func NewDecryptionErrorWithCause(message string, cause error) *AppError {
	return &AppError{
		Code:       ErrCodeDecryption,
		Message:    message,
		HTTPStatus: http.StatusBadGateway,
		Cause:      cause,
	}
}

// ToHTTPStatus converts an error to HTTP status code
func ToHTTPStatus(err error) int {
	if appErr, ok := err.(*AppError); ok {
		return appErr.HTTPStatus
	}
	return http.StatusInternalServerError
}

// ToJSON converts an error to JSON bytes
func ToJSON(err error) []byte {
	if appErr, ok := err.(*AppError); ok {
		data, _ := json.Marshal(map[string]interface{}{
			"code": appErr.Code,
			"msg":  appErr.Message,
		})
		return data
	}
	data, _ := json.Marshal(map[string]interface{}{
		"code": ErrCodeInternal,
		"msg":  err.Error(),
	})
	return data
}
